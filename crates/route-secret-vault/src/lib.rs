//! Durable encrypted custody for a route scalar already public on chain.
//!
//! Publishing the downstream claim makes the scalar public, but an executor
//! can still crash before claiming upstream. This vault closes that recovery
//! gap without turning the daemon journal into a plaintext secret store. Each
//! route has one immutable, strictly versioned AEAD record whose associated
//! data binds the complete chain exposure and composition identity.
//! Production accepts only the V2 record, which commits exposure source and
//! observation time; legacy V1 records are refused rather than opened under a
//! weaker associated-data contract.
//!
//! The sealing key is injected by the composition root and is never written by
//! this crate. The filesystem boundary is Linux-style retained authority:
//! owner-only nodes, an exclusive process lock, descriptor-relative no-follow
//! opens, hard-link rejection, immutable record publication, and fsync on both
//! the record and its containing directory.
//!
//! Retirement requires an opaque capability minted only after the durable
//! route store replays a production-V2 route and proves both legs terminal
//! with no open funds. The vault durably authenticates and fsyncs a tombstone
//! before unlinking the encrypted recovery record.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use cap_std::fs::{Dir, File};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use counterparty_api::RevealedSecretBytes;
use k256::{
    elliptic_curve::{ff::PrimeField, sec1::ToEncodedPoint},
    ProjectivePoint, Scalar,
};
use rand_core::{OsRng, RngCore};
use route_executor::{ExposureSourceV1, RouteSecretRetirementCapabilityV1};
use rustix::{
    fs::{
        fchmod, flock, fstat, fsync, mkdirat, openat2, renameat_with, unlinkat, AtFlags, FileType,
        FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
    },
    process::geteuid,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    io::{Read, Write},
    os::fd::AsFd,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"DOMRSV02";
const VERSION: u16 = 2;
const HEADER_LEN: usize = 260;
const PLAINTEXT_LEN: usize = 32;
const TAG_LEN: usize = 16;
const RECORD_LEN: usize = HEADER_LEN + PLAINTEXT_LEN + TAG_LEN;
const LOCK_NAME: &str = "route-secret-vault.lock";
const RECORD_PREFIX: &str = "route-";
const RECORD_SUFFIX: &str = ".sealed";
const STAGING_PREFIX: &str = ".route-secret-staging-";
const TOMBSTONE_MAGIC: &[u8; 8] = b"DOMRST01";
const TOMBSTONE_VERSION: u16 = 1;
const TOMBSTONE_HEADER_LEN: usize = 396;
const TOMBSTONE_LEN: usize = TOMBSTONE_HEADER_LEN + TAG_LEN;
const TOMBSTONE_SUFFIX: &str = ".retired";
const TOMBSTONE_STAGING_PREFIX: &str = ".route-secret-retire-staging-";
const KEY_ID_DOMAIN: &[u8] = b"DOM:route-secret-seal-key-id:v1";
const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// A redacted, stable failure classification for the vault boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSecretVaultError {
    /// A path, binding, key, scalar, or point was structurally invalid.
    InvalidInput,
    /// A retained filesystem operation failed.
    Filesystem,
    /// The vault is already owned by another live process.
    StoreBusy,
    /// The operating-system CSPRNG failed.
    RandomFailure,
    /// A node, record, key, ciphertext, or binding failed authentication.
    AuthenticationFailed,
    /// The route already has a different immutable record.
    Conflict,
    /// The record is not the one mandatory V2 wire shape.
    UnsupportedSchema,
    /// No immutable scalar record exists for the requested route.
    NotFound,
    /// A durable authenticated tombstone proves this route record retired.
    Retired,
}

impl fmt::Display for RouteSecretVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "route-secret vault input is invalid",
            Self::Filesystem => "route-secret retained filesystem operation failed",
            Self::StoreBusy => "route-secret vault is busy",
            Self::RandomFailure => "route-secret OS randomness failed",
            Self::AuthenticationFailed => "route-secret record authentication failed",
            Self::Conflict => "route-secret immutable record conflicts",
            Self::UnsupportedSchema => "route-secret record schema is unsupported",
            Self::NotFound => "route-secret record was not found",
            Self::Retired => "route-secret record is durably retired",
        })
    }
}

impl Error for RouteSecretVaultError {}

/// The source of one irreversible route-secret exposure.
///
/// The stable tags are committed by the V2 AEAD associated data. Adding a
/// source requires a new record version rather than reusing one of these tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSecretExposureSourceV2 {
    /// Seen in a chain mempool.
    Mempool,
    /// Handed to an external custody or broadcast authority.
    Externalized,
    /// Seen in an authenticated block.
    Block,
    /// Learned from authenticated counterparty evidence.
    PeerEvidence,
}

impl RouteSecretExposureSourceV2 {
    const fn tag(self) -> u8 {
        match self {
            Self::Mempool => 1,
            Self::Externalized => 2,
            Self::Block => 3,
            Self::PeerEvidence => 4,
        }
    }

    fn decode(tag: u8) -> Result<Self, RouteSecretVaultError> {
        match tag {
            1 => Ok(Self::Mempool),
            2 => Ok(Self::Externalized),
            3 => Ok(Self::Block),
            4 => Ok(Self::PeerEvidence),
            _ => Err(RouteSecretVaultError::UnsupportedSchema),
        }
    }
}

/// Exact public facts identifying one irreversible scalar exposure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RouteSecretExposureV2 {
    chain_id: [u8; 32],
    tx_id: [u8; 32],
    evidence_digest: [u8; 32],
    source: RouteSecretExposureSourceV2,
    observed_at_unix_ms: u64,
}

impl RouteSecretExposureV2 {
    /// Validates and freezes one complete public exposure identity.
    pub fn new(
        chain_id: [u8; 32],
        tx_id: [u8; 32],
        evidence_digest: [u8; 32],
        source: RouteSecretExposureSourceV2,
        observed_at_unix_ms: u64,
    ) -> Result<Self, RouteSecretVaultError> {
        if [chain_id, tx_id, evidence_digest]
            .iter()
            .any(|field| field.iter().all(|byte| *byte == 0))
            || observed_at_unix_ms == 0
        {
            return Err(RouteSecretVaultError::InvalidInput);
        }
        Ok(Self {
            chain_id,
            tx_id,
            evidence_digest,
            source,
            observed_at_unix_ms,
        })
    }
}

impl fmt::Debug for RouteSecretExposureV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteSecretExposureV2")
            .field("chain_id", &"[public opaque]")
            .field("tx_id", &"[public opaque]")
            .field("evidence_digest", &"[public opaque]")
            .field("source", &self.source)
            .field("observed_at_unix_ms", &self.observed_at_unix_ms)
            .finish()
    }
}

/// The full public identity of one downstream scalar exposure.
///
/// All five 32-byte identifiers must be nonzero. `adaptor_point_sec1` must be
/// one canonical compressed secp256k1 point. The scalar is verified against
/// this point on both write and read.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RouteSecretBindingsV2 {
    route_id: [u8; 32],
    composition_digest: [u8; 32],
    chain_id: [u8; 32],
    tx_id: [u8; 32],
    exposure_evidence_digest: [u8; 32],
    adaptor_point_sec1: [u8; 33],
    exposure_source: RouteSecretExposureSourceV2,
    observed_at_unix_ms: u64,
}

impl RouteSecretBindingsV2 {
    /// Validates and freezes one exact route/exposure identity.
    pub fn new(
        route_id: [u8; 32],
        composition_digest: [u8; 32],
        exposure: RouteSecretExposureV2,
        adaptor_point_sec1: [u8; 33],
    ) -> Result<Self, RouteSecretVaultError> {
        for field in [&route_id, &composition_digest] {
            if field.iter().all(|byte| *byte == 0) {
                return Err(RouteSecretVaultError::InvalidInput);
            }
        }
        k256::PublicKey::from_sec1_bytes(&adaptor_point_sec1)
            .map_err(|_| RouteSecretVaultError::InvalidInput)?;
        if !matches!(adaptor_point_sec1[0], 0x02 | 0x03) {
            return Err(RouteSecretVaultError::InvalidInput);
        }
        Ok(Self {
            route_id,
            composition_digest,
            chain_id: exposure.chain_id,
            tx_id: exposure.tx_id,
            exposure_evidence_digest: exposure.evidence_digest,
            adaptor_point_sec1,
            exposure_source: exposure.source,
            observed_at_unix_ms: exposure.observed_at_unix_ms,
        })
    }

    /// The route identifier used as the immutable record key.
    pub const fn route_id(&self) -> &[u8; 32] {
        &self.route_id
    }

    /// Digest of the exact two-leg composed binding.
    pub const fn composition_digest(&self) -> &[u8; 32] {
        &self.composition_digest
    }

    /// Canonical identity of the chain that exposed the scalar.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Exact canonical claim transaction identity.
    pub const fn tx_id(&self) -> &[u8; 32] {
        &self.tx_id
    }

    /// Digest of the final authenticated exposure evidence.
    pub const fn exposure_evidence_digest(&self) -> &[u8; 32] {
        &self.exposure_evidence_digest
    }

    /// The shared adaptor point, in canonical compressed SEC1 form.
    pub const fn adaptor_point_sec1(&self) -> &[u8; 33] {
        &self.adaptor_point_sec1
    }

    /// How this exact first exposure was learned.
    pub const fn exposure_source(&self) -> RouteSecretExposureSourceV2 {
        self.exposure_source
    }

    /// Trusted time committed when the first exposure became durable.
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
}

impl fmt::Debug for RouteSecretBindingsV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteSecretBindingsV2")
            .field("route_id", &"[public opaque]")
            .field("composition_digest", &"[public opaque]")
            .field("chain_id", &"[public opaque]")
            .field("tx_id", &"[public opaque]")
            .field("exposure_evidence_digest", &"[public opaque]")
            .field("adaptor_point_sec1", &"[public point]")
            .field("exposure_source", &self.exposure_source)
            .field("observed_at_unix_ms", &self.observed_at_unix_ms)
            .finish()
    }
}

/// Move-only, zeroizing AEAD key imported from an external key authority.
///
/// This type has no clone, codec, raw-byte accessor, or generic encryption
/// callback. Its public `key_id` is derived from the key and is the only value
/// persisted in a record.
pub struct RouteSecretSealKeyV1 {
    bytes: Zeroizing<[u8; 32]>,
    key_id: [u8; 32],
}

impl RouteSecretSealKeyV1 {
    /// Imports one externally managed 256-bit key.
    pub fn import(bytes: [u8; 32]) -> Result<Self, RouteSecretVaultError> {
        Self::import_zeroizing(Zeroizing::new(bytes))
    }

    /// Imports one externally managed 256-bit key from its zeroizing owner.
    ///
    /// Production decoders should use this form so the key never exists in an
    /// ordinary stack array between decoding and admission by the vault.
    pub fn import_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Result<Self, RouteSecretVaultError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RouteSecretVaultError::InvalidInput);
        }
        let mut hasher = Sha256::new();
        hasher.update(KEY_ID_DOMAIN);
        hasher.update(bytes.as_slice());
        let key_id: [u8; 32] = hasher.finalize().into();
        Ok(Self { bytes, key_id })
    }

    /// Stable public identifier committed by each sealed record.
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }
}

impl fmt::Debug for RouteSecretSealKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteSecretSealKeyV1")
            .field("key_id", &"[public opaque]")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Result of an immutable scalar insertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSecretPutOutcomeV1 {
    /// A new immutable sealed record was durably published.
    Created,
    /// The already-published record authenticated to identical bindings and scalar.
    AlreadyPresent,
}

/// Outcome of terminal, authenticated route-secret retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSecretRetireOutcomeV1 {
    /// The encrypted recovery record was retired in this call.
    Retired,
    /// A matching authenticated tombstone was already durable.
    AlreadyRetired,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RetainedNodeIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    directory: bool,
}

/// Exclusively locked durable authority over immutable route-secret records.
pub struct DurableRouteSecretVaultV1 {
    parent: Arc<Dir>,
    root_name: String,
    root: Dir,
    lock: File,
    root_identity: RetainedNodeIdentity,
    lock_identity: RetainedNodeIdentity,
}

impl fmt::Debug for DurableRouteSecretVaultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableRouteSecretVaultV1")
            .field("root", &"[retained directory]")
            .field("lock", &"[exclusive authority]")
            .finish()
    }
}

impl DurableRouteSecretVaultV1 {
    /// Creates a new owner-only vault beneath a retained parent directory.
    ///
    /// `parent` must be backed by a directory descriptor that supports
    /// `fsync` (for example `std::fs::File::open` converted with
    /// [`Dir::from_std_file`]). An `O_PATH`-style capability is intentionally
    /// refused because it cannot prove durable publication of the root name.
    pub fn create_production(
        parent: Arc<Dir>,
        root_name: &str,
    ) -> Result<Self, RouteSecretVaultError> {
        validate_root_name(root_name)?;
        mkdirat(parent.as_fd(), root_name, Mode::from_raw_mode(0o700))
            .map_err(|_| RouteSecretVaultError::Filesystem)?;
        fsync(parent.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
        let root = open_root(parent.as_ref(), root_name)?;
        fchmod(root.as_fd(), Mode::from_raw_mode(0o700))
            .map_err(|_| RouteSecretVaultError::Filesystem)?;
        let root_identity = validate_directory(&root)?;
        let (lock, lock_identity) = acquire_lock(&root, true)?;
        audit_root(&root, None)?;
        validate_named_authority(
            parent.as_ref(),
            root_name,
            &root,
            &root_identity,
            &lock_identity,
        )?;
        Ok(Self {
            parent,
            root_name: root_name.to_owned(),
            root,
            lock,
            root_identity,
            lock_identity,
        })
    }

    /// Resumes only the narrow provisioning crash window after the caller's
    /// durable provisioning journal has published the vault-root intent.
    ///
    /// The named root must already be an exact owner-only directory beneath
    /// the retained parent and must contain either no entries or only the
    /// exact owner-only lock file. This is deliberately not an open-or-create
    /// operation and never admits an already populated vault.
    pub fn resume_create_production(
        parent: Arc<Dir>,
        root_name: &str,
    ) -> Result<Self, RouteSecretVaultError> {
        validate_root_name(root_name)?;
        let root = open_root(parent.as_ref(), root_name)?;
        let root_identity = validate_directory(&root)?;
        let lock_present = audit_partial_provisioned_root(&root)?;
        let (lock, lock_identity) = acquire_lock(&root, !lock_present)?;
        audit_partial_provisioned_root(&root)?;
        fsync(parent.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
        validate_named_authority(
            parent.as_ref(),
            root_name,
            &root,
            &root_identity,
            &lock_identity,
        )?;
        Ok(Self {
            parent,
            root_name: root_name.to_owned(),
            root,
            lock,
            root_identity,
            lock_identity,
        })
    }

    /// Reopens an existing owner-only vault under an exclusive live lock.
    ///
    /// The same fsync-capable retained-parent requirement as
    /// [`Self::create_production`] applies.
    pub fn open_production(
        parent: Arc<Dir>,
        root_name: &str,
        key: &RouteSecretSealKeyV1,
    ) -> Result<Self, RouteSecretVaultError> {
        validate_root_name(root_name)?;
        let root = open_root(parent.as_ref(), root_name)?;
        let root_identity = validate_directory(&root)?;
        let (lock, lock_identity) = acquire_lock(&root, false)?;
        audit_root(&root, Some(key))?;
        validate_named_authority(
            parent.as_ref(),
            root_name,
            &root,
            &root_identity,
            &lock_identity,
        )?;
        Ok(Self {
            parent,
            root_name: root_name.to_owned(),
            root,
            lock,
            root_identity,
            lock_identity,
        })
    }

    /// Seals and durably publishes the scalar once for the exact route.
    ///
    /// Repetition is idempotent only after the existing AEAD record opens to
    /// the same bindings and scalar. Any changed binding or scalar conflicts.
    pub fn put(
        &self,
        key: &RouteSecretSealKeyV1,
        bindings: &RouteSecretBindingsV2,
        mut scalar: RevealedSecretBytes,
    ) -> Result<RouteSecretPutOutcomeV1, RouteSecretVaultError> {
        self.revalidate_authority(Some(key))?;
        if tombstone_exists(&self.root, bindings.route_id())? {
            return Err(RouteSecretVaultError::Retired);
        }
        let scalar_bytes = Zeroizing::new(scalar.expose_scalar_bytes());
        scalar.zeroize();
        let record_name = record_name(&bindings.route_id);
        match read_record(&self.root, &record_name) {
            Ok(existing) => {
                if !record_public_bindings_match(&existing, bindings)? {
                    return Err(RouteSecretVaultError::Conflict);
                }
                let existing_scalar = open_record(&existing, key, bindings)?;
                if bool::from(existing_scalar.as_ref().ct_eq(scalar_bytes.as_ref())) {
                    Ok(RouteSecretPutOutcomeV1::AlreadyPresent)
                } else {
                    Err(RouteSecretVaultError::Conflict)
                }
            }
            Err(RouteSecretVaultError::NotFound) => {
                require_scalar_point(&scalar_bytes, &bindings.adaptor_point_sec1)?;
                require_unique_route_point(&self.root, bindings)?;
                let record = seal_record(key, bindings, &scalar_bytes)?;
                publish_record(&self.root, &record_name, &record)?;
                self.revalidate_authority(Some(key))?;
                let reopened = read_record(&self.root, &record_name)?;
                let reopened_scalar = open_record(&reopened, key, bindings)?;
                if !bool::from(reopened_scalar.as_ref().ct_eq(scalar_bytes.as_ref())) {
                    return Err(RouteSecretVaultError::AuthenticationFailed);
                }
                Ok(RouteSecretPutOutcomeV1::Created)
            }
            Err(error) => Err(error),
        }
    }

    /// Reopens and authenticates the scalar for all exact route bindings.
    pub fn read(
        &self,
        key: &RouteSecretSealKeyV1,
        bindings: &RouteSecretBindingsV2,
    ) -> Result<RevealedSecretBytes, RouteSecretVaultError> {
        self.revalidate_authority(Some(key))?;
        if tombstone_exists(&self.root, bindings.route_id())? {
            return Err(RouteSecretVaultError::Retired);
        }
        let record = read_record(&self.root, &record_name(&bindings.route_id))?;
        let scalar = open_record(&record, key, bindings)?;
        let output = RevealedSecretBytes::new(*scalar);
        Ok(output)
    }

    /// Retires a public scalar only under an opaque capability minted from
    /// the authenticated terminal route journal.
    ///
    /// A key-authenticated tombstone is durably published and directory-synced
    /// before the encrypted scalar is unlinked. Repetition after any crash is
    /// idempotent only for the exact same capability commitments.
    pub fn retire(
        &self,
        key: &RouteSecretSealKeyV1,
        capability: &RouteSecretRetirementCapabilityV1,
    ) -> Result<RouteSecretRetireOutcomeV1, RouteSecretVaultError> {
        self.revalidate_authority(Some(key))?;
        retire_record(&self.root, key, capability)
    }

    fn revalidate_authority(
        &self,
        authentication_key: Option<&RouteSecretSealKeyV1>,
    ) -> Result<(), RouteSecretVaultError> {
        let named_root = open_root(self.parent.as_ref(), &self.root_name)?;
        self.root_identity
            .require_same(&validate_directory(&named_root)?)?;
        self.root_identity
            .require_same(&validate_directory(&self.root)?)?;
        self.lock_identity
            .require_same(&validate_lock_file(&self.lock)?)?;
        let named_lock = open_file(&self.root, LOCK_NAME, false, true)?;
        self.lock_identity
            .require_same(&validate_lock_file(&named_lock)?)?;
        audit_root(&self.root, authentication_key)?;
        Ok(())
    }
}

impl RetainedNodeIdentity {
    fn require_same(&self, current: &Self) -> Result<(), RouteSecretVaultError> {
        if self != current {
            return Err(RouteSecretVaultError::AuthenticationFailed);
        }
        Ok(())
    }
}

fn validate_root_name(name: &str) -> Result<(), RouteSecretVaultError> {
    if name.is_empty()
        || name.len() > 96
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(RouteSecretVaultError::InvalidInput);
    }
    Ok(())
}

fn open_root(parent: &Dir, root_name: &str) -> Result<Dir, RouteSecretVaultError> {
    let descriptor = openat2(
        parent.as_fd(),
        root_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    )
    .map_err(|_| RouteSecretVaultError::Filesystem)?;
    Ok(Dir::from(descriptor))
}

fn acquire_lock(
    root: &Dir,
    create: bool,
) -> Result<(File, RetainedNodeIdentity), RouteSecretVaultError> {
    let lock = open_file(root, LOCK_NAME, create, true).map_err(|error| {
        if create {
            RouteSecretVaultError::Filesystem
        } else {
            error
        }
    })?;
    if create {
        fchmod(lock.as_fd(), Mode::from_raw_mode(0o600))
            .map_err(|_| RouteSecretVaultError::Filesystem)?;
    }
    let identity = validate_lock_file(&lock)?;
    flock(lock.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| RouteSecretVaultError::StoreBusy)?;
    lock.sync_all()
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
    Ok((lock, identity))
}

fn open_file(
    root: &Dir,
    name: &str,
    create: bool,
    writable: bool,
) -> Result<File, RouteSecretVaultError> {
    let mut flags = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    } | OFlags::NOFOLLOW
        | OFlags::CLOEXEC;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    let descriptor = openat2(
        root.as_fd(),
        name,
        flags,
        if create {
            Mode::from_raw_mode(0o600)
        } else {
            Mode::empty()
        },
        RESOLVE_FLAGS,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            RouteSecretVaultError::NotFound
        } else {
            RouteSecretVaultError::Filesystem
        }
    })?;
    Ok(File::from(descriptor))
}

fn validate_directory(directory: &Dir) -> Result<RetainedNodeIdentity, RouteSecretVaultError> {
    let stat = fstat(directory.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != 0o700
        || stat.st_nlink == 0
    {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    Ok(RetainedNodeIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        owner: stat.st_uid,
        directory: true,
    })
}

fn validate_regular_file(file: &File) -> Result<RetainedNodeIdentity, RouteSecretVaultError> {
    let stat = fstat(file.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != 0o600
        || stat.st_nlink != 1
    {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    Ok(RetainedNodeIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        owner: stat.st_uid,
        directory: false,
    })
}

fn validate_lock_file(file: &File) -> Result<RetainedNodeIdentity, RouteSecretVaultError> {
    let identity = validate_regular_file(file)?;
    if file
        .metadata()
        .map_err(|_| RouteSecretVaultError::Filesystem)?
        .len()
        != 0
    {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    Ok(identity)
}

fn validate_named_authority(
    parent: &Dir,
    root_name: &str,
    retained_root: &Dir,
    root_identity: &RetainedNodeIdentity,
    lock_identity: &RetainedNodeIdentity,
) -> Result<(), RouteSecretVaultError> {
    let named_root = open_root(parent, root_name)?;
    root_identity.require_same(&validate_directory(&named_root)?)?;
    root_identity.require_same(&validate_directory(retained_root)?)?;
    let named_lock = open_file(retained_root, LOCK_NAME, false, true)?;
    lock_identity.require_same(&validate_lock_file(&named_lock)?)
}

fn audit_partial_provisioned_root(root: &Dir) -> Result<bool, RouteSecretVaultError> {
    let mut lock_present = false;
    for entry in root
        .entries()
        .map_err(|_| RouteSecretVaultError::Filesystem)?
    {
        let name = entry
            .map_err(|_| RouteSecretVaultError::Filesystem)?
            .file_name()
            .into_string()
            .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
        if name != LOCK_NAME || lock_present {
            return Err(RouteSecretVaultError::AuthenticationFailed);
        }
        let lock = open_file(root, LOCK_NAME, false, true)?;
        validate_lock_file(&lock)?;
        lock_present = true;
    }
    Ok(lock_present)
}

fn record_name(route_id: &[u8; 32]) -> String {
    format!("{RECORD_PREFIX}{}{RECORD_SUFFIX}", hex::encode(route_id))
}

fn tombstone_name(route_id: &[u8; 32]) -> String {
    format!("{RECORD_PREFIX}{}{TOMBSTONE_SUFFIX}", hex::encode(route_id))
}

fn tombstone_exists(root: &Dir, route_id: &[u8; 32]) -> Result<bool, RouteSecretVaultError> {
    match open_file(root, &tombstone_name(route_id), false, false) {
        Ok(file) => {
            validate_regular_file(&file)?;
            Ok(true)
        }
        Err(RouteSecretVaultError::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

fn audit_root(
    root: &Dir,
    authentication_key: Option<&RouteSecretSealKeyV1>,
) -> Result<(), RouteSecretVaultError> {
    let entries = root
        .entries()
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| RouteSecretVaultError::Filesystem)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
        names.push(name);
    }
    let mut recovered_staging = false;
    let mut seen_route_points: Vec<([u8; 32], [u8; 33])> = Vec::new();
    for name in names {
        if name == LOCK_NAME {
            continue;
        }
        if name.starts_with(STAGING_PREFIX) {
            recover_authenticated_staging(root, &name, authentication_key)?;
            recovered_staging = true;
            continue;
        }
        if name.starts_with(TOMBSTONE_STAGING_PREFIX) {
            recover_authenticated_tombstone_staging(root, &name, authentication_key)?;
            recovered_staging = true;
            continue;
        }
        if name.starts_with(RECORD_PREFIX) && name.ends_with(TOMBSTONE_SUFFIX) {
            if name.len() != RECORD_PREFIX.len() + 64 + TOMBSTONE_SUFFIX.len() {
                return Err(RouteSecretVaultError::AuthenticationFailed);
            }
            let key = authentication_key.ok_or(RouteSecretVaultError::AuthenticationFailed)?;
            let tombstone = read_tombstone(root, &name)?;
            authenticate_tombstone(&tombstone, key)?;
            let encoded_route = &name[RECORD_PREFIX.len()..RECORD_PREFIX.len() + 64];
            let decoded_route = hex::decode(encoded_route)
                .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
            if !bool::from(decoded_route.as_slice().ct_eq(&tombstone[46..78])) {
                return Err(RouteSecretVaultError::AuthenticationFailed);
            }
            let route_id: [u8; 32] = tombstone[46..78]
                .try_into()
                .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
            let adaptor_point: [u8; 33] = tombstone[215..248]
                .try_into()
                .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
            if seen_route_points.iter().any(|(seen_route, seen_point)| {
                seen_route != &route_id && seen_point == &adaptor_point
            }) {
                return Err(RouteSecretVaultError::Conflict);
            }
            seen_route_points.push((route_id, adaptor_point));
            match read_record(root, &record_name(&route_id)) {
                Ok(record) => {
                    let bindings = bindings_from_record(&record)?;
                    let _scalar = open_record(&record, key, &bindings)?;
                    if !tombstone_matches_bindings(&tombstone, &bindings) {
                        return Err(RouteSecretVaultError::AuthenticationFailed);
                    }
                }
                Err(RouteSecretVaultError::NotFound) => {}
                Err(error) => return Err(error),
            }
            continue;
        }
        if !name.starts_with(RECORD_PREFIX)
            || !name.ends_with(RECORD_SUFFIX)
            || name.len() != RECORD_PREFIX.len() + 64 + RECORD_SUFFIX.len()
        {
            return Err(RouteSecretVaultError::AuthenticationFailed);
        }
        let encoded_route = &name[RECORD_PREFIX.len()..RECORD_PREFIX.len() + 64];
        let decoded_route =
            hex::decode(encoded_route).map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
        if decoded_route.len() != 32 {
            return Err(RouteSecretVaultError::AuthenticationFailed);
        }
        let record = read_record(root, &name)?;
        require_supported_header(&record)?;
        if !bool::from(decoded_route.as_slice().ct_eq(&record[46..78])) {
            return Err(RouteSecretVaultError::AuthenticationFailed);
        }
        let route_id: [u8; 32] = record[46..78]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
        let adaptor_point: [u8; 33] = record[206..239]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
        if seen_route_points
            .iter()
            .any(|(seen_route, seen_point)| seen_route != &route_id && seen_point == &adaptor_point)
        {
            return Err(RouteSecretVaultError::Conflict);
        }
        seen_route_points.push((route_id, adaptor_point));
        if let Some(key) = authentication_key {
            let bindings = bindings_from_record(&record)?;
            let _authenticated_scalar = open_record(&record, key, &bindings)?;
        }
    }
    if recovered_staging {
        return audit_root(root, authentication_key);
    }
    Ok(())
}

fn recover_authenticated_tombstone_staging(
    root: &Dir,
    staging_name: &str,
    authentication_key: Option<&RouteSecretSealKeyV1>,
) -> Result<(), RouteSecretVaultError> {
    if staging_name.len() != TOMBSTONE_STAGING_PREFIX.len() + 32
        || !staging_name[TOMBSTONE_STAGING_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    let key = authentication_key.ok_or(RouteSecretVaultError::AuthenticationFailed)?;
    let staging = read_tombstone(root, staging_name)?;
    authenticate_tombstone(&staging, key)?;
    let route_id: [u8; 32] = staging[46..78]
        .try_into()
        .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
    let target_name = tombstone_name(&route_id);
    let sealed = read_record(root, &record_name(&route_id))?;
    let bindings = bindings_from_record(&sealed)?;
    let _scalar = open_record(&sealed, key, &bindings)?;
    if !tombstone_matches_bindings(&staging, &bindings) {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    match renameat_with(
        root.as_fd(),
        staging_name,
        root.as_fd(),
        target_name.as_str(),
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem),
        Err(error) if error == rustix::io::Errno::EXIST => {
            let target = read_tombstone(root, &target_name)?;
            authenticate_tombstone(&target, key)?;
            if !bool::from(staging.as_slice().ct_eq(target.as_slice())) {
                return Err(RouteSecretVaultError::Conflict);
            }
            unlinkat(root.as_fd(), staging_name, AtFlags::empty())
                .map_err(|_| RouteSecretVaultError::Filesystem)?;
            fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)
        }
        Err(_) => Err(RouteSecretVaultError::Filesystem),
    }
}

fn require_unique_route_point(
    root: &Dir,
    candidate: &RouteSecretBindingsV2,
) -> Result<(), RouteSecretVaultError> {
    let entries = root
        .entries()
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    for entry in entries {
        let entry = entry.map_err(|_| RouteSecretVaultError::Filesystem)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
        if name == LOCK_NAME {
            continue;
        }
        if name.starts_with(RECORD_PREFIX) && name.ends_with(TOMBSTONE_SUFFIX) {
            let tombstone = read_tombstone(root, &name)?;
            require_supported_tombstone(&tombstone)?;
            if tombstone[46..78] != candidate.route_id
                && tombstone[215..248] == candidate.adaptor_point_sec1
            {
                return Err(RouteSecretVaultError::Conflict);
            }
            continue;
        }
        if !name.starts_with(RECORD_PREFIX) || !name.ends_with(RECORD_SUFFIX) {
            return Err(RouteSecretVaultError::AuthenticationFailed);
        }
        let record = read_record(root, &name)?;
        require_supported_header(&record)?;
        if record[46..78] != candidate.route_id && record[206..239] == candidate.adaptor_point_sec1
        {
            return Err(RouteSecretVaultError::Conflict);
        }
    }
    Ok(())
}

fn recover_authenticated_staging(
    root: &Dir,
    staging_name: &str,
    authentication_key: Option<&RouteSecretSealKeyV1>,
) -> Result<(), RouteSecretVaultError> {
    if staging_name.len() != STAGING_PREFIX.len() + 32
        || !staging_name[STAGING_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    let key = authentication_key.ok_or(RouteSecretVaultError::AuthenticationFailed)?;
    let staging = read_record(root, staging_name)?;
    let bindings = bindings_from_record(&staging)?;
    let _authenticated_scalar = open_record(&staging, key, &bindings)?;
    let target_name = record_name(bindings.route_id());
    match renameat_with(
        root.as_fd(),
        staging_name,
        root.as_fd(),
        target_name.as_str(),
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
            Ok(())
        }
        Err(error) if error == rustix::io::Errno::EXIST => {
            let target = read_record(root, &target_name)?;
            let target_bindings = bindings_from_record(&target)?;
            let _authenticated_target = open_record(&target, key, &target_bindings)?;
            if !bool::from(staging.as_slice().ct_eq(target.as_slice())) {
                return Err(RouteSecretVaultError::Conflict);
            }
            unlinkat(root.as_fd(), staging_name, AtFlags::empty())
                .map_err(|_| RouteSecretVaultError::Filesystem)?;
            fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
            Ok(())
        }
        Err(_) => Err(RouteSecretVaultError::Filesystem),
    }
}

fn bindings_from_record(
    record: &[u8; RECORD_LEN],
) -> Result<RouteSecretBindingsV2, RouteSecretVaultError> {
    require_supported_header(record)?;
    let exposure = RouteSecretExposureV2::new(
        record[110..142]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        record[142..174]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        record[174..206]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        RouteSecretExposureSourceV2::decode(record[239])?,
        u64::from_be_bytes(
            record[240..248]
                .try_into()
                .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        ),
    )
    .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    RouteSecretBindingsV2::new(
        record[46..78]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        record[78..110]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        exposure,
        record[206..239]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
    )
    .map_err(|_| RouteSecretVaultError::AuthenticationFailed)
}

fn capability_matches_bindings(
    capability: &RouteSecretRetirementCapabilityV1,
    bindings: &RouteSecretBindingsV2,
) -> bool {
    let exposure = capability.first_exposure();
    capability.route_id() == *bindings.route_id()
        && capability.composition_v2_digest() == *bindings.composition_digest()
        && exposure.chain_id == *bindings.chain_id()
        && exposure.transaction_id == *bindings.tx_id()
        && exposure.evidence_digest == *bindings.exposure_evidence_digest()
        && exposure_source_tag(exposure.source) == bindings.exposure_source().tag()
        && exposure.observed_at_unix_ms == bindings.observed_at_unix_ms()
}

fn tombstone_matches_bindings(
    tombstone: &[u8; TOMBSTONE_LEN],
    bindings: &RouteSecretBindingsV2,
) -> bool {
    tombstone[46..78] == bindings.route_id
        && tombstone[78..110] == bindings.composition_digest
        && tombstone[110..142] == bindings.chain_id
        && tombstone[142..174] == bindings.tx_id
        && tombstone[174..206] == bindings.exposure_evidence_digest
        && tombstone[206] == bindings.exposure_source.tag()
        && tombstone[207..215] == bindings.observed_at_unix_ms.to_be_bytes()
        && tombstone[215..248] == bindings.adaptor_point_sec1
}

const fn exposure_source_tag(source: ExposureSourceV1) -> u8 {
    match source {
        ExposureSourceV1::Mempool => 1,
        ExposureSourceV1::Externalized => 2,
        ExposureSourceV1::Block => 3,
        ExposureSourceV1::PeerEvidence => 4,
    }
}

fn retire_record(
    root: &Dir,
    key: &RouteSecretSealKeyV1,
    capability: &RouteSecretRetirementCapabilityV1,
) -> Result<RouteSecretRetireOutcomeV1, RouteSecretVaultError> {
    let route_id = capability.route_id();
    let sealed_name = record_name(&route_id);
    let retired_name = tombstone_name(&route_id);
    match read_tombstone(root, &retired_name) {
        Ok(tombstone) => {
            authenticate_tombstone(&tombstone, key)?;
            if !tombstone_matches_capability(&tombstone, capability) {
                return Err(RouteSecretVaultError::AuthenticationFailed);
            }
            match read_record(root, &sealed_name) {
                Ok(record) => {
                    let bindings = bindings_from_record(&record)?;
                    let _scalar = open_record(&record, key, &bindings)?;
                    if !capability_matches_bindings(capability, &bindings) {
                        return Err(RouteSecretVaultError::AuthenticationFailed);
                    }
                    unlinkat(root.as_fd(), sealed_name.as_str(), AtFlags::empty())
                        .map_err(|_| RouteSecretVaultError::Filesystem)?;
                    fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
                }
                Err(RouteSecretVaultError::NotFound) => {}
                Err(error) => return Err(error),
            }
            Ok(RouteSecretRetireOutcomeV1::AlreadyRetired)
        }
        Err(RouteSecretVaultError::NotFound) => {
            let record = read_record(root, &sealed_name)?;
            let bindings = bindings_from_record(&record)?;
            let _scalar = open_record(&record, key, &bindings)?;
            if !capability_matches_bindings(capability, &bindings) {
                return Err(RouteSecretVaultError::AuthenticationFailed);
            }
            let tombstone = seal_tombstone(key, capability, &bindings)?;
            publish_tombstone(root, &retired_name, &tombstone)?;
            unlinkat(root.as_fd(), sealed_name.as_str(), AtFlags::empty())
                .map_err(|_| RouteSecretVaultError::Filesystem)?;
            fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
            Ok(RouteSecretRetireOutcomeV1::Retired)
        }
        Err(error) => Err(error),
    }
}

fn seal_tombstone(
    key: &RouteSecretSealKeyV1,
    capability: &RouteSecretRetirementCapabilityV1,
    bindings: &RouteSecretBindingsV2,
) -> Result<[u8; TOMBSTONE_LEN], RouteSecretVaultError> {
    if !capability_matches_bindings(capability, bindings) {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    let mut record = [0u8; TOMBSTONE_LEN];
    encode_tombstone_header(
        &mut record[..TOMBSTONE_HEADER_LEN],
        key,
        capability,
        bindings,
    )?;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RouteSecretVaultError::RandomFailure)?;
    record[384..396].copy_from_slice(&nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(key.bytes.as_ref())
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    let nonce_value: Nonce = nonce.into();
    let mut empty = [];
    let tag = cipher
        .encrypt_in_place_detached(&nonce_value, &record[..TOMBSTONE_HEADER_LEN], &mut empty)
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    record[TOMBSTONE_HEADER_LEN..].copy_from_slice(&tag);
    nonce.zeroize();
    Ok(record)
}

fn encode_tombstone_header(
    header: &mut [u8],
    key: &RouteSecretSealKeyV1,
    capability: &RouteSecretRetirementCapabilityV1,
    bindings: &RouteSecretBindingsV2,
) -> Result<(), RouteSecretVaultError> {
    if header.len() != TOMBSTONE_HEADER_LEN {
        return Err(RouteSecretVaultError::InvalidInput);
    }
    let exposure = capability.first_exposure();
    header[..8].copy_from_slice(TOMBSTONE_MAGIC);
    header[8..10].copy_from_slice(&TOMBSTONE_VERSION.to_be_bytes());
    header[10..14].copy_from_slice(&(TOMBSTONE_LEN as u32).to_be_bytes());
    header[14..46].copy_from_slice(key.key_id());
    header[46..78].copy_from_slice(&capability.route_id());
    header[78..110].copy_from_slice(&capability.composition_v2_digest());
    header[110..142].copy_from_slice(&exposure.chain_id);
    header[142..174].copy_from_slice(&exposure.transaction_id);
    header[174..206].copy_from_slice(&exposure.evidence_digest);
    header[206] = exposure_source_tag(exposure.source);
    header[207..215].copy_from_slice(&exposure.observed_at_unix_ms.to_be_bytes());
    header[215..248].copy_from_slice(bindings.adaptor_point_sec1());
    header[248..256].copy_from_slice(&capability.revision().to_be_bytes());
    header[256..288].copy_from_slice(&capability.snapshot_digest());
    header[288..320].copy_from_slice(&capability.last_event_digest());
    header[320..352].copy_from_slice(&capability.journal_head_digest());
    header[352..384].copy_from_slice(&capability.admission_checkpoint_digest());
    Ok(())
}

fn require_supported_tombstone(
    tombstone: &[u8; TOMBSTONE_LEN],
) -> Result<(), RouteSecretVaultError> {
    if &tombstone[..8] != TOMBSTONE_MAGIC
        || u16::from_be_bytes(
            tombstone[8..10]
                .try_into()
                .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        ) != TOMBSTONE_VERSION
        || u32::from_be_bytes(
            tombstone[10..14]
                .try_into()
                .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
        ) != TOMBSTONE_LEN as u32
    {
        return Err(RouteSecretVaultError::UnsupportedSchema);
    }
    if tombstone[46..78].iter().all(|byte| *byte == 0)
        || tombstone[78..110].iter().all(|byte| *byte == 0)
        || tombstone[110..142].iter().all(|byte| *byte == 0)
        || tombstone[142..174].iter().all(|byte| *byte == 0)
        || tombstone[174..206].iter().all(|byte| *byte == 0)
        || !matches!(tombstone[206], 1..=4)
        || u64::from_be_bytes(tombstone[207..215].try_into().unwrap_or([0; 8])) == 0
        || k256::PublicKey::from_sec1_bytes(&tombstone[215..248]).is_err()
        || u64::from_be_bytes(tombstone[248..256].try_into().unwrap_or([0; 8])) == 0
        || tombstone[256..288].iter().all(|byte| *byte == 0)
        || tombstone[288..320].iter().all(|byte| *byte == 0)
        || tombstone[320..352].iter().all(|byte| *byte == 0)
        || tombstone[352..384].iter().all(|byte| *byte == 0)
    {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    Ok(())
}

fn authenticate_tombstone(
    tombstone: &[u8; TOMBSTONE_LEN],
    key: &RouteSecretSealKeyV1,
) -> Result<(), RouteSecretVaultError> {
    require_supported_tombstone(tombstone)?;
    if !bool::from(tombstone[14..46].ct_eq(key.key_id())) {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key.bytes.as_ref())
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    let nonce_bytes: [u8; 12] = tombstone[384..396]
        .try_into()
        .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
    let nonce: Nonce = nonce_bytes.into();
    let tag_bytes: [u8; TAG_LEN] = tombstone[TOMBSTONE_HEADER_LEN..]
        .try_into()
        .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
    let tag: Tag = tag_bytes.into();
    let mut empty = [];
    cipher
        .decrypt_in_place_detached(&nonce, &tombstone[..TOMBSTONE_HEADER_LEN], &mut empty, &tag)
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)
}

fn tombstone_matches_capability(
    tombstone: &[u8; TOMBSTONE_LEN],
    capability: &RouteSecretRetirementCapabilityV1,
) -> bool {
    let exposure = capability.first_exposure();
    tombstone[46..78] == capability.route_id()
        && tombstone[78..110] == capability.composition_v2_digest()
        && tombstone[110..142] == exposure.chain_id
        && tombstone[142..174] == exposure.transaction_id
        && tombstone[174..206] == exposure.evidence_digest
        && tombstone[206] == exposure_source_tag(exposure.source)
        && tombstone[207..215] == exposure.observed_at_unix_ms.to_be_bytes()
        && tombstone[248..256] == capability.revision().to_be_bytes()
        && tombstone[256..288] == capability.snapshot_digest()
        && tombstone[288..320] == capability.last_event_digest()
        && tombstone[320..352] == capability.journal_head_digest()
        && tombstone[352..384] == capability.admission_checkpoint_digest()
}

fn read_tombstone(root: &Dir, name: &str) -> Result<[u8; TOMBSTONE_LEN], RouteSecretVaultError> {
    let mut file = open_file(root, name, false, false)?;
    validate_regular_file(&file)?;
    let metadata = file
        .metadata()
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    if metadata.len() != TOMBSTONE_LEN as u64 {
        return Err(RouteSecretVaultError::UnsupportedSchema);
    }
    let mut bytes = [0u8; TOMBSTONE_LEN];
    file.read_exact(&mut bytes)
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    Ok(bytes)
}

fn publish_tombstone(
    root: &Dir,
    target_name: &str,
    tombstone: &[u8; TOMBSTONE_LEN],
) -> Result<(), RouteSecretVaultError> {
    publish_bytes(root, TOMBSTONE_STAGING_PREFIX, target_name, tombstone)
}

fn read_record(root: &Dir, name: &str) -> Result<[u8; RECORD_LEN], RouteSecretVaultError> {
    let mut file = open_file(root, name, false, false)?;
    validate_regular_file(&file)?;
    let metadata = file
        .metadata()
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    if metadata.len() != RECORD_LEN as u64 {
        return Err(RouteSecretVaultError::UnsupportedSchema);
    }
    let mut bytes = [0u8; RECORD_LEN];
    file.read_exact(&mut bytes)
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    let mut extra = [0u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| RouteSecretVaultError::Filesystem)?
        != 0
    {
        return Err(RouteSecretVaultError::UnsupportedSchema);
    }
    Ok(bytes)
}

fn seal_record(
    key: &RouteSecretSealKeyV1,
    bindings: &RouteSecretBindingsV2,
    scalar: &[u8; 32],
) -> Result<[u8; RECORD_LEN], RouteSecretVaultError> {
    let mut record = [0u8; RECORD_LEN];
    encode_header(&mut record[..HEADER_LEN], key, bindings)?;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RouteSecretVaultError::RandomFailure)?;
    record[248..260].copy_from_slice(&nonce);
    let mut plaintext = Zeroizing::new(*scalar);
    let cipher = ChaCha20Poly1305::new_from_slice(key.bytes.as_ref())
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    let nonce_value: Nonce = nonce.into();
    let tag = cipher
        .encrypt_in_place_detached(&nonce_value, &record[..HEADER_LEN], plaintext.as_mut())
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    record[HEADER_LEN..HEADER_LEN + PLAINTEXT_LEN].copy_from_slice(plaintext.as_ref());
    record[HEADER_LEN + PLAINTEXT_LEN..].copy_from_slice(&tag);
    nonce.zeroize();
    Ok(record)
}

fn encode_header(
    header: &mut [u8],
    key: &RouteSecretSealKeyV1,
    bindings: &RouteSecretBindingsV2,
) -> Result<(), RouteSecretVaultError> {
    if header.len() != HEADER_LEN {
        return Err(RouteSecretVaultError::InvalidInput);
    }
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10..14].copy_from_slice(&(RECORD_LEN as u32).to_be_bytes());
    header[14..46].copy_from_slice(&key.key_id);
    header[46..78].copy_from_slice(&bindings.route_id);
    header[78..110].copy_from_slice(&bindings.composition_digest);
    header[110..142].copy_from_slice(&bindings.chain_id);
    header[142..174].copy_from_slice(&bindings.tx_id);
    header[174..206].copy_from_slice(&bindings.exposure_evidence_digest);
    header[206..239].copy_from_slice(&bindings.adaptor_point_sec1);
    header[239] = bindings.exposure_source.tag();
    header[240..248].copy_from_slice(&bindings.observed_at_unix_ms.to_be_bytes());
    Ok(())
}

fn open_record(
    record: &[u8; RECORD_LEN],
    key: &RouteSecretSealKeyV1,
    bindings: &RouteSecretBindingsV2,
) -> Result<Zeroizing<[u8; 32]>, RouteSecretVaultError> {
    require_supported_header(record)?;
    let mut expected = [0u8; HEADER_LEN];
    encode_header(&mut expected, key, bindings)?;
    expected[248..260].copy_from_slice(&record[248..260]);
    if !bool::from(expected.as_slice().ct_eq(&record[..HEADER_LEN])) {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    let mut plaintext = Zeroizing::new([0u8; 32]);
    plaintext.copy_from_slice(&record[HEADER_LEN..HEADER_LEN + PLAINTEXT_LEN]);
    let cipher = ChaCha20Poly1305::new_from_slice(key.bytes.as_ref())
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    let nonce_bytes: [u8; 12] = record[248..260]
        .try_into()
        .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
    let nonce: Nonce = nonce_bytes.into();
    let tag_bytes: [u8; TAG_LEN] = record[HEADER_LEN + PLAINTEXT_LEN..]
        .try_into()
        .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?;
    let tag: Tag = tag_bytes.into();
    cipher
        .decrypt_in_place_detached(&nonce, &record[..HEADER_LEN], plaintext.as_mut(), &tag)
        .map_err(|_| RouteSecretVaultError::AuthenticationFailed)?;
    require_scalar_point(&plaintext, &bindings.adaptor_point_sec1)?;
    Ok(plaintext)
}

fn require_supported_header(record: &[u8; RECORD_LEN]) -> Result<(), RouteSecretVaultError> {
    if &record[..8] != MAGIC {
        return Err(RouteSecretVaultError::UnsupportedSchema);
    }
    let version = u16::from_be_bytes(
        record[8..10]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
    );
    let length = u32::from_be_bytes(
        record[10..14]
            .try_into()
            .map_err(|_| RouteSecretVaultError::UnsupportedSchema)?,
    );
    if version != VERSION || length != RECORD_LEN as u32 {
        return Err(RouteSecretVaultError::UnsupportedSchema);
    }
    Ok(())
}

fn record_public_bindings_match(
    record: &[u8; RECORD_LEN],
    bindings: &RouteSecretBindingsV2,
) -> Result<bool, RouteSecretVaultError> {
    require_supported_header(record)?;
    let fields_match = record[46..78] == bindings.route_id
        && record[78..110] == bindings.composition_digest
        && record[110..142] == bindings.chain_id
        && record[142..174] == bindings.tx_id
        && record[174..206] == bindings.exposure_evidence_digest
        && record[206..239] == bindings.adaptor_point_sec1
        && record[239] == bindings.exposure_source.tag()
        && record[240..248] == bindings.observed_at_unix_ms.to_be_bytes();
    Ok(fields_match)
}

fn require_scalar_point(
    bytes: &[u8; 32],
    adaptor_point: &[u8; 33],
) -> Result<(), RouteSecretVaultError> {
    let scalar = Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .ok_or(RouteSecretVaultError::AuthenticationFailed)?;
    if bool::from(scalar.is_zero()) {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    let derived = (ProjectivePoint::GENERATOR * scalar)
        .to_affine()
        .to_encoded_point(true);
    if !bool::from(derived.as_bytes().ct_eq(adaptor_point)) {
        return Err(RouteSecretVaultError::AuthenticationFailed);
    }
    Ok(())
}

fn publish_record(
    root: &Dir,
    record_name: &str,
    record: &[u8; RECORD_LEN],
) -> Result<(), RouteSecretVaultError> {
    publish_bytes(root, STAGING_PREFIX, record_name, record)
}

fn publish_bytes(
    root: &Dir,
    staging_prefix: &str,
    target_name: &str,
    bytes: &[u8],
) -> Result<(), RouteSecretVaultError> {
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| RouteSecretVaultError::RandomFailure)?;
    let staging_name = format!("{staging_prefix}{}", hex::encode(random));
    random.zeroize();
    let mut staging = open_file(root, &staging_name, true, true)?;
    fchmod(staging.as_fd(), Mode::from_raw_mode(0o600))
        .map_err(|_| RouteSecretVaultError::Filesystem)?;
    validate_regular_file(&staging)?;
    let result = (|| {
        staging
            .write_all(bytes)
            .map_err(|_| RouteSecretVaultError::Filesystem)?;
        staging
            .flush()
            .map_err(|_| RouteSecretVaultError::Filesystem)?;
        staging
            .sync_all()
            .map_err(|_| RouteSecretVaultError::Filesystem)?;
        validate_regular_file(&staging)?;
        renameat_with(
            root.as_fd(),
            staging_name.as_str(),
            root.as_fd(),
            target_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                RouteSecretVaultError::Conflict
            } else {
                RouteSecretVaultError::Filesystem
            }
        })?;
        fsync(root.as_fd()).map_err(|_| RouteSecretVaultError::Filesystem)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(root.as_fd(), staging_name.as_str(), AtFlags::empty());
        let _ = fsync(root.as_fd());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use route_executor::{
        digest_bytes_v1, ActionIntentV1, ActionKindV1, ActionStateV1, DurableRouteStoreV1,
        EffectDispatchV1, FrozenBindingsV1, FrozenRouteAdmissionCheckpointV2,
        FrozenRouteTimeFactsV2, LegIdV1, PublicExposureV1, RefundBindingsV1, RouteEventV1,
        RouteLeaseV1,
    };
    use static_assertions::assert_not_impl_any;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::Path,
    };
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    assert_not_impl_any!(RouteSecretSealKeyV1: Clone, Copy);
    assert_not_impl_any!(RouteSecretRetirementCapabilityV1: Clone, Copy);

    struct Fixture {
        temporary: TempDir,
        parent: Arc<Dir>,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let temporary = tempfile::tempdir()?;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
            let parent_file = fs::File::open(temporary.path())?;
            let parent = Arc::new(Dir::from_std_file(parent_file));
            Ok(Self { temporary, parent })
        }

        fn root(&self) -> std::path::PathBuf {
            self.temporary.path().join("vault")
        }
    }

    fn scalar_bytes(value: u8) -> [u8; 32] {
        let mut scalar = [0u8; 32];
        scalar[31] = value;
        scalar
    }

    fn bindings(seed: u8, scalar: &[u8; 32]) -> Result<RouteSecretBindingsV2, Box<dyn Error>> {
        let parsed = Option::<Scalar>::from(Scalar::from_repr((*scalar).into()))
            .ok_or("invalid test scalar")?;
        let encoded = (ProjectivePoint::GENERATOR * parsed)
            .to_affine()
            .to_encoded_point(true);
        let point: [u8; 33] = encoded.as_bytes().try_into()?;
        RouteSecretBindingsV2::new(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            RouteSecretExposureV2::new(
                [seed.wrapping_add(2); 32],
                [seed.wrapping_add(3); 32],
                [seed.wrapping_add(4); 32],
                RouteSecretExposureSourceV2::Externalized,
                u64::from(seed) + 1,
            )?,
            point,
        )
        .map_err(Into::into)
    }

    fn record_path(root: &Path, bindings: &RouteSecretBindingsV2) -> std::path::PathBuf {
        root.join(record_name(bindings.route_id()))
    }

    fn apply_route_event(
        store: &mut DurableRouteStoreV1,
        lease: RouteLeaseV1,
        revision: &mut u64,
        event_id: &mut u8,
        event: RouteEventV1,
    ) -> Result<(), Box<dyn Error>> {
        let outcome = store.apply_event(
            lease,
            *revision,
            [*event_id; 32],
            &event,
            u64::from(*event_id) + 2,
        )?;
        *revision = match outcome {
            route_executor::CommitOutcomeV1::Committed { revision, .. } => revision,
            route_executor::CommitOutcomeV1::DuplicateSameBytes { .. } => {
                return Err("unexpected duplicate".into());
            }
        };
        *event_id = event_id.checked_add(1).ok_or("event id overflow")?;
        Ok(())
    }

    fn retirement_capability(
        directory: &Path,
        exact: &RouteSecretBindingsV2,
    ) -> Result<RouteSecretRetirementCapabilityV1, Box<dyn Error>> {
        let database = directory.join(format!("route-{}.sqlite3", hex::encode(exact.tx_id())));
        let mut store = DurableRouteStoreV1::create(&database)?;
        store.create_route(*exact.route_id(), 1)?;
        let lease: RouteLeaseV1 = store
            .acquire_lease(*exact.route_id(), [0x81; 32], 2, 10_000)?
            .lease();
        let mut revision = 0;
        let mut event_id = 1_u8;
        let checkpoint = FrozenRouteAdmissionCheckpointV2 {
            network_id: [0x90; 32],
            route_id: *exact.route_id(),
            bindings: FrozenBindingsV1 {
                terms_digest: [0x91; 32],
                profile_bundle_digest: [0x92; 32],
                deployment_bundle_digest: [0x93; 32],
            },
            composition_v2_digest: *exact.composition_digest(),
            registry_epoch: 1,
            registry_manifest_digest: [0x93; 32],
            upstream_terms_digest: [0x95; 32],
            downstream_terms_digest: [0x96; 32],
            upstream_roster_snapshot: [0x97; 32],
            downstream_roster_snapshot: [0x98; 32],
            participant_bindings_digest: [0x99; 32],
            relay_binding_digest: [0x9A; 32],
            registry_authority_set_digest: [0x9B; 32],
            time_policy_authority_set_digest: [0x9C; 32],
            time_evidence_authority_set_digest: [0x9D; 32],
            time: FrozenRouteTimeFactsV2 {
                route_scope_digest: [0xA1; 32],
                policy_digest: [0xA2; 32],
                evidence_digest: [0xA3; 32],
                proof_digest: [0xA4; 32],
                evidence_sequence: 1,
                issued_at_seconds: 1,
                valid_until_seconds: 100,
                validated_at_seconds: 2,
            },
        };
        apply_route_event(
            &mut store,
            lease,
            &mut revision,
            &mut event_id,
            RouteEventV1::FreezeTermsV2(Box::new(checkpoint)),
        )?;
        apply_route_event(
            &mut store,
            lease,
            &mut revision,
            &mut event_id,
            RouteEventV1::ArmRefunds(RefundBindingsV1 {
                upstream_refund_digest: [0xA5; 32],
                downstream_refund_digest: [0xA6; 32],
            }),
        )?;
        for (leg, value) in [(LegIdV1::Upstream, 0xB0), (LegIdV1::Downstream, 0xB1)] {
            let payload = vec![value; 8];
            apply_route_event(
                &mut store,
                lease,
                &mut revision,
                &mut event_id,
                RouteEventV1::CommitAction(ActionIntentV1 {
                    leg,
                    kind: ActionKindV1::Funding,
                    semantic_digest: [value; 32],
                    contains_route_secret: false,
                    dispatch: EffectDispatchV1::RunnerPayload {
                        payload_digest: digest_bytes_v1(&payload),
                        payload,
                    },
                }),
            )?;
            let effect_id = store
                .load_snapshot(*exact.route_id())?
                .leg(leg)
                .funding
                .effect()
                .ok_or("funding effect")?
                .effect_id;
            let tx = [value.wrapping_add(1); 32];
            apply_route_event(
                &mut store,
                lease,
                &mut revision,
                &mut event_id,
                RouteEventV1::ActionExternalized {
                    leg,
                    kind: ActionKindV1::Funding,
                    effect_id,
                    transaction_id: tx,
                    exposure: None,
                },
            )?;
            apply_route_event(
                &mut store,
                lease,
                &mut revision,
                &mut event_id,
                RouteEventV1::ActionFinalized {
                    leg,
                    kind: ActionKindV1::Funding,
                    transaction_id: tx,
                    evidence_digest: [value.wrapping_add(2); 32],
                },
            )?;
        }
        for (leg, value, transaction_id) in [
            (LegIdV1::Downstream, 0xC0, *exact.tx_id()),
            (LegIdV1::Upstream, 0xC1, [0xC2; 32]),
        ] {
            apply_route_event(
                &mut store,
                lease,
                &mut revision,
                &mut event_id,
                RouteEventV1::CommitAction(ActionIntentV1 {
                    leg,
                    kind: ActionKindV1::Claim,
                    semantic_digest: [value; 32],
                    contains_route_secret: true,
                    dispatch: EffectDispatchV1::ExternalCustody {
                        custody_digest: [value.wrapping_add(1); 32],
                        transaction_id,
                    },
                }),
            )?;
            let effect_id = match store.load_snapshot(*exact.route_id())?.leg(leg).claim {
                ActionStateV1::Committed(ref effect) => effect.effect_id,
                _ => return Err("claim effect".into()),
            };
            let exposure = (leg == LegIdV1::Downstream).then_some(PublicExposureV1 {
                source: match exact.exposure_source() {
                    RouteSecretExposureSourceV2::Mempool => ExposureSourceV1::Mempool,
                    RouteSecretExposureSourceV2::Externalized => ExposureSourceV1::Externalized,
                    RouteSecretExposureSourceV2::Block => ExposureSourceV1::Block,
                    RouteSecretExposureSourceV2::PeerEvidence => ExposureSourceV1::PeerEvidence,
                },
                chain_id: *exact.chain_id(),
                transaction_id: *exact.tx_id(),
                evidence_digest: *exact.exposure_evidence_digest(),
                observed_at_unix_ms: exact.observed_at_unix_ms(),
            });
            apply_route_event(
                &mut store,
                lease,
                &mut revision,
                &mut event_id,
                RouteEventV1::ActionExternalized {
                    leg,
                    kind: ActionKindV1::Claim,
                    effect_id,
                    transaction_id,
                    exposure,
                },
            )?;
            apply_route_event(
                &mut store,
                lease,
                &mut revision,
                &mut event_id,
                RouteEventV1::ActionFinalized {
                    leg,
                    kind: ActionKindV1::Claim,
                    transaction_id,
                    evidence_digest: [value.wrapping_add(2); 32],
                },
            )?;
        }
        Ok(store.mint_route_secret_retirement_capability_v1(*exact.route_id())?)
    }

    #[test]
    fn round_trip_and_restart_recover_only_exact_scalar() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(7);
        let exact = bindings(9, &scalar)?;
        {
            let vault =
                DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
            assert_eq!(
                vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?,
                RouteSecretPutOutcomeV1::Created
            );
        }
        let vault =
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key)?;
        let recovered = vault.read(&key, &exact)?;
        assert_eq!(recovered.expose_scalar_bytes(), scalar);
        Ok(())
    }

    #[test]
    fn authenticated_terminal_capability_retires_exact_record_idempotently() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(19);
        let exact = bindings(21, &scalar)?;
        let capability = retirement_capability(fixture.temporary.path(), &exact)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        assert_eq!(
            vault.retire(&key, &capability)?,
            RouteSecretRetireOutcomeV1::Retired
        );
        assert!(!record_path(&fixture.root(), &exact).exists());
        assert_eq!(
            vault.read(&key, &exact),
            Err(RouteSecretVaultError::Retired)
        );
        assert_eq!(
            vault.retire(&key, &capability)?,
            RouteSecretRetireOutcomeV1::AlreadyRetired
        );
        assert_eq!(
            vault.put(&key, &exact, RevealedSecretBytes::new(scalar)),
            Err(RouteSecretVaultError::Retired)
        );
        let cross_route_same_point = bindings(22, &scalar)?;
        assert_eq!(
            vault.put(
                &key,
                &cross_route_same_point,
                RevealedSecretBytes::new(scalar)
            ),
            Err(RouteSecretVaultError::Conflict)
        );
        drop(vault);
        let reopened =
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key)?;
        assert_eq!(
            reopened.retire(&key, &capability)?,
            RouteSecretRetireOutcomeV1::AlreadyRetired
        );
        drop(reopened);
        let tombstone_path = fixture.root().join(tombstone_name(exact.route_id()));
        let mut tombstone = fs::read(&tombstone_path)?;
        let last = tombstone.last_mut().ok_or("tombstone tag")?;
        *last ^= 1;
        fs::write(&tombstone_path, tombstone)?;
        fs::set_permissions(&tombstone_path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn retirement_rejects_exposure_and_route_transplants() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(20);
        let exact = bindings(22, &scalar)?;
        let changed = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                [0xE2; 32],
                [0xE3; 32],
                RouteSecretExposureSourceV2::Block,
                exact.observed_at_unix_ms() + 1,
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        let changed_capability = retirement_capability(fixture.temporary.path(), &changed)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        assert_eq!(
            vault.retire(&key, &changed_capability),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        assert!(record_path(&fixture.root(), &exact).exists());
        Ok(())
    }

    #[test]
    fn retirement_recovers_crashes_after_tombstone_publish_and_unlink() -> TestResult {
        for (seed, unlink_before_reopen) in [(23_u8, false), (24_u8, true)] {
            let fixture = Fixture::new()?;
            let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
            let scalar = scalar_bytes(seed);
            let exact = bindings(seed, &scalar)?;
            let capability = retirement_capability(fixture.temporary.path(), &exact)?;
            let vault =
                DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
            vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
            let tombstone = seal_tombstone(&key, &capability, &exact)?;
            publish_tombstone(&vault.root, &tombstone_name(exact.route_id()), &tombstone)?;
            if unlink_before_reopen {
                fs::remove_file(record_path(&fixture.root(), &exact))?;
            }
            drop(vault);
            let reopened = DurableRouteSecretVaultV1::open_production(
                Arc::clone(&fixture.parent),
                "vault",
                &key,
            )?;
            assert_eq!(
                reopened.retire(&key, &capability)?,
                RouteSecretRetireOutcomeV1::AlreadyRetired
            );
            assert!(!record_path(&fixture.root(), &exact).exists());
        }
        Ok(())
    }

    #[test]
    fn retirement_recovers_authenticated_tombstone_staging_before_publish() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(25);
        let exact = bindings(25, &scalar)?;
        let capability = retirement_capability(fixture.temporary.path(), &exact)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        let tombstone = seal_tombstone(&key, &capability, &exact)?;
        let staging = fixture
            .root()
            .join(format!("{TOMBSTONE_STAGING_PREFIX}{}", "ab".repeat(16)));
        fs::write(&staging, tombstone)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))?;
        drop(vault);
        let reopened =
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key)?;
        assert_eq!(
            reopened.retire(&key, &capability)?,
            RouteSecretRetireOutcomeV1::AlreadyRetired
        );
        assert!(!staging.exists());
        assert!(!record_path(&fixture.root(), &exact).exists());
        Ok(())
    }

    #[test]
    fn strict_resume_create_accepts_only_exact_pristine_partial_root() -> TestResult {
        for lock_already_published in [false, true] {
            let fixture = Fixture::new()?;
            fs::create_dir(fixture.root())?;
            fs::set_permissions(fixture.root(), fs::Permissions::from_mode(0o700))?;
            fs::File::open(fixture.temporary.path())?.sync_all()?;
            if lock_already_published {
                let lock = fixture.root().join(LOCK_NAME);
                fs::write(&lock, [])?;
                fs::set_permissions(lock, fs::Permissions::from_mode(0o600))?;
                fs::File::open(fixture.root().join(LOCK_NAME))?.sync_all()?;
                fs::File::open(fixture.root())?.sync_all()?;
            }
            let resumed = DurableRouteSecretVaultV1::resume_create_production(
                Arc::clone(&fixture.parent),
                "vault",
            )?;
            assert!(fixture.root().join(LOCK_NAME).exists());
            drop(resumed);
        }
        let fixture = Fixture::new()?;
        fs::create_dir(fixture.root())?;
        fs::set_permissions(fixture.root(), fs::Permissions::from_mode(0o700))?;
        fs::write(fixture.root().join("caller-shaped"), b"x")?;
        assert_eq!(
            DurableRouteSecretVaultV1::resume_create_production(
                Arc::clone(&fixture.parent),
                "vault",
            )
            .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        let fixture = Fixture::new()?;
        fs::create_dir(fixture.root())?;
        fs::set_permissions(fixture.root(), fs::Permissions::from_mode(0o700))?;
        let wrong_lock = fixture.root().join(LOCK_NAME);
        fs::write(&wrong_lock, [])?;
        fs::set_permissions(wrong_lock, fs::Permissions::from_mode(0o640))?;
        assert_eq!(
            DurableRouteSecretVaultV1::resume_create_production(
                Arc::clone(&fixture.parent),
                "vault",
            )
            .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        let fixture = Fixture::new()?;
        fs::create_dir(fixture.root())?;
        fs::set_permissions(fixture.root(), fs::Permissions::from_mode(0o700))?;
        let nonempty_lock = fixture.root().join(LOCK_NAME);
        fs::write(&nonempty_lock, b"caller-shaped")?;
        fs::set_permissions(nonempty_lock, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            DurableRouteSecretVaultV1::resume_create_production(
                Arc::clone(&fixture.parent),
                "vault",
            )
            .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn wrong_key_and_ciphertext_tamper_fail_closed() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let wrong = RouteSecretSealKeyV1::import([0x5A; 32])?;
        let scalar = scalar_bytes(8);
        let exact = bindings(10, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        assert_eq!(
            vault.read(&wrong, &exact),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        drop(vault);
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(
                Arc::clone(&fixture.parent),
                "vault",
                &wrong,
            )
            .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        let path = record_path(&fixture.root(), &exact);
        let mut bytes = fs::read(&path)?;
        bytes[HEADER_LEN + 3] ^= 1;
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn route_and_exposure_transplants_are_rejected() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(9);
        let exact = bindings(11, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        let changed_exposure = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                [0xE1; 32],
                exact.exposure_source(),
                exact.observed_at_unix_ms(),
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        assert_eq!(
            vault.read(&key, &changed_exposure),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        let changed_source = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                *exact.exposure_evidence_digest(),
                RouteSecretExposureSourceV2::Block,
                exact.observed_at_unix_ms(),
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        assert_eq!(
            vault.read(&key, &changed_source),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        let changed_time = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                *exact.exposure_evidence_digest(),
                exact.exposure_source(),
                exact.observed_at_unix_ms() + 1,
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        assert_eq!(
            vault.read(&key, &changed_time),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        drop(vault);
        let other = bindings(12, &scalar)?;
        fs::copy(
            record_path(&fixture.root(), &exact),
            record_path(&fixture.root(), &other),
        )?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn duplicate_is_idempotent_only_for_identical_scalar_and_bindings() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(10);
        let exact = bindings(13, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        assert_eq!(
            vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?,
            RouteSecretPutOutcomeV1::Created
        );
        assert_eq!(
            vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?,
            RouteSecretPutOutcomeV1::AlreadyPresent
        );
        let other_scalar = scalar_bytes(11);
        assert_eq!(
            vault.put(&key, &exact, RevealedSecretBytes::new(other_scalar)),
            Err(RouteSecretVaultError::Conflict)
        );
        let changed = RouteSecretBindingsV2::new(
            *exact.route_id(),
            *exact.composition_digest(),
            RouteSecretExposureV2::new(
                *exact.chain_id(),
                *exact.tx_id(),
                [0xD1; 32],
                exact.exposure_source(),
                exact.observed_at_unix_ms(),
            )?,
            *exact.adaptor_point_sec1(),
        )?;
        assert_eq!(
            vault.put(&key, &changed, RevealedSecretBytes::new(scalar)),
            Err(RouteSecretVaultError::Conflict)
        );
        let cross_route = bindings(14, &scalar)?;
        assert_eq!(
            vault.put(&key, &cross_route, RevealedSecretBytes::new(scalar)),
            Err(RouteSecretVaultError::Conflict)
        );
        Ok(())
    }

    #[test]
    fn permissions_symlinks_and_hardlinks_are_rejected() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(12);
        let exact = bindings(14, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        drop(vault);
        let record = record_path(&fixture.root(), &exact);
        let hardlink = fixture.root().join(record_name(&[0xEE; 32]));
        fs::hard_link(&record, &hardlink)?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        fs::remove_file(hardlink)?;
        fs::remove_file(&record)?;
        symlink("elsewhere", &record)?;
        assert!(matches!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,),
            Err(RouteSecretVaultError::Filesystem)
                | Err(RouteSecretVaultError::AuthenticationFailed)
        ));
        fs::remove_file(&record)?;
        fs::set_permissions(fixture.root(), fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn owner_only_nodes_and_symlinked_root_are_rejected() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(18);
        let exact = bindings(18, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        drop(vault);

        assert_eq!(
            fs::metadata(fixture.root())?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(record_path(&fixture.root(), &exact))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(fixture.root().join(LOCK_NAME))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let real_root = fixture.temporary.path().join("real-vault");
        fs::rename(fixture.root(), &real_root)?;
        symlink("real-vault", fixture.root())?;
        assert!(matches!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,),
            Err(RouteSecretVaultError::Filesystem)
                | Err(RouteSecretVaultError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn exclusive_lock_and_exact_v2_shape_are_fail_closed() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(14);
        let exact = bindings(16, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::StoreBusy)
        );
        drop(vault);

        let record = record_path(&fixture.root(), &exact);
        let original = fs::read(&record)?;
        let mut unsupported = original.clone();
        unsupported[8..10].copy_from_slice(&1u16.to_be_bytes());
        fs::write(&record, &unsupported)?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::UnsupportedSchema)
        );

        let mut legacy_v1 = original[..299].to_vec();
        legacy_v1[..8].copy_from_slice(b"DOMRSV01");
        legacy_v1[8..10].copy_from_slice(&1_u16.to_be_bytes());
        legacy_v1[10..14].copy_from_slice(&299_u32.to_be_bytes());
        fs::write(&record, legacy_v1)?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::UnsupportedSchema)
        );

        fs::write(&record, &original[..RECORD_LEN - 1])?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key,)
                .map(|_| ()),
            Err(RouteSecretVaultError::UnsupportedSchema)
        );
        Ok(())
    }

    #[test]
    fn restart_recovers_only_an_authenticated_fsynced_staging_record() -> TestResult {
        let fixture = Fixture::new()?;
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let scalar = scalar_bytes(15);
        let exact = bindings(17, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        drop(vault);

        let committed = record_path(&fixture.root(), &exact);
        let staging = fixture
            .root()
            .join(format!("{STAGING_PREFIX}{}", "ab".repeat(16)));
        fs::rename(&committed, &staging)?;
        let vault =
            DurableRouteSecretVaultV1::open_production(Arc::clone(&fixture.parent), "vault", &key)?;
        assert!(committed.exists());
        assert!(!staging.exists());
        assert_eq!(vault.read(&key, &exact)?.expose_scalar_bytes(), scalar);
        Ok(())
    }

    #[test]
    fn debug_is_redacted_and_disk_never_contains_plaintext_scalar() -> TestResult {
        let fixture = Fixture::new()?;
        let key_bytes = [0xA5; 32];
        let key = RouteSecretSealKeyV1::import(key_bytes)?;
        let scalar = scalar_bytes(13);
        let exact = bindings(15, &scalar)?;
        let vault =
            DurableRouteSecretVaultV1::create_production(Arc::clone(&fixture.parent), "vault")?;
        vault.put(&key, &exact, RevealedSecretBytes::new(scalar))?;
        let key_debug = format!("{key:?}");
        assert!(key_debug.contains("REDACTED"));
        assert!(!key_debug.contains(&format!("{key_bytes:?}")));
        let vault_debug = format!("{vault:?}");
        assert!(!vault_debug.contains(&hex::encode(scalar)));
        for entry in fs::read_dir(fixture.root())? {
            let bytes = fs::read(entry?.path())?;
            assert!(!bytes.windows(scalar.len()).any(|window| window == scalar));
            assert!(!bytes
                .windows(key_bytes.len())
                .any(|window| window == key_bytes));
        }
        Ok(())
    }
}

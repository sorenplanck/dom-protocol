//! Create-once custody for the external Regtest V2 header authority.
//!
//! Regtest proof of work is intentionally cheap.  Consequently an evidence
//! document is never allowed to nominate its own checkpoint.  The operator
//! first validates and pins one genesis-rooted ancestry in this owner-only
//! store.  Operational verification then reopens that exact store with an
//! independently retained pin and accepts only continuations of its authority.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256d, Hash, HashEngine};
use btc_evidence::{RegtestHeaderAuthorityV2, RegtestHeaderCheckpointV2, RegtestHeaderPolicyV2};
use serde::Deserialize;

use crate::decode_hex_internal;

#[cfg(target_os = "linux")]
use rustix::fs::{
    fstat, fsync, mkdirat, openat2, statat, AtFlags, FileType, Mode, OFlags, ResolveFlags,
};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;

const AUTHORITY_INPUT_SCHEMA_V2: &str = "dom-f5-regtest-authority-v2";
const AUTHORITY_FILE_NAME_V2: &str = "regtest-header-authority-v2.pin";
const AUTHORITY_MAGIC_V2: &[u8; 8] = b"F5RGAU2\0";
const AUTHORITY_VERSION_V2: u16 = 2;
const AUTHORITY_ANCESTRY_DOMAIN_V2: &[u8] = b"DOM/F5/REGTEST-AUTHORITY/ANCESTRY/V2\0";
const AUTHORITY_PIN_DOMAIN_V2: &[u8] = b"DOM/F5/REGTEST-AUTHORITY/PIN/V2\0";
const DIRECTORY_MODE_V2: u32 = 0o700;
const FILE_MODE_V2: u32 = 0o600;
const FIXED_RECORD_BYTES_V2: usize = 8 + 2 + 4 + 4 + 32 + 8 + 32 + 32 + 32 + 32;
const AUTHORITY_PIN_BYTES_V2: usize = 32;
const MAX_AUTHORITY_INPUT_BYTES_V2: u64 = 16 * 1024 * 1024;
const MAX_AUTHORITY_RECORD_BYTES_V2: u64 = (FIXED_RECORD_BYTES_V2 + AUTHORITY_PIN_BYTES_V2) as u64
    + (RegtestHeaderPolicyV2::MAX_GENESIS_ROOTED_HEADERS as u64 * 80);

#[cfg(target_os = "linux")]
const RESOLVE_FLAGS_V2: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Digest an operator retains independently from the owner-only authority
/// directory.  It authenticates the exact canonical ancestry bytes and every
/// derived authority fact stored in the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegtestAuthorityPinV2([u8; 32]);

impl RegtestAuthorityPinV2 {
    /// Parses the unique lowercase hexadecimal representation.
    pub fn from_hex(value: &str) -> Result<Self, String> {
        if value.len() != 64
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err("Regtest authority pin must be 32-byte lowercase hex".to_string());
        }
        let bytes: [u8; 32] = decode_hex_internal(value)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| "Regtest authority pin must be 32-byte lowercase hex".to_string())?;
        Ok(Self(bytes))
    }

    /// Returns the fixed-width digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns canonical lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(self) -> String {
        crate::hex_internal(&self.0)
    }
}

/// Public facts crossed against a create-once authority record on every
/// reopen.  None is accepted directly from an evidence document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegtestAuthorityFactsV2 {
    /// Minimum confirmation depth selected in the pinned policy.
    pub minimum_confirmation_depth: u32,
    /// Height of the exact pinned checkpoint.
    pub checkpoint_height: u64,
    /// Checkpoint hash in Bitcoin internal byte order.
    pub checkpoint_block_hash: [u8; 32],
    /// Cumulative checkpoint work in big-endian form.
    pub checkpoint_chain_work: [u8; 32],
    /// Digest of the code-first Regtest policy.
    pub policy_digest: [u8; 32],
    /// Digest of the validated genesis-rooted checkpoint.
    pub checkpoint_digest: [u8; 32],
    /// Digest of the exact count-prefixed canonical ancestry bytes.
    pub ancestry_digest: [u8; 32],
}

/// Retained owner-only authority opened from the exact bytes authenticated by
/// an independently supplied pin.
pub struct PinnedRegtestHeaderAuthorityV2 {
    authority: RegtestHeaderAuthorityV2,
    facts: RegtestAuthorityFactsV2,
    pin: RegtestAuthorityPinV2,
    _root: File,
    _record: File,
}

impl PinnedRegtestHeaderAuthorityV2 {
    /// Creates a brand-new directory and authority record.  Existing paths,
    /// symlinks and aliases are refused; this operation never replaces data.
    pub fn create_from_ancestry(
        root: &Path,
        minimum_confirmation_depth: u32,
        ancestry: &[[u8; 80]],
    ) -> Result<Self, String> {
        create_from_ancestry_v2(root, minimum_confirmation_depth, ancestry)
    }

    /// Reopens only an existing, owner-only, single-link authority record.
    /// It never creates, rewrites, repairs or migrates either path.
    pub fn open_existing(root: &Path, expected_pin: RegtestAuthorityPinV2) -> Result<Self, String> {
        open_existing_v2(root, expected_pin)
    }

    /// Exact independently authenticated authority.
    pub(crate) const fn authority(&self) -> &RegtestHeaderAuthorityV2 {
        &self.authority
    }

    /// Frozen authority facts rederived and crossed on reopen.
    #[must_use]
    pub const fn facts(&self) -> RegtestAuthorityFactsV2 {
        self.facts
    }

    /// Independently supplied pin that authenticated this retained record.
    #[must_use]
    pub const fn pin(&self) -> RegtestAuthorityPinV2 {
        self.pin
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegtestAuthorityInputV2 {
    schema: String,
    minimum_confirmation_depth: u32,
    checkpoint_headers: Vec<RegtestAuthorityHeaderInputV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegtestAuthorityHeaderInputV2 {
    height: u64,
    hash: String,
    header: String,
}

/// Performs the explicit create-once ceremony from an untrusted JSON export.
/// The returned pin must be retained separately and supplied on every reopen.
pub fn create_regtest_authority_from_file(
    root: &Path,
    source: &Path,
) -> Result<PinnedRegtestHeaderAuthorityV2, String> {
    let metadata =
        std::fs::metadata(source).map_err(|error| format!("Regtest authority input: {error}"))?;
    if metadata.len() == 0 || metadata.len() > MAX_AUTHORITY_INPUT_BYTES_V2 {
        return Err("Regtest authority input exceeds its hard bound".to_string());
    }
    let bytes =
        std::fs::read(source).map_err(|error| format!("Regtest authority input: {error}"))?;
    if bytes.is_empty()
        || u64::try_from(bytes.len())
            .map_err(|_| "Regtest authority input length overflow".to_string())?
            > MAX_AUTHORITY_INPUT_BYTES_V2
    {
        return Err("Regtest authority input exceeds its hard bound".to_string());
    }
    let input: RegtestAuthorityInputV2 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Regtest authority json: {error}"))?;
    if input.schema != AUTHORITY_INPUT_SCHEMA_V2 || input.checkpoint_headers.is_empty() {
        return Err("Regtest authority input is not the exact V2 schema".to_string());
    }
    let ancestry = decode_authority_headers_v2(&input.checkpoint_headers)?;
    PinnedRegtestHeaderAuthorityV2::create_from_ancestry(
        root,
        input.minimum_confirmation_depth,
        &ancestry,
    )
}

fn decode_authority_headers_v2(
    entries: &[RegtestAuthorityHeaderInputV2],
) -> Result<Vec<[u8; 80]>, String> {
    if entries.is_empty() || entries.len() > RegtestHeaderPolicyV2::MAX_GENESIS_ROOTED_HEADERS {
        return Err("Regtest checkpoint ancestry exceeds its hard bound".to_string());
    }
    let mut ancestry = Vec::with_capacity(entries.len());
    for (offset, entry) in entries.iter().enumerate() {
        let expected_height =
            u64::try_from(offset).map_err(|_| "Regtest checkpoint height overflow".to_string())?;
        if entry.height != expected_height {
            return Err("Regtest checkpoint heights are not canonical and contiguous".to_string());
        }
        let raw: [u8; 80] = decode_lower_hex_v2(&entry.header, "checkpoint header")?
            .try_into()
            .map_err(|_| "Regtest checkpoint header is not exactly 80 bytes".to_string())?;
        let header: Header =
            deserialize(&raw).map_err(|error| format!("Regtest checkpoint header: {error}"))?;
        if serialize(&header) != raw || header.block_hash().to_string() != entry.hash {
            return Err("Regtest checkpoint header encoding or hash is not canonical".to_string());
        }
        ancestry.push(raw);
    }
    Ok(ancestry)
}

fn authority_facts_v2(
    policy: &RegtestHeaderPolicyV2,
    checkpoint: &RegtestHeaderCheckpointV2,
    ancestry: &[[u8; 80]],
) -> Result<RegtestAuthorityFactsV2, String> {
    Ok(RegtestAuthorityFactsV2 {
        minimum_confirmation_depth: policy.minimum_confirmation_depth(),
        checkpoint_height: checkpoint.height(),
        checkpoint_block_hash: checkpoint.block_hash(),
        checkpoint_chain_work: checkpoint.chain_work(),
        policy_digest: policy.digest(),
        checkpoint_digest: checkpoint.digest(),
        ancestry_digest: ancestry_digest_v2(ancestry)?,
    })
}

fn encode_authority_record_v2(
    policy: &RegtestHeaderPolicyV2,
    checkpoint: &RegtestHeaderCheckpointV2,
    ancestry: &[[u8; 80]],
) -> Result<(Vec<u8>, RegtestAuthorityFactsV2, RegtestAuthorityPinV2), String> {
    if ancestry.is_empty() || ancestry.len() > RegtestHeaderPolicyV2::MAX_GENESIS_ROOTED_HEADERS {
        return Err("Regtest checkpoint ancestry exceeds its hard bound".to_string());
    }
    let count = u32::try_from(ancestry.len())
        .map_err(|_| "Regtest checkpoint ancestry count overflow".to_string())?;
    let facts = authority_facts_v2(policy, checkpoint, ancestry)?;
    let capacity = FIXED_RECORD_BYTES_V2
        .checked_add(
            ancestry
                .len()
                .checked_mul(80)
                .ok_or_else(|| "Regtest authority record length overflow".to_string())?,
        )
        .and_then(|length| length.checked_add(AUTHORITY_PIN_BYTES_V2))
        .ok_or_else(|| "Regtest authority record length overflow".to_string())?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(AUTHORITY_MAGIC_V2);
    bytes.extend_from_slice(&AUTHORITY_VERSION_V2.to_be_bytes());
    bytes.extend_from_slice(&policy.minimum_confirmation_depth().to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for header in ancestry {
        bytes.extend_from_slice(header);
    }
    bytes.extend_from_slice(&facts.ancestry_digest);
    bytes.extend_from_slice(&facts.checkpoint_height.to_be_bytes());
    bytes.extend_from_slice(&facts.checkpoint_block_hash);
    bytes.extend_from_slice(&facts.checkpoint_chain_work);
    bytes.extend_from_slice(&facts.policy_digest);
    bytes.extend_from_slice(&facts.checkpoint_digest);
    let pin = RegtestAuthorityPinV2(authority_pin_digest_v2(&bytes));
    bytes.extend_from_slice(pin.as_bytes());
    if bytes.len() != capacity {
        return Err("Regtest authority record was not canonically encoded".to_string());
    }
    Ok((bytes, facts, pin))
}

fn decode_authority_record_v2(
    bytes: &[u8],
    expected_pin: RegtestAuthorityPinV2,
) -> Result<
    (
        RegtestHeaderAuthorityV2,
        RegtestAuthorityFactsV2,
        RegtestAuthorityPinV2,
    ),
    String,
> {
    if bytes.is_empty()
        || u64::try_from(bytes.len())
            .map_err(|_| "Regtest authority record length overflow".to_string())?
            > MAX_AUTHORITY_RECORD_BYTES_V2
    {
        return Err("Regtest authority record exceeds its hard bound".to_string());
    }
    let mut cursor = RecordCursorV2::new(bytes);
    if &cursor.take::<8>()? != AUTHORITY_MAGIC_V2
        || u16::from_be_bytes(cursor.take::<2>()?) != AUTHORITY_VERSION_V2
    {
        return Err("Regtest authority record has an unknown format".to_string());
    }
    let minimum_confirmation_depth = u32::from_be_bytes(cursor.take::<4>()?);
    let count = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
        .map_err(|_| "Regtest authority ancestry count overflow".to_string())?;
    if count == 0 || count > RegtestHeaderPolicyV2::MAX_GENESIS_ROOTED_HEADERS {
        return Err("Regtest authority ancestry count is invalid".to_string());
    }
    let exact_length = FIXED_RECORD_BYTES_V2
        .checked_add(
            count
                .checked_mul(80)
                .ok_or_else(|| "Regtest authority record length overflow".to_string())?,
        )
        .and_then(|length| length.checked_add(AUTHORITY_PIN_BYTES_V2))
        .ok_or_else(|| "Regtest authority record length overflow".to_string())?;
    if bytes.len() != exact_length {
        return Err("Regtest authority record length is non-canonical".to_string());
    }
    let mut ancestry = Vec::with_capacity(count);
    for _ in 0..count {
        ancestry.push(cursor.take::<80>()?);
    }
    let recorded_facts = RegtestAuthorityFactsV2 {
        minimum_confirmation_depth,
        ancestry_digest: cursor.take::<32>()?,
        checkpoint_height: u64::from_be_bytes(cursor.take::<8>()?),
        checkpoint_block_hash: cursor.take::<32>()?,
        checkpoint_chain_work: cursor.take::<32>()?,
        policy_digest: cursor.take::<32>()?,
        checkpoint_digest: cursor.take::<32>()?,
    };
    let retained_pin = RegtestAuthorityPinV2(cursor.take::<32>()?);
    if !cursor.is_empty()
        || retained_pin != expected_pin
        || authority_pin_digest_v2(&bytes[..bytes.len() - AUTHORITY_PIN_BYTES_V2])
            != *retained_pin.as_bytes()
    {
        return Err("Regtest authority pin authentication failed".to_string());
    }
    let policy = RegtestHeaderPolicyV2::new(minimum_confirmation_depth)
        .map_err(|error| error.to_string())?;
    let checkpoint = RegtestHeaderCheckpointV2::from_genesis_ancestry(&ancestry)
        .map_err(|error| error.to_string())?;
    let derived_facts = authority_facts_v2(&policy, &checkpoint, &ancestry)?;
    if recorded_facts != derived_facts {
        return Err("Regtest authority facts diverge from canonical ancestry bytes".to_string());
    }
    Ok((
        RegtestHeaderAuthorityV2::new(policy, checkpoint),
        derived_facts,
        retained_pin,
    ))
}

fn ancestry_digest_v2(ancestry: &[[u8; 80]]) -> Result<[u8; 32], String> {
    let count = u32::try_from(ancestry.len())
        .map_err(|_| "Regtest checkpoint ancestry count overflow".to_string())?;
    let mut engine = sha256d::Hash::engine();
    engine.input(AUTHORITY_ANCESTRY_DOMAIN_V2);
    engine.input(&AUTHORITY_VERSION_V2.to_be_bytes());
    engine.input(&count.to_be_bytes());
    for header in ancestry {
        engine.input(header);
    }
    Ok(sha256d::Hash::from_engine(engine).to_byte_array())
}

fn authority_pin_digest_v2(record_without_pin: &[u8]) -> [u8; 32] {
    let mut engine = sha256d::Hash::engine();
    engine.input(AUTHORITY_PIN_DOMAIN_V2);
    engine.input(record_without_pin);
    sha256d::Hash::from_engine(engine).to_byte_array()
}

fn decode_lower_hex_v2(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!("{field} must be canonical lowercase hex"));
    }
    decode_hex_internal(value).ok_or_else(|| format!("{field} must be canonical lowercase hex"))
}

struct RecordCursorV2<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecordCursorV2<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], String> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or_else(|| "Regtest authority record offset overflow".to_string())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "Regtest authority record is truncated".to_string())?
            .try_into()
            .map_err(|_| "Regtest authority record field has the wrong width".to_string())?;
        self.offset = end;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(not(target_os = "linux"))]
fn create_from_ancestry_v2(
    _root: &Path,
    _minimum_confirmation_depth: u32,
    _ancestry: &[[u8; 80]],
) -> Result<PinnedRegtestHeaderAuthorityV2, String> {
    Err("Regtest authority custody requires Linux owner-only storage".to_string())
}

#[cfg(target_os = "linux")]
fn create_from_ancestry_v2(
    root: &Path,
    minimum_confirmation_depth: u32,
    ancestry: &[[u8; 80]],
) -> Result<PinnedRegtestHeaderAuthorityV2, String> {
    let policy = RegtestHeaderPolicyV2::new(minimum_confirmation_depth)
        .map_err(|error| error.to_string())?;
    let checkpoint = RegtestHeaderCheckpointV2::from_genesis_ancestry(ancestry)
        .map_err(|error| error.to_string())?;
    let (record_bytes, _facts, pin) = encode_authority_record_v2(&policy, &checkpoint, ancestry)?;
    let (parent, root_name) = open_creation_parent_v2(root)?;
    if statat(
        parent.as_fd(),
        root_name.as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .is_ok()
    {
        return Err("Regtest authority store already exists".to_string());
    }
    mkdirat(
        parent.as_fd(),
        root_name.as_str(),
        Mode::from_raw_mode(DIRECTORY_MODE_V2),
    )
    .map_err(|_| "failed to create Regtest authority directory".to_string())?;
    fsync(parent.as_fd())
        .map_err(|_| "failed to persist Regtest authority directory".to_string())?;
    let root_file = open_child_directory_v2(&parent, &root_name)?;
    validate_directory_fd_v2(&root_file)?;
    require_named_identity_v2(&parent, &root_name, &root_file, true)?;
    let record = openat2(
        root_file.as_fd(),
        AUTHORITY_FILE_NAME_V2,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(FILE_MODE_V2),
        RESOLVE_FLAGS_V2,
    )
    .map(File::from)
    .map_err(|_| "failed to create Regtest authority record".to_string())?;
    validate_regular_file_fd_v2(&record)?;
    require_named_identity_v2(&root_file, AUTHORITY_FILE_NAME_V2, &record, false)?;
    let mut record = record;
    record
        .write_all(&record_bytes)
        .and_then(|()| record.sync_all())
        .map_err(|_| "failed to persist Regtest authority record".to_string())?;
    fsync(root_file.as_fd())
        .map_err(|_| "failed to persist Regtest authority store".to_string())?;
    drop(record);
    drop(root_file);
    drop(parent);
    PinnedRegtestHeaderAuthorityV2::open_existing(root, pin)
}

#[cfg(not(target_os = "linux"))]
fn open_existing_v2(
    _root: &Path,
    _expected_pin: RegtestAuthorityPinV2,
) -> Result<PinnedRegtestHeaderAuthorityV2, String> {
    Err("Regtest authority custody requires Linux owner-only storage".to_string())
}

#[cfg(target_os = "linux")]
fn open_existing_v2(
    root: &Path,
    expected_pin: RegtestAuthorityPinV2,
) -> Result<PinnedRegtestHeaderAuthorityV2, String> {
    let (parent, root_name) = open_existing_parent_v2(root)?;
    let root_file = open_child_directory_v2(&parent, &root_name)?;
    validate_directory_fd_v2(&root_file)?;
    require_named_identity_v2(&parent, &root_name, &root_file, true)?;
    let record = openat2(
        root_file.as_fd(),
        AUTHORITY_FILE_NAME_V2,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS_V2,
    )
    .map(File::from)
    .map_err(|_| "Regtest authority record is unavailable".to_string())?;
    validate_regular_file_fd_v2(&record)?;
    require_named_identity_v2(&root_file, AUTHORITY_FILE_NAME_V2, &record, false)?;
    let bytes = read_record_bounded_v2(&record)?;
    require_named_identity_v2(&root_file, AUTHORITY_FILE_NAME_V2, &record, false)?;
    require_named_identity_v2(&parent, &root_name, &root_file, true)?;
    let (authority, facts, pin) = decode_authority_record_v2(&bytes, expected_pin)?;
    Ok(PinnedRegtestHeaderAuthorityV2 {
        authority,
        facts,
        pin,
        _root: root_file,
        _record: record,
    })
}

#[cfg(target_os = "linux")]
fn open_creation_parent_v2(root: &Path) -> Result<(File, String), String> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err("Regtest authority path must be an absolute child path".to_string());
    }
    if std::fs::symlink_metadata(root).is_ok() {
        return Err("Regtest authority store already exists".to_string());
    }
    open_parent_v2(root)
}

#[cfg(target_os = "linux")]
fn open_existing_parent_v2(root: &Path) -> Result<(File, String), String> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err("Regtest authority path must be an absolute child path".to_string());
    }
    open_parent_v2(root)
}

#[cfg(target_os = "linux")]
fn open_parent_v2(root: &Path) -> Result<(File, String), String> {
    let root_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| "Regtest authority path has an invalid final component".to_string())?
        .to_string();
    let parent_path = root
        .parent()
        .ok_or_else(|| "Regtest authority path has no parent".to_string())?;
    if std::fs::canonicalize(parent_path)
        .map_err(|_| "Regtest authority parent is unavailable".to_string())?
        != parent_path
    {
        return Err("Regtest authority parent is not canonical".to_string());
    }
    let parent = File::open(parent_path)
        .map_err(|_| "Regtest authority parent is unavailable".to_string())?;
    validate_directory_fd_v2(&parent)?;
    let retained =
        fstat(parent.as_fd()).map_err(|_| "Regtest authority parent is unavailable".to_string())?;
    let named = std::fs::symlink_metadata(parent_path)
        .map_err(|_| "Regtest authority parent is unavailable".to_string())?;
    use std::os::unix::fs::MetadataExt;
    if named.file_type().is_symlink()
        || retained.st_dev != named.dev()
        || retained.st_ino != named.ino()
    {
        return Err("Regtest authority parent identity changed".to_string());
    }
    Ok((parent, root_name))
}

#[cfg(target_os = "linux")]
fn open_child_directory_v2(parent: &File, name: &str) -> Result<File, String> {
    openat2(
        parent.as_fd(),
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS_V2,
    )
    .map(File::from)
    .map_err(|_| "Regtest authority directory is unavailable".to_string())
}

#[cfg(target_os = "linux")]
fn validate_directory_fd_v2(directory: &File) -> Result<(), String> {
    let stat = fstat(directory.as_fd())
        .map_err(|_| "Regtest authority directory is unavailable".to_string())?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != DIRECTORY_MODE_V2
        || stat.st_nlink == 0
    {
        return Err("Regtest authority directory is not exact owner-only storage".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_regular_file_fd_v2(file: &File) -> Result<(), String> {
    let stat =
        fstat(file.as_fd()).map_err(|_| "Regtest authority record is unavailable".to_string())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != FILE_MODE_V2
        || stat.st_nlink != 1
    {
        return Err("Regtest authority record is not an owner-only single-link file".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_named_identity_v2(
    parent: &File,
    name: &str,
    retained: &File,
    directory: bool,
) -> Result<(), String> {
    let opened = fstat(retained.as_fd())
        .map_err(|_| "Regtest authority retained identity is unavailable".to_string())?;
    let named = statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "Regtest authority named identity is unavailable".to_string())?;
    let named_type = FileType::from_raw_mode(named.st_mode);
    if (directory && !named_type.is_dir())
        || (!directory && !named_type.is_file())
        || opened.st_dev != named.st_dev
        || opened.st_ino != named.st_ino
        || opened.st_uid != named.st_uid
        || opened.st_mode != named.st_mode
        || (!directory && named.st_nlink != 1)
        || (directory && named.st_nlink == 0)
    {
        return Err("Regtest authority path identity changed or was linked".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_record_bounded_v2(record: &File) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::MetadataExt;

    let before = record
        .metadata()
        .map_err(|_| "Regtest authority record metadata is unavailable".to_string())?;
    if before.len() == 0 || before.len() > MAX_AUTHORITY_RECORD_BYTES_V2 {
        return Err("Regtest authority record exceeds its hard bound".to_string());
    }
    let mut reader = record;
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len())
            .map_err(|_| "Regtest authority record length overflow".to_string())?,
    );
    std::io::Read::by_ref(&mut reader)
        .take(MAX_AUTHORITY_RECORD_BYTES_V2 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Regtest authority record read failed".to_string())?;
    if u64::try_from(bytes.len())
        .map_err(|_| "Regtest authority record length overflow".to_string())?
        > MAX_AUTHORITY_RECORD_BYTES_V2
    {
        return Err("Regtest authority record exceeds its hard bound".to_string());
    }
    let after = record
        .metadata()
        .map_err(|_| "Regtest authority record metadata is unavailable".to_string())?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || after.nlink() != 1
    {
        return Err("Regtest authority record changed while being read".to_string());
    }
    Ok(bytes)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::serialize;
    use bitcoin::Network;

    use super::{PinnedRegtestHeaderAuthorityV2, RegtestAuthorityPinV2};

    fn genesis_ancestry() -> Vec<[u8; 80]> {
        vec![serialize(&genesis_block(Network::Regtest).header)
            .try_into()
            .expect("Regtest genesis header is fixed width")]
    }

    fn isolated_root(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let parent = std::env::temp_dir().join(format!(
            "dom-f5-regtest-authority-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&parent).expect("create isolated parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("set owner-only parent mode");
        let root = parent.join("authority");
        (parent, root)
    }

    #[test]
    fn create_once_reopen_requires_exact_pin_and_modes() {
        let (parent, root) = isolated_root("reopen");
        let created =
            PinnedRegtestHeaderAuthorityV2::create_from_ancestry(&root, 2, &genesis_ancestry())
                .expect("create authority");
        let pin = created.pin();
        drop(created);
        let reopened = PinnedRegtestHeaderAuthorityV2::open_existing(&root, pin)
            .expect("reopen exact authority");
        assert_eq!(reopened.facts().minimum_confirmation_depth, 2);
        assert_eq!(reopened.facts().checkpoint_height, 0);
        assert_eq!(std::fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::metadata(root.join(super::AUTHORITY_FILE_NAME_V2))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert!(PinnedRegtestHeaderAuthorityV2::open_existing(
            &root,
            RegtestAuthorityPinV2([9; 32])
        )
        .is_err());
        assert!(PinnedRegtestHeaderAuthorityV2::create_from_ancestry(
            &root,
            2,
            &genesis_ancestry()
        )
        .is_err());
        drop(reopened);
        std::fs::remove_dir_all(parent).expect("remove isolated parent");
    }

    #[test]
    fn symlink_hardlink_and_tampered_record_fail_closed() {
        let (parent, root) = isolated_root("links");
        let created =
            PinnedRegtestHeaderAuthorityV2::create_from_ancestry(&root, 1, &genesis_ancestry())
                .expect("create authority");
        let pin = created.pin();
        drop(created);
        let record = root.join(super::AUTHORITY_FILE_NAME_V2);
        let alias = root.join("record-hardlink");
        std::fs::hard_link(&record, &alias).expect("create hardlink");
        assert!(std::fs::metadata(&record).unwrap().nlink() > 1);
        assert!(PinnedRegtestHeaderAuthorityV2::open_existing(&root, pin).is_err());
        std::fs::remove_file(&alias).expect("remove hardlink");

        let link = parent.join("authority-link");
        symlink(&root, &link).expect("create symlink");
        assert!(PinnedRegtestHeaderAuthorityV2::open_existing(&link, pin).is_err());
        std::fs::remove_file(link).expect("remove symlink");

        let mut bytes = std::fs::read(&record).expect("read record");
        bytes[20] ^= 1;
        std::fs::write(&record, bytes).expect("tamper record");
        assert!(PinnedRegtestHeaderAuthorityV2::open_existing(&root, pin).is_err());
        std::fs::remove_dir_all(parent).expect("remove isolated parent");
    }
}

//! Owner-only authenticated stage store for prebroadcast funding.

#[cfg(target_os = "linux")]
use std::fs::{DirBuilder, File};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

#[cfg(target_os = "linux")]
use blake2::digest::consts::U32;
#[cfg(target_os = "linux")]
use blake2::digest::{KeyInit, Mac};
#[cfg(target_os = "linux")]
use blake2::Blake2bMac;
#[cfg(target_os = "linux")]
use cap_std::fs::Dir;
#[cfg(target_os = "linux")]
use subtle::ConstantTimeEq;
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use rustix::fs::{
    fchmod, flock, fstat, fsync, openat2, renameat_with, statat, unlinkat, AtFlags, FileType,
    FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
};
#[cfg(target_os = "linux")]
use rustix::io::Errno;
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::LiveBitcoinError;

#[cfg(target_os = "linux")]
const RECORD_MAGIC: &[u8; 8] = b"DBTCLRV1";
#[cfg(target_os = "linux")]
const RECORD_VERSION: u16 = 1;
#[cfg(target_os = "linux")]
const RECORD_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/RECORD/V1\0";
#[cfg(target_os = "linux")]
const RECORD_OVERHEAD: usize = 8 + 2 + 1 + 4 + 32;
#[cfg(target_os = "linux")]
const KEY_MAGIC: &[u8; 8] = b"DBTCLKV1";
#[cfg(target_os = "linux")]
const KEY_VERSION: u16 = 1;
#[cfg(target_os = "linux")]
const KEY_RECORD_LEN: usize = 8 + 2 + 32;
#[cfg(target_os = "linux")]
const AUTH_KEY_NAME: &str = ".record-auth.key";
#[cfg(target_os = "linux")]
const AUTH_KEY_STAGING: &str = ".record-auth.key.staging";
#[cfg(target_os = "linux")]
const LOCK_NAME: &str = ".prebroadcast.lock";
#[cfg(target_os = "linux")]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(target_os = "linux")]
const FILE_MODE: u32 = 0o600;
#[cfg(target_os = "linux")]
const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageKind {
    Prepared = 1,
    Refund = 2,
    Broadcast = 3,
    FundingSummary = 4,
    FreshAuthority = 5,
    FreshTemplates = 6,
    FreshFaceEvidence = 7,
    FreshClaimIntent = 8,
    FreshClaimPrepared = 9,
    FreshClaimExtractionIntent = 10,
    FreshClaimExtractionComplete = 11,
    FreshClaimFinalizationIntent = 12,
    FreshClaimFinalized = 13,
}

impl StageKind {
    #[cfg(target_os = "linux")]
    const fn file_name(self) -> &'static str {
        match self {
            Self::Prepared => "prepared.v1",
            Self::Refund => "refund.v1",
            Self::Broadcast => "broadcast.v1",
            Self::FundingSummary => "funding-summary.v1",
            Self::FreshAuthority => "fresh-authority.v1",
            Self::FreshTemplates => "fresh-templates.v1",
            Self::FreshFaceEvidence => "fresh-face-evidence.v1",
            Self::FreshClaimIntent => "fresh-claim-intent.v1",
            Self::FreshClaimPrepared => "fresh-claim-prepared.v1",
            Self::FreshClaimExtractionIntent => "fresh-claim-extraction-intent.v1",
            Self::FreshClaimExtractionComplete => "fresh-claim-extraction-complete.v1",
            Self::FreshClaimFinalizationIntent => "fresh-claim-finalization-intent.v1",
            Self::FreshClaimFinalized => "fresh-claim-finalized.v1",
        }
    }

    #[cfg(target_os = "linux")]
    const fn staging_name(self) -> &'static str {
        match self {
            Self::Prepared => ".prepared.v1.staging",
            Self::Refund => ".refund.v1.staging",
            Self::Broadcast => ".broadcast.v1.staging",
            Self::FundingSummary => ".funding-summary.v1.staging",
            Self::FreshAuthority => ".fresh-authority.v1.staging",
            Self::FreshTemplates => ".fresh-templates.v1.staging",
            Self::FreshFaceEvidence => ".fresh-face-evidence.v1.staging",
            Self::FreshClaimIntent => ".fresh-claim-intent.v1.staging",
            Self::FreshClaimPrepared => ".fresh-claim-prepared.v1.staging",
            Self::FreshClaimExtractionIntent => ".fresh-claim-extraction-intent.v1.staging",
            Self::FreshClaimExtractionComplete => ".fresh-claim-extraction-complete.v1.staging",
            Self::FreshClaimFinalizationIntent => ".fresh-claim-finalization-intent.v1.staging",
            Self::FreshClaimFinalized => ".fresh-claim-finalized.v1.staging",
        }
    }
}

pub(crate) struct DurableStageStoreV1 {
    #[cfg(target_os = "linux")]
    root: Dir,
    #[cfg(target_os = "linux")]
    _lock: File,
    #[cfg(target_os = "linux")]
    key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for DurableStageStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableStageStoreV1([redacted])")
    }
}

impl DurableStageStoreV1 {
    #[cfg(target_os = "linux")]
    pub(crate) fn open_or_create(path: &Path) -> Result<Self, LiveBitcoinError> {
        Self::open_with_mode(path, true)
    }

    /// Opens an already provisioned authority without creating its directory,
    /// process lock, or authentication key.  A production consumer uses this
    /// path after the fresh-route producer has completed refund arming; absence
    /// is therefore a refusal, never permission to mint replacement custody.
    #[cfg(target_os = "linux")]
    pub(crate) fn open_existing(path: &Path) -> Result<Self, LiveBitcoinError> {
        Self::open_with_mode(path, false)
    }

    #[cfg(target_os = "linux")]
    fn open_with_mode(path: &Path, create: bool) -> Result<Self, LiveBitcoinError> {
        if !path.is_absolute() {
            return Err(LiveBitcoinError::StoreUnavailable);
        }
        let parent = path.parent().ok_or(LiveBitcoinError::StoreUnavailable)?;
        let parent_metadata =
            std::fs::symlink_metadata(parent).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        if !parent_metadata.file_type().is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != geteuid().as_raw()
            || parent_metadata.mode() & 0o777 != DIRECTORY_MODE
        {
            return Err(LiveBitcoinError::StoreUnavailable);
        }
        if create {
            match DirBuilder::new().mode(DIRECTORY_MODE).create(path) {
                Ok(()) => {
                    File::open(path)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
                    if let Some(parent) = path.parent() {
                        File::open(parent)
                            .and_then(|directory| directory.sync_all())
                            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(LiveBitcoinError::StoreUnavailable),
            }
        }
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        let canonical =
            std::fs::canonicalize(path).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        if canonical != path
            || !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o777 != DIRECTORY_MODE
        {
            return Err(LiveBitcoinError::StoreUnavailable);
        }
        let root = Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        validate_directory(&root)?;
        let (lock_descriptor, created) = if create {
            open_existing_or_create(&root, LOCK_NAME, true)?
        } else {
            (open_existing(&root, LOCK_NAME, OFlags::RDWR)?, false)
        };
        if created {
            fchmod(lock_descriptor.as_fd(), Mode::from_raw_mode(FILE_MODE))
                .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
            sync_directory(&root)?;
        }
        validate_file_fd(lock_descriptor.as_fd())?;
        flock(
            lock_descriptor.as_fd(),
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        let lock = File::from(lock_descriptor);
        require_named_file_identity(&root, LOCK_NAME, &lock)?;
        let key = if create {
            load_or_create_auth_key(&root)?
        } else {
            load_existing_auth_key(&root)?
        };
        Ok(Self {
            root,
            _lock: lock,
            key,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open_or_create(_path: &Path) -> Result<Self, LiveBitcoinError> {
        Err(LiveBitcoinError::StoreUnavailable)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open_existing(_path: &Path) -> Result<Self, LiveBitcoinError> {
        Err(LiveBitcoinError::StoreUnavailable)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn read(&self, kind: StageKind) -> Result<Option<Vec<u8>>, LiveBitcoinError> {
        validate_directory(&self.root)?;
        if let Some(envelope) = read_named(&self.root, kind.file_name())? {
            remove_named_if_present(&self.root, kind.staging_name())?;
            return decode_record(&self.key, kind, &envelope).map(Some);
        }
        let Some(staging) = read_named(&self.root, kind.staging_name())? else {
            return Ok(None);
        };
        let payload = match decode_record(&self.key, kind, &staging) {
            Ok(payload) => payload,
            Err(_) => {
                remove_named_if_present(&self.root, kind.staging_name())?;
                return Ok(None);
            }
        };
        renameat_with(
            self.root.as_fd(),
            kind.staging_name(),
            self.root.as_fd(),
            kind.file_name(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        sync_directory(&self.root)?;
        Ok(Some(payload))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn read(&self, _kind: StageKind) -> Result<Option<Vec<u8>>, LiveBitcoinError> {
        Err(LiveBitcoinError::StoreUnavailable)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish(&self, kind: StageKind, payload: &[u8]) -> Result<(), LiveBitcoinError> {
        validate_directory(&self.root)?;
        if let Some(existing) = self.read(kind)? {
            return if existing == payload {
                Ok(())
            } else {
                Err(LiveBitcoinError::StateConflict)
            };
        }
        let envelope = encode_record(&self.key, kind, payload)?;
        if let Some(staging) = read_named(&self.root, kind.staging_name())? {
            match decode_record(&self.key, kind, &staging) {
                Ok(existing) if existing == payload => {}
                Ok(_) => return Err(LiveBitcoinError::StateConflict),
                Err(_) => {
                    remove_named_if_present(&self.root, kind.staging_name())?;
                    create_named(&self.root, kind.staging_name(), &envelope)?;
                }
            }
        } else {
            create_named(&self.root, kind.staging_name(), &envelope)?;
        }
        renameat_with(
            self.root.as_fd(),
            kind.staging_name(),
            self.root.as_fd(),
            kind.file_name(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn publish(
        &self,
        _kind: StageKind,
        _payload: &[u8],
    ) -> Result<(), LiveBitcoinError> {
        Err(LiveBitcoinError::StoreUnavailable)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn write_staging_for_test(
        &self,
        kind: StageKind,
        payload: &[u8],
    ) -> Result<(), LiveBitcoinError> {
        let envelope = encode_record(&self.key, kind, payload)?;
        create_named(&self.root, kind.staging_name(), &envelope)
    }
}

#[cfg(target_os = "linux")]
fn encode_record(
    key: &[u8; 32],
    kind: StageKind,
    payload: &[u8],
) -> Result<Vec<u8>, LiveBitcoinError> {
    let envelope_len = payload
        .len()
        .checked_add(RECORD_OVERHEAD)
        .filter(|length| *length <= crate::funding::MAX_DURABLE_RECORD_BYTES)
        .ok_or(LiveBitcoinError::BoundsExceeded)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    let mut envelope = Vec::with_capacity(envelope_len);
    envelope.extend_from_slice(RECORD_MAGIC);
    envelope.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    envelope.push(kind as u8);
    envelope.extend_from_slice(&payload_len.to_be_bytes());
    envelope.extend_from_slice(payload);
    let tag = record_tag(key, &envelope)?;
    envelope.extend_from_slice(&tag);
    Ok(envelope)
}

#[cfg(target_os = "linux")]
fn decode_record(
    key: &[u8; 32],
    kind: StageKind,
    envelope: &[u8],
) -> Result<Vec<u8>, LiveBitcoinError> {
    if envelope.len() < RECORD_OVERHEAD
        || &envelope[..8] != RECORD_MAGIC
        || u16::from_be_bytes(
            envelope[8..10]
                .try_into()
                .map_err(|_| LiveBitcoinError::CorruptRecord)?,
        ) != RECORD_VERSION
        || envelope[10] != kind as u8
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let payload_len = usize::try_from(u32::from_be_bytes(
        envelope[11..15]
            .try_into()
            .map_err(|_| LiveBitcoinError::CorruptRecord)?,
    ))
    .map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    let authenticated_len = 15usize
        .checked_add(payload_len)
        .ok_or(LiveBitcoinError::BoundsExceeded)?;
    if authenticated_len
        .checked_add(32)
        .filter(|length| *length == envelope.len())
        .is_none()
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    verify_record_tag(
        key,
        &envelope[..authenticated_len],
        &envelope[authenticated_len..],
    )?;
    Ok(envelope[15..authenticated_len].to_vec())
}

#[cfg(target_os = "linux")]
fn record_tag(key: &[u8; 32], authenticated: &[u8]) -> Result<[u8; 32], LiveBitcoinError> {
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(key)
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    Mac::update(&mut mac, RECORD_DOMAIN);
    Mac::update(&mut mac, authenticated);
    let mut tag = [0_u8; 32];
    tag.copy_from_slice(&mac.finalize().into_bytes());
    Ok(tag)
}

#[cfg(target_os = "linux")]
fn verify_record_tag(
    key: &[u8; 32],
    authenticated: &[u8],
    claimed: &[u8],
) -> Result<(), LiveBitcoinError> {
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(key)
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    Mac::update(&mut mac, RECORD_DOMAIN);
    Mac::update(&mut mac, authenticated);
    mac.verify_slice(claimed)
        .map_err(|_| LiveBitcoinError::CorruptRecord)
}

#[cfg(target_os = "linux")]
fn load_or_create_auth_key(root: &Dir) -> Result<Zeroizing<[u8; 32]>, LiveBitcoinError> {
    if let Some(bytes) = read_named(root, AUTH_KEY_NAME)? {
        remove_named_if_present(root, AUTH_KEY_STAGING)?;
        return decode_key(&bytes);
    }
    if let Some(staging) = read_named(root, AUTH_KEY_STAGING)? {
        if decode_key(&staging).is_ok() {
            renameat_with(
                root.as_fd(),
                AUTH_KEY_STAGING,
                root.as_fd(),
                AUTH_KEY_NAME,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
            sync_directory(root)?;
            return read_named(root, AUTH_KEY_NAME)?
                .ok_or(LiveBitcoinError::StoreUnavailable)
                .and_then(|bytes| decode_key(&bytes));
        }
        remove_named_if_present(root, AUTH_KEY_STAGING)?;
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(key.as_mut()).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(LiveBitcoinError::StoreUnavailable);
    }
    let mut record = Zeroizing::new(Vec::with_capacity(KEY_RECORD_LEN));
    record.extend_from_slice(KEY_MAGIC);
    record.extend_from_slice(&KEY_VERSION.to_be_bytes());
    record.extend_from_slice(key.as_ref());
    create_named(root, AUTH_KEY_STAGING, &record)?;
    renameat_with(
        root.as_fd(),
        AUTH_KEY_STAGING,
        root.as_fd(),
        AUTH_KEY_NAME,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    sync_directory(root)?;
    read_named(root, AUTH_KEY_NAME)?
        .ok_or(LiveBitcoinError::StoreUnavailable)
        .and_then(|bytes| decode_key(&bytes))
}

#[cfg(target_os = "linux")]
fn load_existing_auth_key(root: &Dir) -> Result<Zeroizing<[u8; 32]>, LiveBitcoinError> {
    if let Some(bytes) = read_named(root, AUTH_KEY_NAME)? {
        let key = decode_key(&bytes)?;
        remove_named_if_present(root, AUTH_KEY_STAGING)?;
        return Ok(key);
    }
    let staging = read_named(root, AUTH_KEY_STAGING)?.ok_or(LiveBitcoinError::StoreUnavailable)?;
    let key = decode_key(&staging)?;
    renameat_with(
        root.as_fd(),
        AUTH_KEY_STAGING,
        root.as_fd(),
        AUTH_KEY_NAME,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    sync_directory(root)?;
    let exact = read_named(root, AUTH_KEY_NAME)?.ok_or(LiveBitcoinError::StoreUnavailable)?;
    let reopened = decode_key(&exact)?;
    if !bool::from(reopened[..].ct_eq(&key[..])) {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(reopened)
}

#[cfg(target_os = "linux")]
fn decode_key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, LiveBitcoinError> {
    if bytes.len() != KEY_RECORD_LEN
        || &bytes[..8] != KEY_MAGIC
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| LiveBitcoinError::CorruptRecord)?,
        ) != KEY_VERSION
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&bytes[10..42]);
    if key.iter().all(|byte| *byte == 0) {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(key)
}

#[cfg(target_os = "linux")]
fn validate_directory(root: &Dir) -> Result<(), LiveBitcoinError> {
    let stat = fstat(root.as_fd()).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != DIRECTORY_MODE
        || stat.st_nlink == 0
    {
        return Err(LiveBitcoinError::StoreUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_directory(root: &Dir) -> Result<(), LiveBitcoinError> {
    let descriptor = openat2(
        root.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    )
    .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    let retained = fstat(root.as_fd()).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    let reopened = fstat(descriptor.as_fd()).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    if retained.st_dev != reopened.st_dev
        || retained.st_ino != reopened.st_ino
        || retained.st_mode != reopened.st_mode
        || retained.st_uid != reopened.st_uid
        || reopened.st_nlink == 0
    {
        return Err(LiveBitcoinError::StoreUnavailable);
    }
    fsync(descriptor.as_fd()).map_err(|_| LiveBitcoinError::StoreUnavailable)
}

#[cfg(target_os = "linux")]
fn validate_file_fd(file: impl AsFd) -> Result<(), LiveBitcoinError> {
    let stat = fstat(file).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != FILE_MODE
        || stat.st_nlink != 1
    {
        return Err(LiveBitcoinError::StoreUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_existing_or_create(
    root: &Dir,
    name: &str,
    allow_existing: bool,
) -> Result<(OwnedFd, bool), LiveBitcoinError> {
    if allow_existing {
        match openat2(
            root.as_fd(),
            name,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_FLAGS,
        ) {
            Ok(descriptor) => return Ok((descriptor, false)),
            Err(Errno::NOENT) => {}
            Err(_) => return Err(LiveBitcoinError::StoreUnavailable),
        }
    }
    openat2(
        root.as_fd(),
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(FILE_MODE),
        RESOLVE_FLAGS,
    )
    .map(|descriptor| (descriptor, true))
    .map_err(|_| LiveBitcoinError::StoreUnavailable)
}

#[cfg(target_os = "linux")]
fn open_existing(root: &Dir, name: &str, flags: OFlags) -> Result<OwnedFd, LiveBitcoinError> {
    openat2(
        root.as_fd(),
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    )
    .map_err(|_| LiveBitcoinError::StoreUnavailable)
}

#[cfg(target_os = "linux")]
fn require_named_file_identity(
    root: &Dir,
    name: &str,
    retained: &File,
) -> Result<(), LiveBitcoinError> {
    validate_file_fd(retained.as_fd())?;
    let retained_stat = fstat(retained.as_fd()).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    let named_stat = statat(root.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    if retained_stat.st_dev != named_stat.st_dev
        || retained_stat.st_ino != named_stat.st_ino
        || retained_stat.st_mode != named_stat.st_mode
        || retained_stat.st_uid != named_stat.st_uid
        || named_stat.st_nlink != 1
    {
        return Err(LiveBitcoinError::StoreUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_named(root: &Dir, name: &str) -> Result<Option<Vec<u8>>, LiveBitcoinError> {
    let descriptor = match openat2(
        root.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(LiveBitcoinError::StoreUnavailable),
    };
    validate_file_fd(descriptor.as_fd())?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(crate::funding::MAX_DURABLE_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    require_named_file_identity(root, name, &file)?;
    if bytes.len() > crate::funding::MAX_DURABLE_RECORD_BYTES {
        return Err(LiveBitcoinError::BoundsExceeded);
    }
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn create_named(root: &Dir, name: &str, bytes: &[u8]) -> Result<(), LiveBitcoinError> {
    let (descriptor, created) = open_existing_or_create(root, name, false)?;
    if !created {
        return Err(LiveBitcoinError::StateConflict);
    }
    fchmod(descriptor.as_fd(), Mode::from_raw_mode(FILE_MODE))
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    validate_file_fd(descriptor.as_fd())?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    fsync(file.as_fd()).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    require_named_file_identity(root, name, &file)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_named_if_present(root: &Dir, name: &str) -> Result<(), LiveBitcoinError> {
    let descriptor = match openat2(
        root.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(()),
        Err(_) => return Err(LiveBitcoinError::StoreUnavailable),
    };
    let file = File::from(descriptor);
    require_named_file_identity(root, name, &file)?;
    unlinkat(root.as_fd(), name, AtFlags::empty())
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    sync_directory(root)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn root(label: &str) -> Result<std::path::PathBuf, LiveBitcoinError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let parent = std::env::temp_dir().join(format!(
            "btc-live-store-{label}-{}-{nonce}",
            std::process::id()
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        io(builder.create(&parent))?;
        Ok(parent.join("route"))
    }

    fn cleanup(path: &Path) {
        let Some(parent) = path.parent() else {
            return;
        };
        if parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("btc-live-store-"))
        {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn io<T>(result: std::io::Result<T>) -> Result<T, LiveBitcoinError> {
        result.map_err(|_| LiveBitcoinError::StoreUnavailable)
    }

    #[test]
    fn authenticated_record_reopens_and_staging_promotes_exactly() -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = root("restart")?;
        {
            let store = DurableStageStoreV1::open_or_create(&path)?;
            store.write_staging_for_test(StageKind::Prepared, b"canonical-prepared")?;
        }
        let reopened = DurableStageStoreV1::open_or_create(&path)?;
        assert_eq!(
            reopened.read(StageKind::Prepared)?,
            Some(b"canonical-prepared".to_vec())
        );
        assert!(!path.join(StageKind::Prepared.staging_name()).exists());
        cleanup(&path);
        Ok(())
    }

    #[test]
    fn fresh_store_initializes_completely_in_one_open() -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = root("fresh-one-open")?;

        let store = DurableStageStoreV1::open_or_create(&path)?;
        assert!(path.join(LOCK_NAME).is_file());
        assert!(path.join(AUTH_KEY_NAME).is_file());
        assert!(!path.join(AUTH_KEY_STAGING).exists());
        store.publish(StageKind::Prepared, b"first-open-is-usable")?;
        assert_eq!(
            store.read(StageKind::Prepared)?,
            Some(b"first-open-is-usable".to_vec())
        );

        drop(store);
        let reopened = DurableStageStoreV1::open_or_create(&path)?;
        assert_eq!(
            reopened.read(StageKind::Prepared)?,
            Some(b"first-open-is-usable".to_vec())
        );
        drop(reopened);
        cleanup(&path);
        Ok(())
    }

    #[test]
    fn production_open_existing_never_mints_missing_authority() -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = root("existing-refuses-missing")?;
        assert_eq!(
            DurableStageStoreV1::open_existing(&path).map(|_| ()),
            Err(LiveBitcoinError::StoreUnavailable)
        );
        assert!(!path.exists());

        io(std::fs::create_dir(&path))?;
        io(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(DIRECTORY_MODE),
        ))?;
        assert_eq!(
            DurableStageStoreV1::open_existing(&path).map(|_| ()),
            Err(LiveBitcoinError::StoreUnavailable)
        );
        assert_eq!(
            io(std::fs::read_dir(&path))?.count(),
            0,
            "open_existing must not create a lock or authentication key"
        );

        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path.join(LOCK_NAME));
        drop(io(lock)?);
        assert_eq!(
            DurableStageStoreV1::open_existing(&path).map(|_| ()),
            Err(LiveBitcoinError::StoreUnavailable)
        );
        assert!(path.join(LOCK_NAME).is_file());
        assert!(!path.join(AUTH_KEY_NAME).exists());
        assert!(!path.join(AUTH_KEY_STAGING).exists());
        cleanup(&path);
        Ok(())
    }

    #[test]
    fn production_open_existing_reuses_and_recovers_only_existing_custody(
    ) -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = root("existing-complete")?;
        {
            let store = DurableStageStoreV1::open_or_create(&path)?;
            store.publish(StageKind::Prepared, b"already-provisioned")?;
        }
        let reopened = DurableStageStoreV1::open_existing(&path)?;
        assert_eq!(
            reopened.read(StageKind::Prepared)?,
            Some(b"already-provisioned".to_vec())
        );
        drop(reopened);

        io(std::fs::rename(
            path.join(AUTH_KEY_NAME),
            path.join(AUTH_KEY_STAGING),
        ))?;
        let recovered = DurableStageStoreV1::open_existing(&path)?;
        assert_eq!(
            recovered.read(StageKind::Prepared)?,
            Some(b"already-provisioned".to_vec())
        );
        assert!(path.join(AUTH_KEY_NAME).is_file());
        assert!(!path.join(AUTH_KEY_STAGING).exists());
        drop(recovered);
        cleanup(&path);
        Ok(())
    }

    #[test]
    fn production_open_existing_preserves_single_physical_owner() -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = root("existing-single-owner")?;
        let retained = DurableStageStoreV1::open_or_create(&path)?;
        retained.publish(StageKind::Prepared, b"single-owner")?;
        assert_eq!(
            DurableStageStoreV1::open_existing(&path).map(|_| ()),
            Err(LiveBitcoinError::StoreUnavailable)
        );
        assert_eq!(
            retained.read(StageKind::Prepared)?,
            Some(b"single-owner".to_vec())
        );
        drop(retained);

        let reopened = DurableStageStoreV1::open_existing(&path)?;
        assert_eq!(
            reopened.read(StageKind::Prepared)?,
            Some(b"single-owner".to_vec())
        );
        drop(reopened);
        cleanup(&path);
        Ok(())
    }

    #[test]
    fn production_open_existing_recovers_authenticated_stage_publish(
    ) -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = root("existing-stage-recovery")?;
        {
            let store = DurableStageStoreV1::open_or_create(&path)?;
            store.write_staging_for_test(StageKind::Prepared, b"durable-before-rename")?;
        }
        assert!(!path.join(StageKind::Prepared.file_name()).exists());
        assert!(path.join(StageKind::Prepared.staging_name()).is_file());

        let reopened = DurableStageStoreV1::open_existing(&path)?;
        assert_eq!(
            reopened.read(StageKind::Prepared)?,
            Some(b"durable-before-rename".to_vec())
        );
        assert!(path.join(StageKind::Prepared.file_name()).is_file());
        assert!(!path.join(StageKind::Prepared.staging_name()).exists());
        drop(reopened);
        cleanup(&path);
        Ok(())
    }

    #[test]
    fn record_tamper_and_cross_stage_substitution_fail_closed() -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let path = root("substitution")?;
        let prepared_envelope = {
            let store = DurableStageStoreV1::open_or_create(&path)?;
            store.publish(StageKind::Prepared, b"prepared")?;
            io(std::fs::read(path.join(StageKind::Prepared.file_name())))?
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut substituted = io(options.open(path.join(StageKind::Refund.file_name())))?;
        io(std::io::Write::write_all(
            &mut substituted,
            &prepared_envelope,
        ))?;
        io(substituted.sync_all())?;
        drop(substituted);
        let reopened = DurableStageStoreV1::open_or_create(&path)?;
        assert_eq!(
            reopened.read(StageKind::Refund),
            Err(LiveBitcoinError::CorruptRecord)
        );
        drop(reopened);
        cleanup(&path);

        let path = root("fresh-face-substitution")?;
        let templates_envelope = {
            let store = DurableStageStoreV1::open_or_create(&path)?;
            store.publish(StageKind::FreshTemplates, b"fresh-templates")?;
            io(std::fs::read(
                path.join(StageKind::FreshTemplates.file_name()),
            ))?
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut substituted =
            io(options.open(path.join(StageKind::FreshFaceEvidence.file_name())))?;
        io(std::io::Write::write_all(
            &mut substituted,
            &templates_envelope,
        ))?;
        io(substituted.sync_all())?;
        drop(substituted);
        let reopened = DurableStageStoreV1::open_or_create(&path)?;
        assert_eq!(
            reopened.read(StageKind::FreshFaceEvidence),
            Err(LiveBitcoinError::CorruptRecord)
        );
        drop(reopened);
        cleanup(&path);

        let path = root("tamper")?;
        {
            let store = DurableStageStoreV1::open_or_create(&path)?;
            store.publish(StageKind::Prepared, b"prepared")?;
        }
        let record = path.join(StageKind::Prepared.file_name());
        let mut bytes = io(std::fs::read(&record))?;
        bytes[18] ^= 1;
        io(std::fs::write(&record, bytes))?;
        let reopened = DurableStageStoreV1::open_or_create(&path)?;
        assert_eq!(
            reopened.read(StageKind::Prepared),
            Err(LiveBitcoinError::CorruptRecord)
        );
        cleanup(&path);
        Ok(())
    }

    #[test]
    fn existing_wrong_mode_is_rejected_without_repair() -> Result<(), LiveBitcoinError> {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = root("mode")?;
        {
            let _store = DurableStageStoreV1::open_or_create(&path)?;
        }
        let lock = path.join(LOCK_NAME);
        io(std::fs::set_permissions(
            &lock,
            std::fs::Permissions::from_mode(0o640),
        ))?;
        assert!(DurableStageStoreV1::open_or_create(&path).is_err());
        let metadata = io(std::fs::symlink_metadata(&lock))?;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        cleanup(&path);
        Ok(())
    }
}

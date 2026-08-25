//! Authenticated sealing of restartable Bitcoin claim nonce owners.

#[cfg(target_os = "linux")]
use std::fs::{DirBuilder, File};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
#[cfg(target_os = "linux")]
use cap_std::fs::Dir;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "linux")]
use rustix::fs::{
    fchmod, flock, fstat, fsync, openat2, renameat_with, statat, unlinkat, AtFlags, FileType,
    FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
};
#[cfg(target_os = "linux")]
use rustix::io::Errno;
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::{BitcoinNoncePermitV1, BitcoinNonceReservationIdV1, VaultError};

const SEAL_MAGIC: &[u8; 8] = b"DBTCNSV1";
const SEAL_VERSION: u16 = 1;
const SEAL_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F7/SEALED-NONCE-OWNER/V1\0";
const SEALED_SECRET_LEN: usize = 8 + 2 + 12 + 32 + 16;
const KEY_STORE_MAGIC: &[u8; 8] = b"DBTCKSV1";
const KEY_STORE_VERSION: u16 = 1;
const KEY_ID_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F7/NONCE-SEAL-KEY-ID/V1\0";
const KEY_STORE_ENVELOPE_LEN: usize = 8 + 2 + 32 + 32 + 32 + 16;
#[cfg(target_os = "linux")]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(target_os = "linux")]
const FILE_MODE: u32 = 0o600;
#[cfg(target_os = "linux")]
const LOCK_FILE_NAME: &str = ".nonce-seal-key-store.lock";
#[cfg(target_os = "linux")]
const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Closed names for the two participant-specific F7 nonce-owner keys.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinNonceSealKeySlotV1 {
    /// First participant in canonical roster order.
    FirstParticipant,
    /// Second participant in canonical roster order.
    SecondParticipant,
}

impl BitcoinNonceSealKeySlotV1 {
    #[cfg(target_os = "linux")]
    const fn file_name(self) -> &'static str {
        match self {
            Self::FirstParticipant => "first-participant.key",
            Self::SecondParticipant => "second-participant.key",
        }
    }

    #[cfg(target_os = "linux")]
    const fn staging_name(self) -> &'static str {
        match self {
            Self::FirstParticipant => ".first-participant.key.staging",
            Self::SecondParticipant => ".second-participant.key.staging",
        }
    }
}

/// Retained, exclusively locked owner-only store for the two F7 nonce seal
/// keys.
///
/// On Linux, the root must be a directory owned by the effective user with
/// exact mode `0700`. Descendant opens use `openat2` beneath that retained
/// directory with symlink and magic-link resolution disabled. Key files are
/// immutable, single-link, mode `0600` records. No key is accepted from an
/// argument, environment variable, log, or SQLite database.
pub struct BitcoinNonceSealKeyStoreV1 {
    #[cfg(target_os = "linux")]
    root: Dir,
    #[cfg(target_os = "linux")]
    _lock: File,
}

impl core::fmt::Debug for BitcoinNonceSealKeyStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BitcoinNonceSealKeyStoreV1([redacted])")
    }
}

/// A non-cloneable, non-serializable, zeroizing key supplied by the isolated
/// route owner to authenticate encrypted nonce continuations.
pub struct BitcoinNonceSealKeyV1 {
    bytes: Zeroizing<[u8; 32]>,
    key_id: [u8; 32],
}

impl BitcoinNonceSealKeyV1 {
    /// Imports an existing route-owner key. All-zero keys are rejected.
    pub fn new(bytes: [u8; 32]) -> Result<Self, VaultError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(VaultError::InvalidSealKey);
        }
        let key_id = key_id(&bytes)?;
        Ok(Self { bytes, key_id })
    }

    /// Stable public identifier of this key. The identifier reveals no key
    /// bytes and is safe to bind into a durable route issuance record.
    #[must_use]
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl BitcoinNonceSealKeyStoreV1 {
    /// Opens or creates one dedicated key-store directory and acquires its
    /// process-exclusive owner lock.
    ///
    /// The parent directory must already exist. A newly created root and its
    /// parent directory entry are fsync'd before use. Existing roots with a
    /// symlink, wrong owner, wrong mode, or invalid node type fail closed.
    #[cfg(target_os = "linux")]
    pub fn open_or_create(path: &Path) -> Result<Self, VaultError> {
        match DirBuilder::new().mode(DIRECTORY_MODE).create(path) {
            Ok(()) => {
                File::open(path)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| VaultError::KeyStoreUnavailable)?;
                if let Some(parent) = path.parent() {
                    File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|_| VaultError::KeyStoreUnavailable)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(VaultError::KeyStoreUnavailable),
        }
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| VaultError::KeyStoreUnavailable)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(VaultError::InvalidKeyStoreObject);
        }
        let root = Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .map_err(|_| VaultError::KeyStoreUnavailable)?;
        validate_directory(&root)?;
        let (lock_descriptor, lock_was_created) = match openat2(
            root.as_fd(),
            LOCK_FILE_NAME,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_FLAGS,
        ) {
            Ok(descriptor) => (descriptor, false),
            Err(Errno::NOENT) => match openat2(
                root.as_fd(),
                LOCK_FILE_NAME,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(FILE_MODE),
                RESOLVE_FLAGS,
            ) {
                Ok(descriptor) => (descriptor, true),
                Err(Errno::EXIST) => (
                    openat2(
                        root.as_fd(),
                        LOCK_FILE_NAME,
                        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                        RESOLVE_FLAGS,
                    )
                    .map_err(|_| VaultError::KeyStoreUnavailable)?,
                    false,
                ),
                Err(_) => return Err(VaultError::KeyStoreUnavailable),
            },
            Err(_) => return Err(VaultError::KeyStoreUnavailable),
        };
        if lock_was_created {
            fchmod(lock_descriptor.as_fd(), Mode::from_raw_mode(FILE_MODE))
                .map_err(|_| VaultError::KeyStoreUnavailable)?;
            sync_directory(&root)?;
        }
        validate_file_fd(lock_descriptor.as_fd())?;
        flock(
            lock_descriptor.as_fd(),
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| VaultError::KeyStoreUnavailable)?;
        let lock = File::from(lock_descriptor);
        require_named_file_identity(&root, LOCK_FILE_NAME, &lock)?;
        Ok(Self { root, _lock: lock })
    }

    /// Non-Linux platforms cannot satisfy the retained `openat2` authority
    /// required by the F7 laboratory.
    #[cfg(not(target_os = "linux"))]
    pub fn open_or_create(_path: &Path) -> Result<Self, VaultError> {
        Err(VaultError::KeyStoreUnavailable)
    }

    /// Reopens the exact immutable key for `slot`, or creates it with OS
    /// entropy before any nonce reservation is possible.
    ///
    /// `owner_binding` must commit to the route, participant, vault and claim
    /// continuation. A retry with another binding cannot substitute the key.
    /// Crash-interrupted staging prefixes are recoverable because no key is
    /// returned until the complete authenticated record is renamed and the
    /// retained parent directory is synchronized.
    #[cfg(target_os = "linux")]
    pub fn load_or_create(
        &self,
        slot: BitcoinNonceSealKeySlotV1,
        owner_binding: [u8; 32],
    ) -> Result<BitcoinNonceSealKeyV1, VaultError> {
        if owner_binding == [0; 32] {
            return Err(VaultError::BindingMismatch);
        }
        validate_directory(&self.root)?;
        if let Some(bytes) = read_named_record(&self.root, slot.file_name())? {
            remove_staging_if_present(&self.root, slot.staging_name())?;
            return decode_key_envelope(&bytes, &owner_binding);
        }
        if let Some(staging) = read_named_record(&self.root, slot.staging_name())? {
            match decode_key_envelope(&staging, &owner_binding) {
                Ok(_) => publish_staging(&self.root, slot)?,
                Err(_) => remove_staging_if_present(&self.root, slot.staging_name())?,
            }
            if let Some(bytes) = read_named_record(&self.root, slot.file_name())? {
                return decode_key_envelope(&bytes, &owner_binding);
            }
        }
        let mut raw_key = Zeroizing::new([0_u8; 32]);
        getrandom::getrandom(raw_key.as_mut()).map_err(|_| VaultError::EntropyUnavailable)?;
        let key = BitcoinNonceSealKeyV1::new(*raw_key)?;
        let mut envelope = encode_key_envelope(&key, &owner_binding)?;
        create_staging_record(&self.root, slot.staging_name(), &envelope)?;
        envelope.zeroize();
        publish_staging(&self.root, slot)?;
        let exact = read_named_record(&self.root, slot.file_name())?
            .ok_or(VaultError::InvalidKeyStoreObject)?;
        let reopened = decode_key_envelope(&exact, &owner_binding)?;
        if reopened.key_id() != key.key_id() {
            return Err(VaultError::InvalidKeyStoreObject);
        }
        Ok(reopened)
    }

    /// Non-Linux platforms cannot mint a production F7 sealing key.
    #[cfg(not(target_os = "linux"))]
    pub fn load_or_create(
        &self,
        _slot: BitcoinNonceSealKeySlotV1,
        _owner_binding: [u8; 32],
    ) -> Result<BitcoinNonceSealKeyV1, VaultError> {
        Err(VaultError::KeyStoreUnavailable)
    }
}

fn key_id(key_bytes: &[u8; 32]) -> Result<[u8; 32], VaultError> {
    let mut hash = Blake2bVar::new(32).map_err(|_| VaultError::InvalidKeyStoreObject)?;
    hash.update(KEY_ID_DOMAIN);
    hash.update(key_bytes);
    let mut output = [0_u8; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| VaultError::InvalidKeyStoreObject)?;
    Ok(output)
}

fn encode_key_envelope(
    key: &BitcoinNonceSealKeyV1,
    owner_binding: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_STORE_ENVELOPE_LEN));
    bytes.extend_from_slice(KEY_STORE_MAGIC);
    bytes.extend_from_slice(&KEY_STORE_VERSION.to_be_bytes());
    bytes.extend_from_slice(owner_binding);
    bytes.extend_from_slice(key.key_id());
    bytes.extend_from_slice(key.as_bytes());
    let mut empty = [];
    let tag = ChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt_in_place_detached((&[0_u8; 12]).into(), &bytes, &mut empty)
        .map_err(|_| VaultError::InvalidKeyStoreObject)?;
    bytes.extend_from_slice(&tag[..]);
    if bytes.len() != KEY_STORE_ENVELOPE_LEN {
        return Err(VaultError::InvalidKeyStoreObject);
    }
    Ok(bytes)
}

fn decode_key_envelope(
    bytes: &[u8],
    expected_owner_binding: &[u8; 32],
) -> Result<BitcoinNonceSealKeyV1, VaultError> {
    if bytes.len() != KEY_STORE_ENVELOPE_LEN
        || &bytes[..8] != KEY_STORE_MAGIC
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| VaultError::InvalidKeyStoreObject)?,
        ) != KEY_STORE_VERSION
        || &bytes[10..42] != expected_owner_binding
    {
        return Err(VaultError::InvalidKeyStoreObject);
    }
    let mut raw_key = Zeroizing::new([0_u8; 32]);
    raw_key.copy_from_slice(&bytes[74..106]);
    let key = BitcoinNonceSealKeyV1::new(*raw_key)?;
    if bytes[42..74] != key.key_id()[..] {
        return Err(VaultError::InvalidKeyStoreObject);
    }
    let mut empty = [];
    // The envelope length is checked above, so this conversion cannot fail;
    // going through `TryInto` makes the length a TYPE obligation rather than
    // an argument about the surrounding code, and maps the impossible case to
    // the error this path already uses instead of to a panic.
    let tag: [u8; 16] = bytes[106..122]
        .try_into()
        .map_err(|_| VaultError::InvalidKeyStoreObject)?;
    ChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt_in_place_detached(
            (&[0_u8; 12]).into(),
            &bytes[..106],
            &mut empty,
            (&tag).into(),
        )
        .map_err(|_| VaultError::InvalidKeyStoreObject)?;
    Ok(key)
}

#[cfg(target_os = "linux")]
fn validate_directory(directory: &Dir) -> Result<(), VaultError> {
    let stat = fstat(directory.as_fd()).map_err(|_| VaultError::KeyStoreUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != DIRECTORY_MODE
        || stat.st_nlink == 0
    {
        return Err(VaultError::InvalidKeyStoreObject);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_directory(directory: &Dir) -> Result<(), VaultError> {
    let descriptor = openat2(
        directory.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    )
    .map_err(|_| VaultError::KeyStoreUnavailable)?;
    let retained = fstat(directory.as_fd()).map_err(|_| VaultError::KeyStoreUnavailable)?;
    let reopened = fstat(descriptor.as_fd()).map_err(|_| VaultError::KeyStoreUnavailable)?;
    if retained.st_dev != reopened.st_dev
        || retained.st_ino != reopened.st_ino
        || retained.st_mode != reopened.st_mode
        || retained.st_uid != reopened.st_uid
        || reopened.st_nlink == 0
    {
        return Err(VaultError::InvalidKeyStoreObject);
    }
    fsync(descriptor.as_fd()).map_err(|_| VaultError::KeyStoreUnavailable)
}

#[cfg(target_os = "linux")]
fn validate_file_fd(file: impl AsFd) -> Result<(), VaultError> {
    let stat = fstat(file).map_err(|_| VaultError::KeyStoreUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != FILE_MODE
        || stat.st_nlink != 1
    {
        return Err(VaultError::InvalidKeyStoreObject);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_named_file_identity(root: &Dir, name: &str, retained: &File) -> Result<(), VaultError> {
    validate_file_fd(retained.as_fd())?;
    let retained_stat = fstat(retained.as_fd()).map_err(|_| VaultError::KeyStoreUnavailable)?;
    let named_stat = statat(root.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| VaultError::KeyStoreUnavailable)?;
    if retained_stat.st_dev != named_stat.st_dev
        || retained_stat.st_ino != named_stat.st_ino
        || retained_stat.st_mode != named_stat.st_mode
        || retained_stat.st_uid != named_stat.st_uid
        || named_stat.st_nlink != 1
    {
        return Err(VaultError::InvalidKeyStoreObject);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_named_record(root: &Dir, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
    let descriptor = match openat2(
        root.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(VaultError::KeyStoreUnavailable),
    };
    validate_file_fd(descriptor.as_fd())?;
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_STORE_ENVELOPE_LEN + 1));
    Read::by_ref(&mut file)
        .take((KEY_STORE_ENVELOPE_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::KeyStoreUnavailable)?;
    require_named_file_identity(root, name, &file)?;
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn create_staging_record(root: &Dir, name: &str, bytes: &[u8]) -> Result<(), VaultError> {
    let descriptor = openat2(
        root.as_fd(),
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(FILE_MODE),
        RESOLVE_FLAGS,
    )
    .map_err(|_| VaultError::KeyStoreUnavailable)?;
    fchmod(descriptor.as_fd(), Mode::from_raw_mode(FILE_MODE))
        .map_err(|_| VaultError::KeyStoreUnavailable)?;
    validate_file_fd(descriptor.as_fd())?;
    let mut file = File::from(descriptor);
    if test_crash_cut(1) {
        return Err(VaultError::KeyStoreUnavailable);
    }
    if test_crash_cut(2) {
        let prefix = bytes.len() / 2;
        file.write_all(&bytes[..prefix])
            .map_err(|_| VaultError::KeyStoreUnavailable)?;
        file.sync_all()
            .map_err(|_| VaultError::KeyStoreUnavailable)?;
        return Err(VaultError::KeyStoreUnavailable);
    }
    file.write_all(bytes)
        .map_err(|_| VaultError::KeyStoreUnavailable)?;
    if test_crash_cut(3) {
        return Err(VaultError::KeyStoreUnavailable);
    }
    fsync(file.as_fd()).map_err(|_| VaultError::KeyStoreUnavailable)?;
    require_named_file_identity(root, name, &file)?;
    if test_crash_cut(4) {
        return Err(VaultError::KeyStoreUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_staging(root: &Dir, slot: BitcoinNonceSealKeySlotV1) -> Result<(), VaultError> {
    renameat_with(
        root.as_fd(),
        slot.staging_name(),
        root.as_fd(),
        slot.file_name(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| VaultError::KeyStoreUnavailable)?;
    if test_crash_cut(5) {
        return Err(VaultError::KeyStoreUnavailable);
    }
    sync_directory(root)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_staging_if_present(root: &Dir, name: &str) -> Result<(), VaultError> {
    let descriptor = match openat2(
        root.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(()),
        Err(_) => return Err(VaultError::KeyStoreUnavailable),
    };
    let file = File::from(descriptor);
    require_named_file_identity(root, name, &file)?;
    unlinkat(root.as_fd(), name, AtFlags::empty()).map_err(|_| VaultError::KeyStoreUnavailable)?;
    sync_directory(root)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
static TEST_CRASH_CUT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[cfg(all(test, target_os = "linux"))]
fn test_crash_cut(stage: u8) -> bool {
    TEST_CRASH_CUT.load(core::sync::atomic::Ordering::SeqCst) == stage
}

#[cfg(all(not(test), target_os = "linux"))]
const fn test_crash_cut(_stage: u8) -> bool {
    false
}

pub(crate) fn seal_secret(
    key: &BitcoinNonceSealKeyV1,
    id: &BitcoinNonceReservationIdV1,
    permit: &BitcoinNoncePermitV1,
    anchor: Option<&[u8; 32]>,
    continuation_binding_digest: &[u8; 32],
    nonce_bytes: [u8; 12],
    secret: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    if *continuation_binding_digest == [0; 32] {
        return Err(VaultError::BindingMismatch);
    }
    let aad = aad(id, permit, anchor, continuation_binding_digest);
    let mut ciphertext = Zeroizing::new(*secret);
    let tag = ChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt_in_place_detached((&nonce_bytes).into(), &aad, ciphertext.as_mut())
        .map_err(|_| VaultError::SealAuthenticationFailed)?;
    let mut sealed = Vec::with_capacity(SEALED_SECRET_LEN);
    sealed.extend_from_slice(SEAL_MAGIC);
    sealed.extend_from_slice(&SEAL_VERSION.to_be_bytes());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(ciphertext.as_ref());
    sealed.extend_from_slice(&tag[..]);
    Ok(sealed)
}

pub(crate) fn open_secret(
    key: &BitcoinNonceSealKeyV1,
    id: &BitcoinNonceReservationIdV1,
    permit: &BitcoinNoncePermitV1,
    anchor: Option<&[u8; 32]>,
    continuation_binding_digest: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if sealed.len() != SEALED_SECRET_LEN
        || &sealed[..8] != SEAL_MAGIC
        || u16::from_be_bytes(
            sealed[8..10]
                .try_into()
                .map_err(|_| VaultError::CorruptState)?,
        ) != SEAL_VERSION
        || *continuation_binding_digest == [0; 32]
    {
        return Err(VaultError::CorruptState);
    }
    let aad = aad(id, permit, anchor, continuation_binding_digest);
    let mut plaintext = Zeroizing::new([0u8; 32]);
    plaintext.copy_from_slice(&sealed[22..54]);
    // Both lengths are checked above, so neither conversion can fail; going
    // through `TryInto` makes them TYPE obligations and maps the impossible
    // case to the error this path already uses instead of to a panic.
    let tag: [u8; 16] = sealed[54..70]
        .try_into()
        .map_err(|_| VaultError::CorruptState)?;
    let nonce: [u8; 12] = sealed[10..22]
        .try_into()
        .map_err(|_| VaultError::CorruptState)?;
    ChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt_in_place_detached((&nonce).into(), &aad, plaintext.as_mut(), (&tag).into())
        .map_err(|_| VaultError::SealAuthenticationFailed)?;
    Ok(plaintext)
}

fn aad(
    id: &BitcoinNonceReservationIdV1,
    permit: &BitcoinNoncePermitV1,
    anchor: Option<&[u8; 32]>,
    continuation_binding_digest: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_DOMAIN.len() + 32 * 4 + 1);
    aad.extend_from_slice(SEAL_DOMAIN);
    aad.extend_from_slice(&id.0);
    aad.extend_from_slice(&permit.binding_digest());
    match anchor {
        Some(anchor) => {
            aad.push(1);
            aad.extend_from_slice(anchor);
        }
        None => {
            aad.push(0);
            aad.extend_from_slice(&[0; 32]);
        }
    }
    aad.extend_from_slice(continuation_binding_digest);
    aad
}

impl Drop for BitcoinNonceSealKeyV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn temporary_root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "btc-nonce-key-store-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn remove_root(path: &Path) {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("btc-nonce-key-store-"))
        {
            let _ = std::fs::remove_dir_all(path);
        }
    }

    #[test]
    fn owner_only_key_reopens_exactly_and_rejects_another_binding() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = temporary_root("reopen");
        let binding = [0x31; 32];
        let first_id = {
            let store = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
            let key = store
                .load_or_create(BitcoinNonceSealKeySlotV1::FirstParticipant, binding)
                .unwrap();
            *key.key_id()
        };
        let store = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
        let reopened = store
            .load_or_create(BitcoinNonceSealKeySlotV1::FirstParticipant, binding)
            .unwrap();
        assert_eq!(reopened.key_id(), &first_id);
        assert_eq!(
            store
                .load_or_create(BitcoinNonceSealKeySlotV1::FirstParticipant, [0x32; 32])
                .err(),
            Some(VaultError::InvalidKeyStoreObject)
        );
        drop(store);
        remove_root(&root);
    }

    #[test]
    fn precreated_store_initializes_both_keys_in_one_open() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = temporary_root("precreated-first-open");
        std::fs::DirBuilder::new()
            .mode(DIRECTORY_MODE)
            .create(&root)
            .unwrap();
        let first_binding = [0x35; 32];
        let second_binding = [0x36; 32];
        let (first_id, second_id) = {
            let store = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
            let first = store
                .load_or_create(BitcoinNonceSealKeySlotV1::FirstParticipant, first_binding)
                .unwrap();
            let second = store
                .load_or_create(BitcoinNonceSealKeySlotV1::SecondParticipant, second_binding)
                .unwrap();
            (*first.key_id(), *second.key_id())
        };
        assert!(root.join(LOCK_FILE_NAME).is_file());
        assert!(root
            .join(BitcoinNonceSealKeySlotV1::FirstParticipant.file_name())
            .is_file());
        assert!(root
            .join(BitcoinNonceSealKeySlotV1::SecondParticipant.file_name())
            .is_file());
        let reopened = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
        assert_eq!(
            reopened
                .load_or_create(BitcoinNonceSealKeySlotV1::FirstParticipant, first_binding,)
                .unwrap()
                .key_id(),
            &first_id
        );
        assert_eq!(
            reopened
                .load_or_create(BitcoinNonceSealKeySlotV1::SecondParticipant, second_binding,)
                .unwrap()
                .key_id(),
            &second_id
        );
        drop(reopened);
        remove_root(&root);
    }

    #[test]
    fn tampered_key_envelope_fails_closed() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = temporary_root("tamper");
        let binding = [0x41; 32];
        {
            let store = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
            let _key = store
                .load_or_create(BitcoinNonceSealKeySlotV1::FirstParticipant, binding)
                .unwrap();
        }
        let path = root.join(BitcoinNonceSealKeySlotV1::FirstParticipant.file_name());
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[50] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let store = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
        assert_eq!(
            store
                .load_or_create(BitcoinNonceSealKeySlotV1::FirstParticipant, binding)
                .err(),
            Some(VaultError::InvalidKeyStoreObject)
        );
        drop(store);
        remove_root(&root);
    }

    #[test]
    fn existing_lock_with_non_owner_only_mode_is_rejected_without_repair() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = temporary_root("lock-mode");
        {
            let _store = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
        }
        let lock_path = root.join(LOCK_FILE_NAME);
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            BitcoinNonceSealKeyStoreV1::open_or_create(&root),
            Err(VaultError::InvalidKeyStoreObject)
        ));
        assert_eq!(
            std::fs::symlink_metadata(&lock_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        remove_root(&root);
    }

    #[test]
    fn every_key_publication_crash_prefix_recovers_without_fixed_key_input() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for cut in 1..=5 {
            let root = temporary_root(&format!("crash-{cut}"));
            let binding = [0x51_u8.saturating_add(cut); 32];
            {
                let store = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
                TEST_CRASH_CUT.store(cut, core::sync::atomic::Ordering::SeqCst);
                assert_eq!(
                    store
                        .load_or_create(BitcoinNonceSealKeySlotV1::SecondParticipant, binding)
                        .err(),
                    Some(VaultError::KeyStoreUnavailable)
                );
            }
            TEST_CRASH_CUT.store(0, core::sync::atomic::Ordering::SeqCst);
            {
                let reopened = BitcoinNonceSealKeyStoreV1::open_or_create(&root).unwrap();
                let key = reopened
                    .load_or_create(BitcoinNonceSealKeySlotV1::SecondParticipant, binding)
                    .unwrap();
                assert_ne!(key.key_id(), &[0; 32]);
            }
            remove_root(&root);
        }
    }
}

/// Frozen byte-for-byte witness of the sealed formats.
///
/// Built BEFORE the `generic-array` deprecation migration and committed on
/// its own, so that the migration has an oracle describing the behaviour of
/// the code as it stood, not the behaviour someone hoped for. Everything is
/// fixed: key, nonce, identifiers and payload. Nothing reads the clock, the
/// filesystem or an RNG, so the vectors are reproducible anywhere.
///
/// If a change to this module alters a single byte of either format, these
/// tests fail. That is their whole purpose.
#[cfg(test)]
mod frozen_format_vectors {
    use super::*;
    use crate::permit::{BitcoinNoncePurposeV1, BitcoinSigningPhaseV1};

    fn fixed_key() -> BitcoinNonceSealKeyV1 {
        let mut raw = [0_u8; 32];
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = 0x10_u8.wrapping_add(i as u8);
        }
        BitcoinNonceSealKeyV1::new(raw).expect("the fixed key is non-zero")
    }

    fn fixed_id() -> BitcoinNonceReservationIdV1 {
        BitcoinNonceReservationIdV1([0x21; 32])
    }

    fn fixed_permit() -> BitcoinNoncePermitV1 {
        BitcoinNoncePermitV1 {
            settlement_id: [0x31; 32],
            session_id: [0x32; 32],
            participant_id: [0x33; 32],
            purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
            phase: BitcoinSigningPhaseV1::PartialSignature,
            roster_hash: [0x34; 32],
            terms_hash: [0x35; 32],
            claim_template_hash: [0x36; 32],
            tap_sighash: [0x37; 32],
            adaptor_point: [0x38; 33],
            attempt: 7,
        }
    }

    const FIXED_NONCE: [u8; 12] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
    ];
    const FIXED_SECRET: [u8; 32] = [0x51; 32];
    const FIXED_ANCHOR: [u8; 32] = [0x61; 32];
    const FIXED_BINDING: [u8; 32] = [0x71; 32];
    const FIXED_OWNER_BINDING: [u8; 32] = [0x81; 32];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The sealed-secret envelope, byte for byte.
    #[test]
    fn sealed_secret_envelope_is_frozen() {
        let sealed = seal_secret(
            &fixed_key(),
            &fixed_id(),
            &fixed_permit(),
            Some(&FIXED_ANCHOR),
            &FIXED_BINDING,
            FIXED_NONCE,
            &FIXED_SECRET,
        )
        .expect("the fixed inputs seal");
        assert_eq!(sealed.len(), SEALED_SECRET_LEN);
        assert_eq!(hex(&sealed), SEALED_SECRET_VECTOR);
    }

    /// The same envelope opens back to the exact plaintext.
    #[test]
    fn sealed_secret_opens_to_the_same_secret() {
        let sealed = seal_secret(
            &fixed_key(),
            &fixed_id(),
            &fixed_permit(),
            Some(&FIXED_ANCHOR),
            &FIXED_BINDING,
            FIXED_NONCE,
            &FIXED_SECRET,
        )
        .expect("the fixed inputs seal");
        let opened = open_secret(
            &fixed_key(),
            &fixed_id(),
            &fixed_permit(),
            Some(&FIXED_ANCHOR),
            &FIXED_BINDING,
            &sealed,
        )
        .expect("the sealed envelope opens");
        assert_eq!(*opened, FIXED_SECRET);
    }

    /// The key-store envelope, byte for byte.
    #[test]
    fn key_store_envelope_is_frozen() {
        let encoded =
            encode_key_envelope(&fixed_key(), &FIXED_OWNER_BINDING).expect("the fixed key encodes");
        assert_eq!(encoded.len(), KEY_STORE_ENVELOPE_LEN);
        assert_eq!(hex(&encoded), KEY_STORE_ENVELOPE_VECTOR);
    }

    /// The same envelope decodes back to the same key identity.
    #[test]
    fn key_store_envelope_decodes_to_the_same_key() {
        let key = fixed_key();
        let encoded =
            encode_key_envelope(&key, &FIXED_OWNER_BINDING).expect("the fixed key encodes");
        let decoded = decode_key_envelope(&encoded, &FIXED_OWNER_BINDING)
            .expect("the encoded envelope decodes");
        assert_eq!(decoded.key_id(), key.key_id());
        assert_eq!(decoded.as_bytes(), key.as_bytes());
    }

    const SEALED_SECRET_VECTOR: &str = "444254434e53563100014142434445464748494a4b4cdae0e0d0be9b8cd312ba9570836c74adec3f5b2a836da936dee0ae37777f51db3a8be741a5f4c9fa5862fd3e1e60f42d";
    const KEY_STORE_ENVELOPE_VECTOR: &str = "444254434b53563100018181818181818181818181818181818181818181818181818181818181818181b938e750989016c1c6dd92d81b825fc6c5d054481af174774c9bafce1a34ee4b101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fd4f5e18e1ef242e04d114e4ad4f3f045";
}

/// Length refusals on the sealed formats.
///
/// Written alongside the `generic-array` deprecation migration, which moved
/// the tag and nonce slices onto `TryInto` so the length is a TYPE
/// obligation instead of an argument about the surrounding code.
///
/// A correction the migration produced, recorded here because it changes
/// what these tests can honestly claim: the `TryInto` conversions are
/// UNREACHABLE. Both decoders reject a wrong length in their first
/// statement, before any slice is taken, and `||` short-circuits so no
/// indexing happens on a short input. The old `from_slice` therefore could
/// not panic either — the panic was already unreachable. The migration does
/// not fix a live panic; it replaces an unreachable panic with an
/// unreachable typed error, and moves the length guarantee from prose into
/// the type system.
///
/// What these tests DO prove is the guard that makes that true, and that
/// the migrated tag really flows into the authentication.
#[cfg(test)]
mod length_refusals {
    use super::*;
    use crate::permit::{BitcoinNoncePurposeV1, BitcoinSigningPhaseV1};

    fn key() -> BitcoinNonceSealKeyV1 {
        BitcoinNonceSealKeyV1::new([0x77; 32]).expect("non-zero")
    }

    fn id() -> BitcoinNonceReservationIdV1 {
        BitcoinNonceReservationIdV1([0x21; 32])
    }

    fn permit() -> BitcoinNoncePermitV1 {
        BitcoinNoncePermitV1 {
            settlement_id: [0x31; 32],
            session_id: [0x32; 32],
            participant_id: [0x33; 32],
            purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
            phase: BitcoinSigningPhaseV1::PartialSignature,
            roster_hash: [0x34; 32],
            terms_hash: [0x35; 32],
            claim_template_hash: [0x36; 32],
            tap_sighash: [0x37; 32],
            adaptor_point: [0x38; 33],
            attempt: 7,
        }
    }

    const BINDING: [u8; 32] = [0x71; 32];

    /// Every length other than the exact one is refused with the typed
    /// error, and none of them reaches a slice — which is why the migrated
    /// conversions cannot fail.
    #[test]
    fn a_sealed_secret_of_the_wrong_length_is_refused() {
        for len in [
            0_usize,
            1,
            8,
            21,
            SEALED_SECRET_LEN - 1,
            SEALED_SECRET_LEN + 1,
            200,
        ] {
            let sealed = vec![0x00_u8; len];
            let outcome = open_secret(&key(), &id(), &permit(), None, &BINDING, &sealed);
            assert_eq!(
                outcome.err(),
                Some(VaultError::CorruptState),
                "length {len} must be refused, not indexed"
            );
        }
    }

    /// The same for the key-store envelope.
    #[test]
    fn a_key_envelope_of_the_wrong_length_is_refused() {
        for len in [
            0_usize,
            1,
            9,
            105,
            KEY_STORE_ENVELOPE_LEN - 1,
            KEY_STORE_ENVELOPE_LEN + 1,
            300,
        ] {
            let bytes = vec![0x00_u8; len];
            let outcome = decode_key_envelope(&bytes, &[0x81; 32]);
            assert_eq!(
                outcome.err(),
                Some(VaultError::InvalidKeyStoreObject),
                "length {len} must be refused, not indexed"
            );
        }
    }

    /// The migrated tag is really the one that authenticates: flipping a bit
    /// inside the tag region of a well-formed envelope is rejected.
    #[test]
    fn a_tampered_tag_fails_authentication() {
        let mut sealed = seal_secret(
            &key(),
            &id(),
            &permit(),
            None,
            &BINDING,
            [0x41; 12],
            &[0x51; 32],
        )
        .expect("seals");
        assert_eq!(sealed.len(), SEALED_SECRET_LEN);
        sealed[54] ^= 0x01;
        assert_eq!(
            open_secret(&key(), &id(), &permit(), None, &BINDING, &sealed).err(),
            Some(VaultError::SealAuthenticationFailed)
        );
    }

    /// And the migrated nonce is really the one that decrypts: flipping a bit
    /// inside the nonce region is rejected too.
    #[test]
    fn a_tampered_nonce_fails_authentication() {
        let mut sealed = seal_secret(
            &key(),
            &id(),
            &permit(),
            None,
            &BINDING,
            [0x41; 12],
            &[0x51; 32],
        )
        .expect("seals");
        sealed[10] ^= 0x01;
        assert_eq!(
            open_secret(&key(), &id(), &permit(), None, &BINDING, &sealed).err(),
            Some(VaultError::SealAuthenticationFailed)
        );
    }
}

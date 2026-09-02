//! Independent encrypted transport-identity custody for DOM Contracts.
//!
//! NAR-DC-P1-001 forbids Contracts and DOM Wallet from sharing a keystore or
//! database. This crate therefore owns a separate retained application
//! keystore for exactly two long-lived keys: an X25519 Noise static key and a
//! DOM Schnorr DSC1 identity key. Both are drawn independently from the OS
//! CSPRNG, encrypted before use, and rehydrated only into purpose-specific
//! opaque capabilities. No spending share, wallet seed, witness key, protocol
//! nonce, adaptor scalar, or route secret is accepted by this boundary.
//!
//! The production signing surface accepts only an opaque request already
//! prepared and persisted by `dom-scriptless-store`. In particular, the old
//! caller-shaped signer is not available:
//!
//! ```compile_fail
//! use dom_scriptless_identity_store::ContractsTransportIdentityStoreV1;
//! use dom_scriptless_store::SessionTransportIdentityReferenceV1;
//! use dom_scriptless_transport::UnsignedMessageV1;
//!
//! fn caller_shaped_signing_is_forbidden(
//!     identity: &ContractsTransportIdentityStoreV1,
//!     unsigned: UnsignedMessageV1,
//!     reference: &SessionTransportIdentityReferenceV1,
//! ) {
//!     let _ = identity.sign_exact_dsc1_for_session(unsigned, reference);
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use argon2::{Algorithm, Argon2, Params, Version};
use cap_std::fs::{Dir, File};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use dom_crypto::{blake2b_256_tagged, PublicKey, SecretKey};
use dom_scriptless_store::{
    CommittedOutboundDsc1V1, ContractsSessionStoreV1, PreparedDsc1SigningRequestV1,
    SessionTransportIdentityReferenceV1,
};
use dom_scriptless_transport::{
    AbortPayloadV1, EncryptedTransportV1, MessageTypeV1, NoiseRoleV1, NoiseSessionConfigV1,
    NoiseStaticKeyV1, SignedMessageV1, TransportError, UnsignedMessageV1,
};
use rand_core::{OsRng, RngCore};
use rustix::{
    fs::{
        fchmod, flock, fstat, fsync, mkdirat, openat2, renameat_with, unlinkat, AtFlags, FileType,
        FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
    },
    process::geteuid,
};
use std::{
    error::Error,
    fmt,
    io::{Read, Write},
    os::fd::AsFd,
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_NAME: &str = "contracts-transport-identity.envelope";
const LOCK_NAME: &str = "contracts-transport-identity.lock";
const STAGING_PREFIX: &str = ".contracts-transport-identity-init-";
const MAGIC: &[u8; 8] = b"DOMCTIK1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 205;
const SECRET_LEN: usize = 64;
const TAG_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
const ENVELOPE_LEN: usize = HEADER_LEN + SECRET_LEN + TAG_LEN + DIGEST_LEN;
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_LANES: u32 = 1;
const ENVELOPE_DIGEST_TAG: &str = "DOM:contracts-transport-identity-envelope:v1";
const RETAINED_ENVELOPE_DIGEST_TAG: &str = "DOM:contracts-transport-identity-retained-envelope:v1";
const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Redacted failure from the independent Contracts identity keystore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityStoreError {
    /// The retained filesystem capability or required lock failed.
    Filesystem,
    /// A root name, passphrase, or canonical field was invalid.
    InvalidInput,
    /// The operating-system CSPRNG failed.
    RandomFailure,
    /// Argon2id could not derive the fixed V1 encryption key.
    KeyDerivation,
    /// The immutable identity envelope was malformed, replaced, or tampered.
    AuthenticationFailed,
    /// A generated or recovered transport key failed its authoritative parser.
    InvalidKey,
    /// The selected store is already retained by another process authority.
    StoreBusy,
    /// Exact DSC1 signing failed at the canonical transport boundary.
    SigningFailed,
    /// The retained Contracts Store rejected the prepared request or commit.
    StoreRejected,
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Filesystem => "Contracts identity retained filesystem operation failed",
            Self::InvalidInput => "Contracts identity input is invalid",
            Self::RandomFailure => "Contracts identity OS randomness failed",
            Self::KeyDerivation => "Contracts identity key derivation failed",
            Self::AuthenticationFailed => "Contracts identity envelope authentication failed",
            Self::InvalidKey => "Contracts identity key material is invalid",
            Self::StoreBusy => "Contracts identity store is busy",
            Self::SigningFailed => "Contracts DSC1 identity signing failed",
            Self::StoreRejected => "Contracts Store rejected the DSC1 operation",
        })
    }
}

impl Error for IdentityStoreError {}

/// Owned zeroizing passphrase for the independent Contracts application
/// keystore.
pub struct ContractsIdentityPassphraseV1 {
    bytes: Zeroizing<Vec<u8>>,
}

impl ContractsIdentityPassphraseV1 {
    /// Accepts 16 through 1024 non-NUL bytes. The value is never serialized or
    /// returned by this crate.
    pub fn new(bytes: Vec<u8>) -> Result<Self, IdentityStoreError> {
        if !(16..=1024).contains(&bytes.len()) || bytes.contains(&0) {
            return Err(IdentityStoreError::InvalidInput);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }
}

/// Public reference stored by session records instead of either private key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ContractsTransportIdentityReferenceV1 {
    key_reference: [u8; 32],
    noise_public_key: [u8; 32],
    schnorr_public_key: [u8; 33],
}

impl ContractsTransportIdentityReferenceV1 {
    /// Opaque stable reference to the independent keystore record.
    pub const fn key_reference(&self) -> &[u8; 32] {
        &self.key_reference
    }

    /// X25519 public key frozen in the session's Noise terms.
    pub const fn noise_public_key(&self) -> &[u8; 32] {
        &self.noise_public_key
    }

    /// Dedicated DOM Schnorr identity public key frozen in the DSC1 roster.
    pub const fn schnorr_public_key(&self) -> &[u8; 33] {
        &self.schnorr_public_key
    }

    /// Builds the public-only session-database binding for one canonical
    /// participant. The resulting value contains no private key material.
    pub fn bind_session_participant(
        &self,
        participant_id: [u8; 32],
    ) -> Result<SessionTransportIdentityReferenceV1, IdentityStoreError> {
        let schnorr_public_key = PublicKey::from_compressed_bytes(&self.schnorr_public_key)
            .map_err(|_| IdentityStoreError::InvalidKey)?;
        SessionTransportIdentityReferenceV1::new(
            participant_id,
            self.key_reference,
            self.noise_public_key,
            schnorr_public_key,
        )
        .map_err(|_| IdentityStoreError::InvalidInput)
    }
}

impl fmt::Debug for ContractsTransportIdentityReferenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContractsTransportIdentityReferenceV1")
            .field("key_reference", &"[opaque]")
            .field("public_keys", &"[public]")
            .finish()
    }
}

/// Purpose-specific rehydrated authority over the Contracts transport keys.
///
/// It implements no `Clone`, `Debug`, codec, raw-secret accessor, or generic
/// signing callback. Noise receives only the opaque static-key object; Schnorr
/// is reachable only inside the Store-issued sign-and-commit bridge.
struct ContractsTransportIdentityV1 {
    reference: ContractsTransportIdentityReferenceV1,
    noise: NoiseStaticKeyV1,
    schnorr: SecretKey,
}

impl ContractsTransportIdentityV1 {
    /// Evidence-only compatibility boundary for the F7 wallet compositor.
    ///
    /// Production outbound DSC1 signing goes through
    /// [`ContractsTransportIdentityStoreV1::sign_and_commit_store_prepared_dsc1`],
    /// which only signs store-prepared requests. This exact-message path
    /// compiles solely for tests and the evidence/compositor builds; the
    /// paired session-store ingress still adjudicates every accepted byte.
    #[cfg(any(test, feature = "evidence-only"))]
    fn sign_exact_dsc1_for_session(
        &self,
        message: UnsignedMessageV1,
        local_reference: &SessionTransportIdentityReferenceV1,
    ) -> Result<SignedMessageV1, IdentityStoreError> {
        self.require_local_reference(local_reference)?;
        if message.sender_id() != local_reference.participant_id() {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        SignedMessageV1::sign(message, &self.schnorr).map_err(|_| IdentityStoreError::SigningFailed)
    }

    fn establish_noise_for_session<S: Read + Write>(
        &self,
        stream: S,
        role: NoiseRoleV1,
        chain_id: [u8; 32],
        session_id: [u8; 32],
        local_reference: &SessionTransportIdentityReferenceV1,
        remote_reference: &SessionTransportIdentityReferenceV1,
    ) -> Result<EncryptedTransportV1<S>, IdentityStoreError> {
        self.require_local_reference(local_reference)?;
        if local_reference.participant_id() == remote_reference.participant_id()
            || local_reference.key_reference() == remote_reference.key_reference()
            || local_reference.noise_public_key() == remote_reference.noise_public_key()
        {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        EncryptedTransportV1::establish(
            stream,
            NoiseSessionConfigV1 {
                role,
                chain_id,
                session_id,
                local_static: &self.noise,
                expected_remote_static: *remote_reference.noise_public_key(),
            },
        )
        .map_err(|_| IdentityStoreError::AuthenticationFailed)
    }

    fn require_local_reference(
        &self,
        local_reference: &SessionTransportIdentityReferenceV1,
    ) -> Result<(), IdentityStoreError> {
        if local_reference.key_reference() != self.reference.key_reference()
            || local_reference.noise_public_key() != self.reference.noise_public_key()
            || local_reference.schnorr_public_key().to_compressed_bytes()
                != *self.reference.schnorr_public_key()
        {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// Retained exclusive authority for one independent Contracts identity root.
///
/// The lock remains owned for the lifetime of this value. Dropping it removes
/// all plaintext key objects from the process but leaves the immutable
/// authenticated envelope available for restart.
pub struct ContractsTransportIdentityStoreV1 {
    parent: Arc<Dir>,
    root_name: String,
    root: Dir,
    lock: File,
    identity: ContractsTransportIdentityV1,
    root_identity: RetainedNodeIdentity,
    lock_identity: RetainedNodeIdentity,
    envelope_identity: RetainedNodeIdentity,
    retained_envelope_digest: [u8; 32],
}

impl ContractsTransportIdentityStoreV1 {
    /// Creates a new independent identity root and fsyncs its encrypted key
    /// record before returning any public key or signing/Noise authority.
    pub fn create_production(
        parent: Arc<Dir>,
        root_name: &str,
        passphrase: &ContractsIdentityPassphraseV1,
    ) -> Result<Self, IdentityStoreError> {
        validate_root_name(root_name)?;
        let (envelope, generated_reference) = generate_and_seal(passphrase)?;
        let mut staging = StagingIdentityRoot::create(Arc::clone(&parent))?;
        let root = staging.root()?;
        let (lock, lock_identity) = acquire_lock(root, true)?;
        let mut file = open_identity_file(root, ENVELOPE_NAME, true, true)?;
        fchmod(file.as_fd(), Mode::from_raw_mode(0o600))
            .map_err(|_| IdentityStoreError::Filesystem)?;
        let envelope_identity = validate_regular_file(&file)?;
        file.write_all(&envelope)
            .map_err(|_| IdentityStoreError::Filesystem)?;
        file.sync_all()
            .map_err(|_| IdentityStoreError::Filesystem)?;
        fsync(root.as_fd()).map_err(|_| IdentityStoreError::Filesystem)?;
        let (persisted, persisted_identity) = read_exact_envelope(root)?;
        envelope_identity.require_same(&persisted_identity)?;
        if persisted != envelope {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        let reopened = open_identity(&persisted, passphrase)?;
        if reopened.reference != generated_reference {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        identity_create_crash_hook("identity-create-after-envelope-persist");
        let root_identity = validate_directory(root)?;
        staging.publish(root_name)?;
        identity_create_crash_hook("identity-create-after-rename");
        fsync(parent.as_fd()).map_err(|_| IdentityStoreError::Filesystem)?;
        let named_root = open_identity_root(parent.as_ref(), root_name)?;
        root_identity.require_same(&validate_directory(&named_root)?)?;
        drop(file);
        let root = staging.into_root()?;
        Ok(Self {
            parent,
            root_name: root_name.to_owned(),
            root,
            lock,
            identity: reopened,
            root_identity,
            lock_identity,
            envelope_identity,
            retained_envelope_digest: retained_envelope_digest(&persisted),
        })
    }

    /// Reopens and authenticates an existing independent Contracts identity
    /// root under an exclusive retained lock.
    pub fn open_production(
        parent: Arc<Dir>,
        root_name: &str,
        passphrase: &ContractsIdentityPassphraseV1,
    ) -> Result<Self, IdentityStoreError> {
        validate_root_name(root_name)?;
        let root = open_identity_root(parent.as_ref(), root_name)?;
        let root_identity = validate_directory(&root)?;
        let (lock, lock_identity) = acquire_lock(&root, false)?;
        let (envelope, envelope_identity) = read_exact_envelope(&root)?;
        let identity = open_identity(&envelope, passphrase)?;
        Ok(Self {
            parent,
            root_name: root_name.to_owned(),
            root,
            lock,
            identity,
            root_identity,
            lock_identity,
            envelope_identity,
            retained_envelope_digest: retained_envelope_digest(&envelope),
        })
    }

    /// Public session/database reference for this exact encrypted record.
    pub const fn reference(&self) -> &ContractsTransportIdentityReferenceV1 {
        &self.identity.reference
    }

    /// Signs and immediately commits one opaque Store-issued DSC1 request.
    ///
    /// The retained identity inode and envelope are reauthenticated before the
    /// Store revalidates its request. The unsigned envelope is then rebuilt
    /// exclusively from the request's getters, signed by the referenced
    /// retained key, checked against the Store-issued digest, and handed
    /// directly back to the same Store for durable commit. Neither a
    /// [`SignedMessageV1`] nor raw signed bytes can leave this operation before
    /// the Store returns a committed handle.
    ///
    /// ```compile_fail
    /// use dom_scriptless_identity_store::{
    ///     ContractsTransportIdentityStoreV1, IdentityStoreError,
    /// };
    /// use dom_scriptless_store::{ContractsSessionStoreV1, PreparedDsc1SigningRequestV1};
    /// use dom_scriptless_transport::SignedMessageV1;
    ///
    /// fn signed_value_cannot_escape_before_commit(
    ///     identity: &ContractsTransportIdentityStoreV1,
    ///     store: &ContractsSessionStoreV1,
    ///     request: PreparedDsc1SigningRequestV1,
    /// ) -> Result<SignedMessageV1, IdentityStoreError> {
    ///     identity.sign_and_commit_store_prepared_dsc1(store, request)
    /// }
    /// ```
    pub fn sign_and_commit_store_prepared_dsc1(
        &self,
        store: &ContractsSessionStoreV1,
        request: PreparedDsc1SigningRequestV1,
    ) -> Result<CommittedOutboundDsc1V1, IdentityStoreError> {
        self.revalidate()?;
        store
            .revalidate_prepared_outbound_dsc1(&request)
            .map_err(|_| IdentityStoreError::StoreRejected)?;
        if request.signer_key_reference() != self.identity.reference.key_reference() {
            return Err(IdentityStoreError::AuthenticationFailed);
        }

        let kind = MessageTypeV1::try_from(request.message_type())
            .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
        let unsigned = if kind == MessageTypeV1::Abort {
            let binding_digest = request
                .payload()
                .try_into()
                .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
            let payload = AbortPayloadV1::new(binding_digest)
                .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
            UnsignedMessageV1::new_abort(
                *request.chain_id(),
                *request.session_id(),
                *request.sender_id(),
                request.sequence(),
                *request.previous_transcript_hash(),
                payload,
            )
        } else {
            UnsignedMessageV1::new(
                kind,
                *request.chain_id(),
                *request.session_id(),
                *request.sender_id(),
                request.sequence(),
                *request.previous_transcript_hash(),
                request.payload().to_vec(),
            )
        }
        .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
        let signed = SignedMessageV1::sign(unsigned, &self.identity.schnorr)
            .map_err(|_| IdentityStoreError::SigningFailed)?;
        if signed.digest() != request.unsigned_message_digest() {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        store
            .commit_prepared_outbound_dsc1(request, signed.as_bytes())
            .map_err(|_| IdentityStoreError::StoreRejected)
    }

    /// Signs one exact canonical DSC1 message after revalidating the retained
    /// inode and exact encrypted envelope, then authenticating the public-only
    /// local session reference and its sender ID. Evidence-only compatibility
    /// boundary for the F7 wallet compositor; see the inner method.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn sign_exact_dsc1_for_session(
        &self,
        message: UnsignedMessageV1,
        local_reference: &SessionTransportIdentityReferenceV1,
    ) -> Result<SignedMessageV1, IdentityStoreError> {
        self.revalidate()?;
        self.identity
            .sign_exact_dsc1_for_session(message, local_reference)
    }

    /// Establishes authenticated Noise XX only after revalidating the retained
    /// inode and exact encrypted envelope. Both public identity references
    /// must have been loaded from the session database.
    pub fn establish_noise_for_session<S: Read + Write>(
        &self,
        stream: S,
        role: NoiseRoleV1,
        chain_id: [u8; 32],
        session_id: [u8; 32],
        local_reference: &SessionTransportIdentityReferenceV1,
        remote_reference: &SessionTransportIdentityReferenceV1,
    ) -> Result<EncryptedTransportV1<S>, IdentityStoreError> {
        self.revalidate()?;
        self.identity.establish_noise_for_session(
            stream,
            role,
            chain_id,
            session_id,
            local_reference,
            remote_reference,
        )
    }

    /// Revalidates the retained root and lock before a long-running process
    /// begins a new transport connection.
    pub fn revalidate(&self) -> Result<(), IdentityStoreError> {
        let named_root = open_identity_root(self.parent.as_ref(), &self.root_name)?;
        self.root_identity
            .require_same(&validate_directory(&named_root)?)?;
        self.root_identity
            .require_same(&validate_directory(&self.root)?)?;
        self.lock_identity
            .require_same(&validate_regular_file(&self.lock)?)?;
        let named_lock = open_identity_file(&self.root, LOCK_NAME, false, true)?;
        self.lock_identity
            .require_same(&validate_regular_file(&named_lock)?)?;
        let (envelope, envelope_identity) = read_exact_envelope(&self.root)?;
        self.envelope_identity.require_same(&envelope_identity)?;
        if retained_envelope_digest(&envelope) != self.retained_envelope_digest
            || envelope_reference(&envelope)? != self.identity.reference
        {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// Owns an unpublished identity root until an atomic no-replace rename makes
/// it visible under the caller-selected production name.
struct StagingIdentityRoot {
    parent: Arc<Dir>,
    name: String,
    root: Option<Dir>,
    published: bool,
}

impl StagingIdentityRoot {
    fn create(parent: Arc<Dir>) -> Result<Self, IdentityStoreError> {
        let name = new_staging_name()?;
        mkdirat(parent.as_fd(), name.as_str(), Mode::from_raw_mode(0o700))
            .map_err(|_| IdentityStoreError::Filesystem)?;
        let root = match open_identity_root(parent.as_ref(), &name) {
            Ok(root) => root,
            Err(error) => {
                let _ = unlinkat(parent.as_fd(), name.as_str(), AtFlags::REMOVEDIR);
                let _ = fsync(parent.as_fd());
                return Err(error);
            }
        };
        let staging = Self {
            parent,
            name,
            root: Some(root),
            published: false,
        };
        let root = staging.root()?;
        fchmod(root.as_fd(), Mode::from_raw_mode(0o700))
            .map_err(|_| IdentityStoreError::Filesystem)?;
        validate_directory(root)?;
        fsync(root.as_fd()).map_err(|_| IdentityStoreError::Filesystem)?;
        fsync(staging.parent.as_fd()).map_err(|_| IdentityStoreError::Filesystem)?;
        identity_create_crash_hook("identity-create-after-staging-persist");
        Ok(staging)
    }

    fn root(&self) -> Result<&Dir, IdentityStoreError> {
        self.root.as_ref().ok_or(IdentityStoreError::Filesystem)
    }

    fn publish(&mut self, root_name: &str) -> Result<(), IdentityStoreError> {
        renameat_with(
            self.parent.as_fd(),
            self.name.as_str(),
            self.parent.as_fd(),
            root_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| IdentityStoreError::Filesystem)?;
        self.published = true;
        Ok(())
    }

    fn into_root(mut self) -> Result<Dir, IdentityStoreError> {
        self.root.take().ok_or(IdentityStoreError::Filesystem)
    }
}

impl Drop for StagingIdentityRoot {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        if let Some(root) = self.root.as_ref() {
            let _ = unlinkat(root.as_fd(), ENVELOPE_NAME, AtFlags::empty());
            let _ = unlinkat(root.as_fd(), LOCK_NAME, AtFlags::empty());
        }
        let _ = unlinkat(self.parent.as_fd(), self.name.as_str(), AtFlags::REMOVEDIR);
        let _ = fsync(self.parent.as_fd());
    }
}

fn new_staging_name() -> Result<String, IdentityStoreError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| IdentityStoreError::RandomFailure)?;
    let mut name = String::with_capacity(STAGING_PREFIX.len() + random.len() * 2);
    name.push_str(STAGING_PREFIX);
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(name)
}

#[cfg(test)]
fn identity_create_crash_hook(boundary: &str) {
    if std::env::var("DOM_F7_IDENTITY_CREATE_CRASH_CUT")
        .ok()
        .as_deref()
        != Some(boundary)
    {
        return;
    }
    if let Some(marker) = std::env::var_os("DOM_F7_IDENTITY_CREATE_CRASH_MARKER") {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(marker)
        {
            let _ = file.write_all(boundary.as_bytes());
            let _ = file.sync_all();
        }
    }
    std::process::abort();
}

#[cfg(not(test))]
fn identity_create_crash_hook(_: &str) {}

fn retained_envelope_digest(envelope: &[u8]) -> [u8; 32] {
    *blake2b_256_tagged(RETAINED_ENVELOPE_DIGEST_TAG, envelope).as_bytes()
}

fn validate_root_name(value: &str) -> Result<(), IdentityStoreError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(IdentityStoreError::InvalidInput);
    }
    Ok(())
}

fn acquire_lock(
    root: &Dir,
    create: bool,
) -> Result<(File, RetainedNodeIdentity), IdentityStoreError> {
    let file = open_identity_file(root, LOCK_NAME, create, true)?;
    if create {
        fchmod(file.as_fd(), Mode::from_raw_mode(0o600))
            .map_err(|_| IdentityStoreError::Filesystem)?;
    }
    let identity = validate_regular_file(&file)?;
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| IdentityStoreError::StoreBusy)?;
    file.sync_all()
        .map_err(|_| IdentityStoreError::Filesystem)?;
    fsync(root.as_fd()).map_err(|_| IdentityStoreError::Filesystem)?;
    Ok((file, identity))
}

fn open_identity_root(parent: &Dir, root_name: &str) -> Result<Dir, IdentityStoreError> {
    let descriptor = openat2(
        parent.as_fd(),
        root_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    )
    .map_err(|_| IdentityStoreError::Filesystem)?;
    Ok(Dir::from(descriptor))
}

fn open_identity_file(
    root: &Dir,
    name: &str,
    create: bool,
    writable: bool,
) -> Result<File, IdentityStoreError> {
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
    .map_err(|_| IdentityStoreError::Filesystem)?;
    Ok(File::from(descriptor))
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RetainedNodeIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    directory: bool,
}

impl RetainedNodeIdentity {
    fn require_same(&self, current: &Self) -> Result<(), IdentityStoreError> {
        if self != current {
            return Err(IdentityStoreError::AuthenticationFailed);
        }
        Ok(())
    }
}

fn validate_directory(directory: &Dir) -> Result<RetainedNodeIdentity, IdentityStoreError> {
    let stat = fstat(directory.as_fd()).map_err(|_| IdentityStoreError::Filesystem)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != 0o700
        || stat.st_nlink == 0
    {
        return Err(IdentityStoreError::AuthenticationFailed);
    }
    Ok(RetainedNodeIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        owner: stat.st_uid,
        directory: true,
    })
}

fn validate_regular_file(file: &File) -> Result<RetainedNodeIdentity, IdentityStoreError> {
    let stat = fstat(file.as_fd()).map_err(|_| IdentityStoreError::Filesystem)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != 0o600
        || stat.st_nlink != 1
    {
        return Err(IdentityStoreError::AuthenticationFailed);
    }
    Ok(RetainedNodeIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        owner: stat.st_uid,
        directory: false,
    })
}

fn fill_nonzero(bytes: &mut [u8; 32]) -> Result<(), IdentityStoreError> {
    loop {
        OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| IdentityStoreError::RandomFailure)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(());
        }
    }
}

fn generate_and_seal(
    passphrase: &ContractsIdentityPassphraseV1,
) -> Result<(Vec<u8>, ContractsTransportIdentityReferenceV1), IdentityStoreError> {
    let mut key_reference = [0u8; 32];
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut noise_bytes = Zeroizing::new([0u8; 32]);
    let mut schnorr_bytes = Zeroizing::new([0u8; 32]);
    fill_nonzero(&mut key_reference)?;
    fill_nonzero(&mut salt)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| IdentityStoreError::RandomFailure)?;
    fill_nonzero(&mut noise_bytes)?;
    let noise = NoiseStaticKeyV1::from_keystore_bytes(Zeroizing::new(*noise_bytes))
        .map_err(|_| IdentityStoreError::InvalidKey)?;
    let schnorr = loop {
        fill_nonzero(&mut schnorr_bytes)?;
        if schnorr_bytes.as_slice() == noise_bytes.as_slice() {
            schnorr_bytes.zeroize();
            continue;
        }
        match SecretKey::from_bytes(schnorr_bytes.as_slice()) {
            Ok(key) => break key,
            Err(_) => schnorr_bytes.zeroize(),
        }
    };
    let reference = ContractsTransportIdentityReferenceV1 {
        key_reference,
        noise_public_key: *noise.public_key(),
        schnorr_public_key: schnorr.public_key().to_compressed_bytes(),
    };
    let mut plaintext = Zeroizing::new([0u8; SECRET_LEN]);
    plaintext[..32].copy_from_slice(&noise_bytes[..]);
    plaintext[32..].copy_from_slice(&schnorr_bytes[..]);
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_le_bytes());
    header[16..48].copy_from_slice(&reference.key_reference);
    header[48..80].copy_from_slice(&reference.noise_public_key);
    header[80..113].copy_from_slice(&reference.schnorr_public_key);
    header[113..145].copy_from_slice(&salt);
    header[145..157].copy_from_slice(&nonce);
    header[157..161].copy_from_slice(&KDF_MEMORY_KIB.to_le_bytes());
    header[161..165].copy_from_slice(&KDF_ITERATIONS.to_le_bytes());
    header[165..169].copy_from_slice(&KDF_LANES.to_le_bytes());
    header[169..173].copy_from_slice(&(SECRET_LEN as u32).to_le_bytes());
    let header_digest = *blake2b_256_tagged(ENVELOPE_DIGEST_TAG, &header[..173]).as_bytes();
    header[173..205].copy_from_slice(&header_digest);
    let key = derive_key(passphrase, &salt)?;
    let tag = ChaCha20Poly1305::new((&*key).into())
        .encrypt_in_place_detached((&nonce).into(), &header, plaintext.as_mut_slice())
        .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
    let mut envelope = Vec::with_capacity(ENVELOPE_LEN);
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&plaintext[..]);
    envelope.extend_from_slice(tag.as_ref());
    let digest = *blake2b_256_tagged(ENVELOPE_DIGEST_TAG, &envelope).as_bytes();
    envelope.extend_from_slice(&digest);
    drop(noise);
    drop(schnorr);
    Ok((envelope, reference))
}

fn derive_key(
    passphrase: &ContractsIdentityPassphraseV1,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, IdentityStoreError> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_LANES, Some(32))
        .map_err(|_| IdentityStoreError::KeyDerivation)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&passphrase.bytes, salt, key.as_mut())
        .map_err(|_| IdentityStoreError::KeyDerivation)?;
    Ok(key)
}

fn open_identity(
    envelope: &[u8],
    passphrase: &ContractsIdentityPassphraseV1,
) -> Result<ContractsTransportIdentityV1, IdentityStoreError> {
    validate_envelope(envelope)?;
    let reference = envelope_reference(envelope)?;
    let salt: [u8; 32] = envelope[113..145]
        .try_into()
        .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
    let nonce: [u8; 12] = envelope[145..157]
        .try_into()
        .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
    let key = derive_key(passphrase, &salt)?;
    let header = &envelope[..HEADER_LEN];
    let mut plaintext = Zeroizing::new([0u8; SECRET_LEN]);
    plaintext.copy_from_slice(&envelope[HEADER_LEN..HEADER_LEN + SECRET_LEN]);
    let tag: [u8; TAG_LEN] = envelope[HEADER_LEN + SECRET_LEN..HEADER_LEN + SECRET_LEN + TAG_LEN]
        .try_into()
        .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
    ChaCha20Poly1305::new((&*key).into())
        .decrypt_in_place_detached(
            (&nonce).into(),
            header,
            plaintext.as_mut_slice(),
            (&tag).into(),
        )
        .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
    let noise_bytes: [u8; 32] = plaintext[..32]
        .try_into()
        .map_err(|_| IdentityStoreError::InvalidKey)?;
    let noise = NoiseStaticKeyV1::from_keystore_bytes(Zeroizing::new(noise_bytes))
        .map_err(|_| IdentityStoreError::InvalidKey)?;
    let schnorr =
        SecretKey::from_bytes(&plaintext[32..]).map_err(|_| IdentityStoreError::InvalidKey)?;
    if noise.public_key() != &reference.noise_public_key
        || schnorr.public_key().to_compressed_bytes() != reference.schnorr_public_key
        || plaintext[..32] == plaintext[32..]
    {
        return Err(IdentityStoreError::AuthenticationFailed);
    }
    Ok(ContractsTransportIdentityV1 {
        reference,
        noise,
        schnorr,
    })
}

fn validate_envelope(envelope: &[u8]) -> Result<(), IdentityStoreError> {
    if envelope.len() != ENVELOPE_LEN
        || envelope.get(..8) != Some(MAGIC)
        || envelope.get(8..10) != Some(VERSION.to_le_bytes().as_slice())
        || envelope[10..16] != [0; 6]
        || envelope[16..48] == [0; 32]
        || envelope[48..80] == [0; 32]
        || envelope[113..145] == [0; 32]
        || u32::from_le_bytes(
            envelope[157..161]
                .try_into()
                .map_err(|_| IdentityStoreError::AuthenticationFailed)?,
        ) != KDF_MEMORY_KIB
        || u32::from_le_bytes(
            envelope[161..165]
                .try_into()
                .map_err(|_| IdentityStoreError::AuthenticationFailed)?,
        ) != KDF_ITERATIONS
        || u32::from_le_bytes(
            envelope[165..169]
                .try_into()
                .map_err(|_| IdentityStoreError::AuthenticationFailed)?,
        ) != KDF_LANES
        || u32::from_le_bytes(
            envelope[169..173]
                .try_into()
                .map_err(|_| IdentityStoreError::AuthenticationFailed)?,
        ) as usize
            != SECRET_LEN
    {
        return Err(IdentityStoreError::AuthenticationFailed);
    }
    let header_digest = *blake2b_256_tagged(ENVELOPE_DIGEST_TAG, &envelope[..173]).as_bytes();
    if envelope[173..205] != header_digest
        || envelope[ENVELOPE_LEN - DIGEST_LEN..]
            != *blake2b_256_tagged(ENVELOPE_DIGEST_TAG, &envelope[..ENVELOPE_LEN - DIGEST_LEN])
                .as_bytes()
    {
        return Err(IdentityStoreError::AuthenticationFailed);
    }
    PublicKey::from_compressed_bytes(&envelope[80..113])
        .map_err(|_| IdentityStoreError::AuthenticationFailed)?;
    Ok(())
}

fn envelope_reference(
    envelope: &[u8],
) -> Result<ContractsTransportIdentityReferenceV1, IdentityStoreError> {
    validate_envelope(envelope)?;
    Ok(ContractsTransportIdentityReferenceV1 {
        key_reference: envelope[16..48]
            .try_into()
            .map_err(|_| IdentityStoreError::AuthenticationFailed)?,
        noise_public_key: envelope[48..80]
            .try_into()
            .map_err(|_| IdentityStoreError::AuthenticationFailed)?,
        schnorr_public_key: envelope[80..113]
            .try_into()
            .map_err(|_| IdentityStoreError::AuthenticationFailed)?,
    })
}

fn read_exact_envelope(root: &Dir) -> Result<(Vec<u8>, RetainedNodeIdentity), IdentityStoreError> {
    let mut file = open_identity_file(root, ENVELOPE_NAME, false, false)?;
    let identity = validate_regular_file(&file)?;
    let mut bytes = Vec::with_capacity(ENVELOPE_LEN);
    Read::by_ref(&mut file)
        .take((ENVELOPE_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| IdentityStoreError::Filesystem)?;
    if bytes.len() != ENVELOPE_LEN {
        return Err(IdentityStoreError::AuthenticationFailed);
    }
    Ok((bytes, identity))
}

impl From<TransportError> for IdentityStoreError {
    fn from(_: TransportError) -> Self {
        Self::InvalidKey
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::fs::Dir;
    use dom_adaptor::TrustedChainIdV1;
    use dom_core::Hash256;
    use dom_scriptless_store::{
        BudgetPolicyProfileV1, BudgetPolicyV1, DirectionV1,
        PreparedOperationalAbortTransportAuthorityV1, SessionChainProjectionV1,
        SessionIrreversibleV1, SessionPhaseV1, SessionRecordFieldsV1, SessionRecordV1,
        SessionTransportParticipantV1, SessionTxObservationV1, BUDGET_POLICY_LEN,
    };
    use dom_scriptless_transport::{MessageTypeV1, NoiseRoleV1};
    use static_assertions::assert_not_impl_any;
    use std::{
        collections::BTreeMap,
        fs::{self, File as AmbientFile, OpenOptions as AmbientOpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        net::{TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        os::unix::process::ExitStatusExt,
        path::{Path, PathBuf},
        process::Command,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };
    use tempfile::TempDir;

    assert_not_impl_any!(ContractsTransportIdentityV1: Clone, fmt::Debug);
    assert_not_impl_any!(ContractsTransportIdentityStoreV1: Clone, fmt::Debug);
    assert_not_impl_any!(PreparedDsc1SigningRequestV1: Clone, Copy, fmt::Debug);
    assert_not_impl_any!(CommittedOutboundDsc1V1: Clone, Copy, fmt::Debug);

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    struct MustRemainUntouchedStream {
        touched: Arc<AtomicBool>,
    }

    impl Read for MustRemainUntouchedStream {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            self.touched.store(true, Ordering::SeqCst);
            Err(std::io::Error::other("stream must remain untouched"))
        }
    }

    impl Write for MustRemainUntouchedStream {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            self.touched.store(true, Ordering::SeqCst);
            Err(std::io::Error::other("stream must remain untouched"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.touched.store(true, Ordering::SeqCst);
            Err(std::io::Error::other("stream must remain untouched"))
        }
    }

    fn passphrase() -> Result<ContractsIdentityPassphraseV1, IdentityStoreError> {
        ContractsIdentityPassphraseV1::new(
            b"correct horse battery staple for contracts identity".to_vec(),
        )
    }

    fn open_parent(path: &Path) -> Result<Arc<Dir>, std::io::Error> {
        AmbientFile::open(path).map(|file| Arc::new(Dir::from_std_file(file)))
    }

    fn production_policy() -> Result<BudgetPolicyV1, Box<dyn Error + Send + Sync>> {
        let mut bytes = [0; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
        bytes[11] = 1;
        bytes[16..48].fill(0x41);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let digest = blake2b_256_tagged("DOM:contracts-vault-budget-policy:v1", &bytes[..112]);
        bytes[112..].copy_from_slice(digest.as_bytes());
        Ok(BudgetPolicyV1::from_bytes(&bytes)?)
    }

    fn bridge_session_record(
        session_id: [u8; 32],
    ) -> Result<SessionRecordV1, Box<dyn Error + Send + Sync>> {
        Ok(SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id,
                revision: 0,
                phase: SessionPhaseV1::Created,
                terms_hash: [0x32; 32],
                transcript_hash: [0x33; 32],
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: false,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 7,
                },
                chain: SessionChainProjectionV1 {
                    tip_id: [0x34; 32],
                    tip_height: 100,
                    funding: SessionTxObservationV1::Unknown,
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            b"sealed-identity-bridge-test-payload",
        )?)
    }

    struct Dsc1BridgeFixture {
        temporary: TempDir,
        parent: Arc<Dir>,
        policy: BudgetPolicyV1,
        identity: ContractsTransportIdentityStoreV1,
        store: ContractsSessionStoreV1,
        chain: TrustedChainIdV1,
        local_participant_id: [u8; 32],
        remote_participant_id: [u8; 32],
        remote_identity_key: PublicKey,
    }

    impl Dsc1BridgeFixture {
        fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
            let temporary = TempDir::new()?;
            let parent = open_parent(temporary.path())?;
            let policy = production_policy()?;
            let identity = ContractsTransportIdentityStoreV1::create_production(
                Arc::clone(&parent),
                "bridge-identity",
                &passphrase()?,
            )?;
            let store = ContractsSessionStoreV1::create_production(
                Arc::clone(&parent),
                "bridge-sessions",
                policy.clone(),
            )?;
            let chain = TrustedChainIdV1::from_authenticated_genesis(
                0x4455_6677,
                &Hash256::from_bytes([0x91; 32]),
            );
            let remote_identity_key = SecretKey::from_bytes(&[0x71; 32])?.public_key();
            Ok(Self {
                temporary,
                parent,
                policy,
                identity,
                store,
                chain,
                local_participant_id: [0x11; 32],
                remote_participant_id: [0x22; 32],
                remote_identity_key,
            })
        }

        fn prepare_abort_authority(
            &self,
            session_id: [u8; 32],
            decision_digest: [u8; 32],
        ) -> Result<PreparedOperationalAbortTransportAuthorityV1, Box<dyn Error + Send + Sync>>
        {
            let initial = bridge_session_record(session_id)?;
            self.store.create_session(&initial)?;
            let local_public =
                PublicKey::from_compressed_bytes(self.identity.reference().schnorr_public_key())?;
            self.store.bind_transport_roster(
                session_id,
                *self.chain.as_bytes(),
                [
                    SessionTransportParticipantV1::new(
                        self.local_participant_id,
                        local_public,
                        DirectionV1::Initiator,
                    )?,
                    SessionTransportParticipantV1::new(
                        self.remote_participant_id,
                        self.remote_identity_key.clone(),
                        DirectionV1::Responder,
                    )?,
                ],
            )?;
            let local_reference = self
                .identity
                .reference()
                .bind_session_participant(self.local_participant_id)?;
            let remote_reference = SessionTransportIdentityReferenceV1::new(
                self.remote_participant_id,
                [0xe1; 32],
                [0xe2; 32],
                self.remote_identity_key.clone(),
            )?;
            self.store.bind_transport_identity_references(
                session_id,
                [local_reference, remote_reference],
            )?;
            self.store.bind_local_transport_signer(
                session_id,
                *self.identity.reference().key_reference(),
            )?;
            Ok(self.store.prepare_operational_abort_transport_authority(
                self.chain,
                session_id,
                decision_digest,
            )?)
        }

        fn prepare_abort_request(
            &self,
            session_id: [u8; 32],
            decision_digest: [u8; 32],
        ) -> Result<PreparedDsc1SigningRequestV1, Box<dyn Error + Send + Sync>> {
            let authority = self.prepare_abort_authority(session_id, decision_digest)?;
            Ok(self
                .store
                .prepare_abort_dsc1_signing_request(&authority)?
                .ok_or(IdentityStoreError::StoreRejected)?)
        }
    }

    fn regular_file_snapshot(
        root: &Path,
    ) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn Error + Send + Sync>> {
        let mut pending = vec![root.to_path_buf()];
        let mut files = BTreeMap::new();
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    pending.push(entry.path());
                } else if file_type.is_file() {
                    files.insert(entry.path(), fs::read(entry.path())?);
                }
            }
        }
        Ok(files)
    }

    #[test]
    fn store_issued_bridge_commits_only_a_handle_and_rejects_wrong_key_or_store() -> TestResult {
        let fixture = Dsc1BridgeFixture::new()?;

        let wrong_store_request = fixture.prepare_abort_request([0x41; 32], [0xa1; 32])?;
        let unrelated_store = ContractsSessionStoreV1::create_production(
            Arc::clone(&fixture.parent),
            "unrelated-sessions",
            fixture.policy.clone(),
        )?;
        assert!(matches!(
            fixture
                .identity
                .sign_and_commit_store_prepared_dsc1(&unrelated_store, wrong_store_request,),
            Err(IdentityStoreError::StoreRejected)
        ));

        let wrong_key_request = fixture.prepare_abort_request([0x42; 32], [0xa2; 32])?;
        let wrong_identity = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&fixture.parent),
            "wrong-identity",
            &passphrase()?,
        )?;
        assert_ne!(
            wrong_identity.reference().key_reference(),
            fixture.identity.reference().key_reference()
        );
        assert!(matches!(
            wrong_identity.sign_and_commit_store_prepared_dsc1(&fixture.store, wrong_key_request),
            Err(IdentityStoreError::AuthenticationFailed)
        ));

        let request = fixture.prepare_abort_request([0x43; 32], [0xa3; 32])?;
        let committed: CommittedOutboundDsc1V1 = fixture
            .identity
            .sign_and_commit_store_prepared_dsc1(&fixture.store, request)?;
        assert_ne!(committed.application_id(), &[0; 32]);
        assert_eq!(committed.session_id(), &[0x43; 32]);
        assert_eq!(committed.sender_id(), &fixture.local_participant_id);
        let signed = SignedMessageV1::decode_exact(committed.signed_bytes())?;
        assert_eq!(signed.unsigned().kind(), MessageTypeV1::Abort);
        assert_eq!(signed.unsigned().session_id(), committed.session_id());
        assert_eq!(signed.unsigned().sender_id(), committed.sender_id());
        assert_eq!(signed.unsigned().sequence(), committed.sequence());
        assert_eq!(signed.digest(), committed.message_digest());
        signed.verify_identity(&PublicKey::from_compressed_bytes(
            fixture.identity.reference().schnorr_public_key(),
        )?)?;
        fixture
            .store
            .revalidate_committed_outbound_dsc1(&committed)?;
        Ok(())
    }

    #[test]
    fn store_issued_bridge_rejects_a_request_from_an_old_store_opening() -> TestResult {
        let fixture = Dsc1BridgeFixture::new()?;
        let request = fixture.prepare_abort_request([0x44; 32], [0xa4; 32])?;
        let Dsc1BridgeFixture {
            temporary: _temporary,
            parent,
            policy,
            identity,
            store,
            ..
        } = fixture;
        drop(store);
        let reopened = ContractsSessionStoreV1::open_production(
            Arc::clone(&parent),
            "bridge-sessions",
            policy,
        )?;
        assert!(matches!(
            identity.sign_and_commit_store_prepared_dsc1(&reopened, request),
            Err(IdentityStoreError::StoreRejected)
        ));
        Ok(())
    }

    #[test]
    fn store_issued_bridge_revalidates_keystore_before_signing() -> TestResult {
        let fixture = Dsc1BridgeFixture::new()?;
        let request = fixture.prepare_abort_request([0x45; 32], [0xa5; 32])?;
        let envelope_path = fixture
            .temporary
            .path()
            .join("bridge-identity")
            .join(ENVELOPE_NAME);
        let mut envelope = AmbientOpenOptions::new()
            .read(true)
            .write(true)
            .open(envelope_path)?;
        envelope.seek(SeekFrom::Start((HEADER_LEN + 3) as u64))?;
        let mut byte = [0_u8; 1];
        envelope.read_exact(&mut byte)?;
        envelope.seek(SeekFrom::Current(-1))?;
        byte[0] ^= 0x01;
        envelope.write_all(&byte)?;
        envelope.sync_all()?;
        drop(envelope);

        assert!(matches!(
            fixture
                .identity
                .sign_and_commit_store_prepared_dsc1(&fixture.store, request),
            Err(IdentityStoreError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn store_issued_bridge_revalidates_the_durable_request_before_signing() -> TestResult {
        let fixture = Dsc1BridgeFixture::new()?;
        let authority = fixture.prepare_abort_authority([0x46; 32], [0xa6; 32])?;
        let store_root = fixture.temporary.path().join("bridge-sessions");
        let before = regular_file_snapshot(&store_root)?;
        let request = fixture
            .store
            .prepare_abort_dsc1_signing_request(&authority)?
            .ok_or(IdentityStoreError::StoreRejected)?;
        let after = regular_file_snapshot(&store_root)?;
        let changed: Vec<_> = after
            .iter()
            .filter(|(path, bytes)| before.get(*path) != Some(*bytes))
            .map(|(path, _)| path.clone())
            .collect();
        assert_eq!(changed.len(), 1, "one owner-only request record is added");
        let mut retained = AmbientOpenOptions::new()
            .read(true)
            .write(true)
            .open(&changed[0])?;
        let offset = after
            .get(&changed[0])
            .ok_or(IdentityStoreError::Filesystem)?
            .len()
            / 2;
        retained.seek(SeekFrom::Start(u64::try_from(offset)?))?;
        let mut byte = [0_u8; 1];
        retained.read_exact(&mut byte)?;
        retained.seek(SeekFrom::Current(-1))?;
        byte[0] ^= 0x80;
        retained.write_all(&byte)?;
        retained.sync_all()?;
        drop(retained);

        assert!(matches!(
            fixture
                .identity
                .sign_and_commit_store_prepared_dsc1(&fixture.store, request),
            Err(IdentityStoreError::StoreRejected)
        ));
        Ok(())
    }

    #[test]
    fn transactional_create_crash_cuts_never_publish_an_incomplete_root() -> TestResult {
        for cut in [
            "identity-create-after-staging-persist",
            "identity-create-after-envelope-persist",
            "identity-create-after-rename",
        ] {
            let temp = TempDir::new()?;
            let marker = temp.path().join("crash.marker");
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg("tests::transactional_create_crash_child")
                .env("DOM_F7_IDENTITY_CREATE_PARENT", temp.path())
                .env("DOM_F7_IDENTITY_CREATE_CRASH_CUT", cut)
                .env("DOM_F7_IDENTITY_CREATE_CRASH_MARKER", &marker)
                .status()?;
            assert!(!status.success());
            assert!(status.signal().is_some());
            assert_eq!(fs::read(&marker)?, cut.as_bytes());

            let parent = open_parent(temp.path())?;
            let final_root = temp.path().join("identity-a");
            if cut == "identity-create-after-rename" {
                assert!(final_root.is_dir());
                assert!(matches!(
                    ContractsTransportIdentityStoreV1::create_production(
                        Arc::clone(&parent),
                        "identity-a",
                        &passphrase()?,
                    ),
                    Err(IdentityStoreError::Filesystem)
                ));
                let reopened = ContractsTransportIdentityStoreV1::open_production(
                    parent,
                    "identity-a",
                    &passphrase()?,
                )?;
                reopened.revalidate()?;
            } else {
                assert!(!final_root.exists());
                let completed = ContractsTransportIdentityStoreV1::create_production(
                    Arc::clone(&parent),
                    "identity-a",
                    &passphrase()?,
                )?;
                let reference = *completed.reference();
                drop(completed);
                let reopened = ContractsTransportIdentityStoreV1::open_production(
                    parent,
                    "identity-a",
                    &passphrase()?,
                )?;
                assert_eq!(reopened.reference(), &reference);
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by transactional_create_crash_cuts_never_publish_an_incomplete_root"]
    fn transactional_create_crash_child() -> TestResult {
        let parent_path = std::env::var_os("DOM_F7_IDENTITY_CREATE_PARENT")
            .ok_or(IdentityStoreError::InvalidInput)?;
        let parent = open_parent(Path::new(&parent_path))?;
        let _unexpected = ContractsTransportIdentityStoreV1::create_production(
            parent,
            "identity-a",
            &passphrase()?,
        )?;
        Err(Box::new(IdentityStoreError::Filesystem))
    }

    #[test]
    fn restart_rehydrates_the_same_public_identity() -> TestResult {
        let temp = TempDir::new()?;
        let parent = open_parent(temp.path())?;
        let store = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "identity-a",
            &passphrase()?,
        )?;
        let reference = *store.reference();
        let session_reference = reference.bind_session_participant([0x41; 32])?;
        assert_eq!(session_reference.participant_id(), &[0x41; 32]);
        assert_eq!(session_reference.key_reference(), reference.key_reference());
        assert_eq!(
            session_reference.noise_public_key(),
            reference.noise_public_key()
        );
        PublicKey::from_compressed_bytes(reference.schnorr_public_key())?;
        store.revalidate()?;
        drop(store);

        let reopened = ContractsTransportIdentityStoreV1::open_production(
            Arc::clone(&parent),
            "identity-a",
            &passphrase()?,
        )?;
        assert_eq!(reopened.reference(), &reference);
        reopened.revalidate()?;
        Ok(())
    }

    #[test]
    fn wrong_passphrase_tamper_and_parallel_open_fail_closed() -> TestResult {
        let temp = TempDir::new()?;
        let parent = open_parent(temp.path())?;
        let store = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "identity-a",
            &passphrase()?,
        )?;
        assert!(matches!(
            ContractsTransportIdentityStoreV1::open_production(
                Arc::clone(&parent),
                "identity-a",
                &passphrase()?
            ),
            Err(IdentityStoreError::StoreBusy)
        ));
        drop(store);

        let wrong = ContractsIdentityPassphraseV1::new(
            b"a deliberately different contracts identity passphrase".to_vec(),
        )?;
        assert!(matches!(
            ContractsTransportIdentityStoreV1::open_production(
                Arc::clone(&parent),
                "identity-a",
                &wrong
            ),
            Err(IdentityStoreError::AuthenticationFailed)
        ));

        let envelope_path = temp.path().join("identity-a").join(ENVELOPE_NAME);
        let mut envelope = AmbientOpenOptions::new()
            .read(true)
            .write(true)
            .open(envelope_path)?;
        envelope.seek(SeekFrom::Start((HEADER_LEN + 7) as u64))?;
        let mut byte = [0u8; 1];
        envelope.read_exact(&mut byte)?;
        envelope.seek(SeekFrom::Current(-1))?;
        byte[0] ^= 0x80;
        envelope.write_all(&byte)?;
        envelope.sync_all()?;
        drop(envelope);
        assert!(matches!(
            ContractsTransportIdentityStoreV1::open_production(
                parent,
                "identity-a",
                &passphrase()?
            ),
            Err(IdentityStoreError::AuthenticationFailed)
        ));
        Ok(())
    }

    /// The envelope decoder refuses every length but the exact one. This is
    /// the reachability witness for the fixed-width tag slice the AEAD call
    /// takes: `validate_envelope` short-circuits on `len() != ENVELOPE_LEN`
    /// before any indexing, so a short buffer never reaches the slice and
    /// the conversion behind it can only ever see exactly `TAG_LEN` bytes.
    #[test]
    fn open_identity_refuses_every_envelope_length_but_the_exact_one() -> TestResult {
        let (envelope, _reference) = generate_and_seal(&passphrase()?)?;
        assert_eq!(envelope.len(), ENVELOPE_LEN);
        for length in [
            0,
            1,
            HEADER_LEN,
            HEADER_LEN + SECRET_LEN,
            ENVELOPE_LEN - TAG_LEN,
            ENVELOPE_LEN - 1,
        ] {
            assert!(matches!(
                open_identity(&envelope[..length], &passphrase()?),
                Err(IdentityStoreError::AuthenticationFailed)
            ));
        }
        let mut longer = envelope.clone();
        longer.push(0);
        assert!(matches!(
            open_identity(&longer, &passphrase()?),
            Err(IdentityStoreError::AuthenticationFailed)
        ));
        assert!(open_identity(&envelope, &passphrase()?).is_ok());
        Ok(())
    }

    #[test]
    fn permissive_or_multiply_linked_envelope_is_rejected() -> TestResult {
        let temp = TempDir::new()?;
        let parent = open_parent(temp.path())?;
        let store = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "identity-a",
            &passphrase()?,
        )?;
        drop(store);
        let envelope_path = temp.path().join("identity-a").join(ENVELOPE_NAME);
        fs::set_permissions(&envelope_path, fs::Permissions::from_mode(0o640))?;
        assert!(matches!(
            ContractsTransportIdentityStoreV1::open_production(
                Arc::clone(&parent),
                "identity-a",
                &passphrase()?
            ),
            Err(IdentityStoreError::AuthenticationFailed)
        ));
        fs::set_permissions(&envelope_path, fs::Permissions::from_mode(0o600))?;
        fs::hard_link(
            &envelope_path,
            temp.path().join("identity-a").join("unexpected-hard-link"),
        )?;
        assert!(matches!(
            ContractsTransportIdentityStoreV1::open_production(
                parent,
                "identity-a",
                &passphrase()?
            ),
            Err(IdentityStoreError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn same_inode_mutation_revokes_live_signing_and_noise_before_use() -> TestResult {
        let temp = TempDir::new()?;
        let parent = open_parent(temp.path())?;
        let store = ContractsTransportIdentityStoreV1::create_production(
            parent,
            "identity-a",
            &passphrase()?,
        )?;
        let local = store.reference().bind_session_participant([0x41; 32])?;
        let remote_key = SecretKey::from_bytes(&[0x51; 32])?;
        let remote = SessionTransportIdentityReferenceV1::new(
            [0x42; 32],
            [0x61; 32],
            [0x62; 32],
            remote_key.public_key(),
        )?;
        let envelope_path = temp.path().join("identity-a").join(ENVELOPE_NAME);
        let mut envelope = AmbientOpenOptions::new()
            .read(true)
            .write(true)
            .open(envelope_path)?;
        envelope.seek(SeekFrom::Start((HEADER_LEN + 3) as u64))?;
        let mut byte = [0u8; 1];
        envelope.read_exact(&mut byte)?;
        envelope.seek(SeekFrom::Current(-1))?;
        byte[0] ^= 0x01;
        envelope.write_all(&byte)?;
        envelope.sync_all()?;
        drop(envelope);

        assert!(matches!(
            store.revalidate(),
            Err(IdentityStoreError::AuthenticationFailed)
        ));
        let touched = Arc::new(AtomicBool::new(false));
        assert!(matches!(
            store.establish_noise_for_session(
                MustRemainUntouchedStream {
                    touched: Arc::clone(&touched),
                },
                NoiseRoleV1::Initiator,
                [0x31; 32],
                [0x32; 32],
                &local,
                &remote,
            ),
            Err(IdentityStoreError::AuthenticationFailed)
        ));
        assert!(!touched.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn restart_tcp_noise_uses_the_frozen_public_keys_and_dsc1_identity() -> TestResult {
        let temp = TempDir::new()?;
        let parent = open_parent(temp.path())?;
        let alice = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "alice",
            &passphrase()?,
        )?;
        let bob = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "bob",
            &passphrase()?,
        )?;
        let alice_reference = *alice.reference();
        let bob_reference = *bob.reference();
        let alice_session_reference = alice_reference.bind_session_participant([0x41; 32])?;
        let bob_session_reference = bob_reference.bind_session_participant([0x42; 32])?;
        assert_ne!(
            alice_reference.key_reference(),
            bob_reference.key_reference()
        );
        assert_ne!(
            alice_reference.noise_public_key(),
            bob_reference.noise_public_key()
        );
        assert_ne!(
            alice_reference.schnorr_public_key(),
            bob_reference.schnorr_public_key()
        );
        drop(alice);
        drop(bob);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let responder_parent = Arc::clone(&parent);
        let responder_alice_reference = alice_session_reference.clone();
        let responder_bob_reference = bob_session_reference.clone();
        let responder = thread::spawn(move || -> TestResult {
            let bob = ContractsTransportIdentityStoreV1::open_production(
                responder_parent,
                "bob",
                &passphrase()?,
            )?;
            assert_eq!(bob.reference(), &bob_reference);
            let (stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            let mut channel = bob.establish_noise_for_session(
                stream,
                NoiseRoleV1::Responder,
                [0x31; 32],
                [0x32; 32],
                &responder_bob_reference,
                &responder_alice_reference,
            )?;
            let received = channel.receive_message()?;
            assert_eq!(received, b"restart-noise-test");
            channel.send_message(b"restart-ack")?;
            Ok(())
        });

        let alice = ContractsTransportIdentityStoreV1::open_production(
            Arc::clone(&parent),
            "alice",
            &passphrase()?,
        )?;
        assert_eq!(alice.reference(), &alice_reference);
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut channel = alice.establish_noise_for_session(
            stream,
            NoiseRoleV1::Initiator,
            [0x31; 32],
            [0x32; 32],
            &alice_session_reference,
            &bob_session_reference,
        )?;
        channel.send_message(b"restart-noise-test")?;
        assert_eq!(channel.receive_message()?, b"restart-ack");
        responder
            .join()
            .map_err(|_| IdentityStoreError::Filesystem)??;
        Ok(())
    }
}

#![forbid(unsafe_code)]

//! Atomic generation storage for encrypted canonical wallet state.

use dom_wallet_crypto::{decode, encode, open, seal, CryptoError, KdfParameters};
use dom_wallet_domain::{
    NetworkIdentity, NodeConfiguration, RescanPlan, WalletState, MODEL_VERSION,
    RECOVERY_SCHEME_BIP39_256_V1, SECRET_PROFILE_VERSION,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

const METADATA_FILE: &str = "metadata.json";
const ACTIVE_FILE: &str = "active-generation";
const GENERATIONS_DIR: &str = "generations";
const STATE_FILE: &str = "state.envelope";
const AUTHENTICATION_FILE: &str = "authentication.envelope";
const AUTHENTICATION_PLAINTEXT: &[u8] = b"DOM-WALLET-V3-PASSWORD-CHECK-V1";
const RESCAN_PLAN_FILE: &str = "rescan-plan.envelope";
const WRITER_LOCK_FILE: &str = ".wallet.lock";
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const BACKUP_MAGIC: [u8; 8] = *b"DOMWBK01";
pub const BACKUP_FORMAT_VERSION: u16 = 1;
pub const MAX_BACKUP_BYTES: usize = 20 * 1024 * 1024;
pub const RETAIN_SUPERSEDED_GENERATIONS: usize = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletMetadata {
    pub metadata_version: u16,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub schema_version: u16,
    pub secret_profile_version: u16,
    pub active_generation: u64,
}

/// The outer, non-secret backup header is authenticated as AEAD associated
/// data.  The encrypted payload carries the complete active V3 state and the
/// durable rescan plan; it is never an archive of filesystem paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupContainer {
    pub magic: [u8; 8],
    pub format_version: u16,
    pub created_unix_seconds: u64,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub envelope: dom_wallet_crypto::EncryptedEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupPayload {
    payload_version: u16,
    state: WalletState,
    rescan_plan: Option<RescanPlan>,
}

impl WalletMetadata {
    fn from_state(state: &WalletState) -> Self {
        Self {
            metadata_version: 1,
            wallet_id: state.wallet_id,
            identity: state.identity.clone(),
            schema_version: MODEL_VERSION,
            secret_profile_version: SECRET_PROFILE_VERSION,
            active_generation: state.generation,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WalletDirectory {
    root: PathBuf,
    _writer_lock: Arc<File>,
}

impl WalletDirectory {
    fn create_staging_path(root: &Path) -> Result<PathBuf, StorageError> {
        let parent = root.parent().ok_or(StorageError::UnsafePath)?;
        let name = root.file_name().ok_or(StorageError::UnsafePath)?;
        Ok(parent.join(format!(".{}.create-staging", name.to_string_lossy())))
    }

    pub fn create(
        root: impl AsRef<Path>,
        state: &WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StorageError::UnsafePath);
            }
            Ok(_) => return Err(StorageError::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StorageError::Io(error)),
        }
        let parent = root.parent().ok_or(StorageError::UnsafePath)?.to_path_buf();
        let parent_metadata = fs::symlink_metadata(&parent).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io(error)
            }
        })?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(StorageError::UnsafePath);
        }
        let staging = Self::create_staging_path(&root)?;
        match fs::symlink_metadata(&staging) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StorageError::UnsafePath);
            }
            Ok(_) => return Err(StorageError::IncompleteGeneration),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StorageError::Io(error)),
        }
        state.validate().map_err(StorageError::Domain)?;
        create_private_directory(&staging)?;
        let result = (|| {
            create_private_directory(&staging.join(GENERATIONS_DIR))?;
            let wallet = Self {
                _writer_lock: acquire_writer_lock(&staging)?,
                root: staging.clone(),
            };
            wallet.publish_initial(state, password, kdf)?;
            sync_directory(&staging)?;
            drop(wallet);
            fs::rename(&staging, &root).map_err(StorageError::Io)?;
            sync_directory(&parent)?;
            Self::open(&root)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    /// Authenticated crash recovery for a fully committed create stage.
    pub fn resume_create(
        root: impl AsRef<Path>,
        password: &str,
    ) -> Result<(Self, WalletState), StorageError> {
        let root = root.as_ref().to_path_buf();
        if root.exists() {
            return Err(StorageError::AlreadyExists);
        }
        let parent = root.parent().ok_or(StorageError::UnsafePath)?;
        let staging = Self::create_staging_path(&root)?;
        Self::inspect_structure(&staging)?;
        let wallet = Self::open(&staging)?;
        let state = wallet.load(password)?;
        if !state.recovery.as_ref().is_some_and(|recovery| {
            recovery.scheme == RECOVERY_SCHEME_BIP39_256_V1 && !recovery.phrase_confirmed
        }) {
            return Err(StorageError::IncompleteGeneration);
        }
        drop(wallet);
        sync_directory(&staging)?;
        fs::rename(&staging, &root).map_err(StorageError::Io)?;
        sync_directory(parent)?;
        Ok((Self::open(&root)?, state))
    }

    /// Remove only an authenticated, structurally valid interrupted create.
    pub fn abort_create(root: impl AsRef<Path>, password: &str) -> Result<(), StorageError> {
        let root = root.as_ref();
        if root.exists() {
            return Err(StorageError::AlreadyExists);
        }
        let parent = root.parent().ok_or(StorageError::UnsafePath)?;
        let staging = Self::create_staging_path(root)?;
        Self::inspect_structure(&staging)?;
        let wallet = Self::open(&staging)?;
        wallet.load(password)?;
        drop(wallet);
        fs::remove_dir_all(&staging).map_err(StorageError::Io)?;
        sync_directory(parent)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        let metadata = root.symlink_metadata().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io(error)
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StorageError::NotFound);
        }
        Self::inspect_structure(&root)?;
        Ok(Self {
            _writer_lock: acquire_writer_lock(&root)?,
            root,
        })
    }

    pub fn metadata(&self) -> Result<WalletMetadata, StorageError> {
        let bytes = read_bounded(&self.root.join(METADATA_FILE))?;
        let metadata: WalletMetadata =
            serde_json::from_slice(&bytes).map_err(|_| StorageError::InvalidMetadata)?;
        if metadata.metadata_version != 1
            || metadata.schema_version != MODEL_VERSION
            || metadata.secret_profile_version != SECRET_PROFILE_VERSION
        {
            return Err(StorageError::UnsupportedVersion);
        }
        Ok(metadata)
    }

    /// Perform a lock-free structural catalog check. This never decrypts state
    /// and never mutates a wallet.
    pub fn inspect_structure(root: impl AsRef<Path>) -> Result<WalletMetadata, StorageError> {
        let root = root.as_ref();
        let root_metadata = fs::symlink_metadata(root).map_err(StorageError::Io)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(StorageError::UnsafePath);
        }
        let metadata_path = root.join(METADATA_FILE);
        require_regular_file(&metadata_path)?;
        let metadata_bytes = read_bounded(&metadata_path)?;
        let metadata: WalletMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|_| StorageError::InvalidMetadata)?;
        if metadata.metadata_version != 1
            || metadata.schema_version != MODEL_VERSION
            || metadata.secret_profile_version != SECRET_PROFILE_VERSION
        {
            return Err(StorageError::UnsupportedVersion);
        }
        let active_path = root.join(ACTIVE_FILE);
        require_regular_file(&active_path)?;
        let active_bytes = read_bounded(&active_path)?;
        let active_text = std::str::from_utf8(&active_bytes)
            .map_err(|_| StorageError::InvalidActiveGeneration)?;
        let active = parse_generation(active_text)?;
        let interrupted_publication = metadata
            .active_generation
            .checked_add(1)
            .is_some_and(|next| next == active);
        if active != metadata.active_generation && !interrupted_publication {
            return Err(StorageError::GenerationConflict);
        }
        let generations = root.join(GENERATIONS_DIR);
        let generations_metadata = fs::symlink_metadata(&generations).map_err(StorageError::Io)?;
        if generations_metadata.file_type().is_symlink() || !generations_metadata.is_dir() {
            return Err(StorageError::UnsafePath);
        }
        let generation = generations.join(generation_name(active));
        let generation_metadata = fs::symlink_metadata(&generation).map_err(StorageError::Io)?;
        if generation_metadata.file_type().is_symlink() || !generation_metadata.is_dir() {
            return Err(StorageError::UnsafePath);
        }
        let state_path = generation.join(STATE_FILE);
        require_regular_file(&state_path)?;
        let state_encoded = read_bounded(&state_path)?;
        decode(&state_encoded).map_err(|_| StorageError::AuthenticatedPayloadCorrupt)?;
        let authentication = root.join(AUTHENTICATION_FILE);
        if authentication.exists() {
            require_regular_file(&authentication)?;
            let authentication_encoded = read_bounded(&authentication)?;
            decode(&authentication_encoded).map_err(|_| StorageError::AuthenticationDataCorrupt)?;
        }
        Ok(metadata)
    }

    pub fn load(&self, password: &str) -> Result<WalletState, StorageError> {
        let metadata = self.metadata()?;
        let password_authenticated = self.authenticate_password(password, &metadata)?;
        let active = self.active_generation()?;
        let interrupted_publication = metadata
            .active_generation
            .checked_add(1)
            .is_some_and(|next| next == active);
        if active != metadata.active_generation && !interrupted_publication {
            return Err(StorageError::GenerationConflict);
        }
        let state = self.load_generation(active, password, &metadata, password_authenticated)?;
        if state.generation != active
            || state.wallet_id != metadata.wallet_id
            || state.identity != metadata.identity
        {
            return Err(StorageError::GenerationConflict);
        }
        state.validate().map_err(StorageError::Domain)?;
        if interrupted_publication {
            let repaired = serde_json::to_vec(&WalletMetadata::from_state(&state))
                .map_err(|_| StorageError::CanonicalEncoding)?;
            atomic_write(&self.root.join(METADATA_FILE), &repaired)?;
            sync_directory(&self.root)?;
        }
        if !password_authenticated {
            self.write_authenticator(password, &metadata, KdfParameters::DOM_CONTINUITY)?;
        }
        Ok(state)
    }

    pub fn commit(
        &self,
        expected_generation: u64,
        state: WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<WalletState, StorageError> {
        let state = self.stage_generation(expected_generation, state, password, kdf)?;
        self.publish_staged_generation(expected_generation, &state)?;
        Ok(state)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes a complete encrypted generation without changing the sole active
    /// pointer. This is the first half of the existing commit protocol.
    pub fn stage_generation(
        &self,
        expected_generation: u64,
        mut state: WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<WalletState, StorageError> {
        let metadata = self.metadata()?;
        let active = self.active_generation()?;
        if active != expected_generation || metadata.active_generation != expected_generation {
            return Err(StorageError::ExpectedGenerationConflict { current: active });
        }
        if state.wallet_id != metadata.wallet_id || state.identity != metadata.identity {
            return Err(StorageError::IdentityMismatch);
        }
        state.generation = expected_generation
            .checked_add(1)
            .ok_or(StorageError::GenerationOverflow)?;
        state.validate().map_err(StorageError::Domain)?;
        self.remove_unpublished_generation(state.generation)?;
        self.write_generation(&state, password, kdf)?;
        Ok(state)
    }

    /// Publishes only a previously complete generation through the existing
    /// pointer+metadata atomic publication path.
    pub fn publish_staged_generation(
        &self,
        expected_generation: u64,
        state: &WalletState,
    ) -> Result<(), StorageError> {
        let active = self.active_generation()?;
        if active != expected_generation {
            return Err(StorageError::ExpectedGenerationConflict { current: active });
        }
        if state.generation
            != expected_generation
                .checked_add(1)
                .ok_or(StorageError::GenerationOverflow)?
        {
            return Err(StorageError::GenerationConflict);
        }
        state.validate().map_err(StorageError::Domain)?;
        self.publish_pointer_and_metadata(state)
    }

    pub fn load_generation_for_recovery(
        &self,
        generation: u64,
        password: &str,
    ) -> Result<WalletState, StorageError> {
        let metadata = self.metadata()?;
        let password_authenticated = self.authenticate_password(password, &metadata)?;
        let state =
            self.load_generation(generation, password, &metadata, password_authenticated)?;
        if state.generation != generation
            || state.wallet_id != metadata.wallet_id
            || state.identity != metadata.identity
        {
            return Err(StorageError::GenerationConflict);
        }
        state.validate().map_err(StorageError::Domain)?;
        Ok(state)
    }

    /// Durable staging is deliberately outside the active-generation pointer:
    /// a failed or interrupted rescan cannot publish partial canonical state.
    pub fn save_rescan_plan(
        &self,
        state: &WalletState,
        plan: &RescanPlan,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<(), StorageError> {
        let plaintext = serde_json::to_vec(plan).map_err(|_| StorageError::CanonicalEncoding)?;
        let context = rescan_context(state.wallet_id, &state.identity);
        let encoded =
            encode(&seal(&plaintext, password, &context, kdf).map_err(StorageError::Crypto)?)
                .map_err(StorageError::Crypto)?;
        atomic_write(&self.root.join(RESCAN_PLAN_FILE), &encoded)
    }

    pub fn load_rescan_plan(
        &self,
        state: &WalletState,
        password: &str,
    ) -> Result<Option<RescanPlan>, StorageError> {
        let path = self.root.join(RESCAN_PLAN_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let envelope = decode(&read_bounded(&path)?).map_err(StorageError::Crypto)?;
        let context = rescan_context(state.wallet_id, &state.identity);
        let plaintext = open(&envelope, password, &context).map_err(StorageError::Crypto)?;
        let plan =
            serde_json::from_slice(&plaintext).map_err(|_| StorageError::CanonicalEncoding)?;
        Ok(Some(plan))
    }

    pub fn clear_rescan_plan(&self) -> Result<(), StorageError> {
        let path = self.root.join(RESCAN_PLAN_FILE);
        if path.exists() {
            fs::remove_file(path).map_err(StorageError::Io)?;
            sync_directory(&self.root)?;
        }
        Ok(())
    }

    /// Exports one coherent committed generation, rather than a collection of
    /// mutable wallet files. The outer envelope uses the same Argon2id and
    /// authenticated-encryption profile as storage, with independent salt and
    /// nonce under the explicitly supplied backup password.
    pub fn export_backup(
        &self,
        wallet_password: &str,
        backup_password: &str,
        kdf: KdfParameters,
        destination: impl AsRef<Path>,
    ) -> Result<(), StorageError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StorageError::BackupDestinationExists);
        }
        let state = self.load(wallet_password)?;
        let plan = self.load_rescan_plan(&state, wallet_password)?;
        let created_unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StorageError::Clock)?
            .as_secs();
        let payload = BackupPayload {
            payload_version: BACKUP_FORMAT_VERSION,
            state: state.clone(),
            rescan_plan: plan,
        };
        let plaintext =
            serde_json::to_vec(&payload).map_err(|_| StorageError::CanonicalEncoding)?;
        if plaintext.is_empty() || plaintext.len() > MAX_STATE_BYTES {
            return Err(StorageError::FileSizeOutOfBounds);
        }
        let context = backup_context(created_unix_seconds, state.wallet_id, &state.identity);
        let envelope =
            seal(&plaintext, backup_password, &context, kdf).map_err(StorageError::Crypto)?;
        let container = BackupContainer {
            magic: BACKUP_MAGIC,
            format_version: BACKUP_FORMAT_VERSION,
            created_unix_seconds,
            wallet_id: state.wallet_id,
            identity: state.identity,
            envelope,
        };
        let encoded =
            serde_json::to_vec(&container).map_err(|_| StorageError::CanonicalEncoding)?;
        atomic_write_private(destination, &encoded, MAX_BACKUP_BYTES)
    }

    /// Authenticates and validates the complete backup before creating any
    /// destination state. Installation happens through a sibling staging
    /// directory and a single rename; an existing wallet is never replaced.
    pub fn import_backup(
        destination: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
        backup_password: &str,
        wallet_password: &str,
        expected_identity: &NetworkIdentity,
        kdf: KdfParameters,
    ) -> Result<Self, StorageError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StorageError::AlreadyExists);
        }
        let encoded = read_bounded_with_limit(backup_path.as_ref(), MAX_BACKUP_BYTES)?;
        let container: BackupContainer =
            serde_json::from_slice(&encoded).map_err(|_| StorageError::InvalidBackup)?;
        if container.magic != BACKUP_MAGIC || container.format_version != BACKUP_FORMAT_VERSION {
            return Err(StorageError::UnsupportedBackupVersion);
        }
        if &container.identity != expected_identity {
            return Err(StorageError::IdentityMismatch);
        }
        let context = backup_context(
            container.created_unix_seconds,
            container.wallet_id,
            &container.identity,
        );
        let plaintext =
            open(&container.envelope, backup_password, &context).map_err(StorageError::Crypto)?;
        let mut payload: BackupPayload =
            serde_json::from_slice(&plaintext).map_err(|_| StorageError::InvalidBackup)?;
        if payload.payload_version != BACKUP_FORMAT_VERSION
            || payload.state.wallet_id != container.wallet_id
            || payload.state.identity != container.identity
            || payload.state.identity != *expected_identity
        {
            return Err(StorageError::IdentityMismatch);
        }
        payload
            .state
            .migrate_transaction_exposure()
            .map_err(StorageError::Domain)?;
        payload.state.validate().map_err(StorageError::Domain)?;
        if let Some(plan) = &payload.rescan_plan {
            if plan.wallet_id != payload.state.wallet_id || plan.identity != payload.state.identity
            {
                return Err(StorageError::InvalidBackup);
            }
        }
        let file_name = destination.file_name().ok_or(StorageError::InvalidBackup)?;
        let parent = destination.parent().ok_or(StorageError::InvalidBackup)?;
        let staging = parent.join(format!(".{}.backup-import", file_name.to_string_lossy()));
        if staging.exists() {
            return Err(StorageError::IncompleteGeneration);
        }
        let staged = match WalletDirectory::create(&staging, &payload.state, wallet_password, kdf) {
            Ok(staged) => staged,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        let result = (|| {
            if let Some(plan) = &payload.rescan_plan {
                staged.save_rescan_plan(&payload.state, plan, wallet_password, kdf)?;
            }
            drop(staged);
            fs::rename(&staging, destination).map_err(StorageError::Io)?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        WalletDirectory::open(destination)
    }

    /// Conservative, idempotent cleanup. It only considers complete named
    /// generations after reading the authoritative active pointer; callers
    /// provide generations referenced by a durable nonterminal plan.
    pub fn cleanup_superseded_generations(&self, protected: &[u64]) -> Result<(), StorageError> {
        let active = self.active_generation()?;
        let mut generations = Vec::new();
        for entry in fs::read_dir(self.root.join(GENERATIONS_DIR)).map_err(StorageError::Io)? {
            let entry = entry.map_err(StorageError::Io)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(StorageError::InvalidActiveGeneration)?;
            if name.starts_with('.') {
                continue;
            }
            generations.push(parse_generation(name)?);
        }
        generations.sort_unstable();
        if !generations.contains(&active) {
            return Err(StorageError::GenerationConflict);
        }
        let mut retained = std::collections::BTreeSet::from([active]);
        retained.extend(protected.iter().copied());
        retained.extend(
            generations
                .iter()
                .copied()
                .filter(|generation| *generation < active)
                .rev()
                .take(RETAIN_SUPERSEDED_GENERATIONS),
        );
        for generation in generations {
            if !retained.contains(&generation) {
                let path = self
                    .root
                    .join(GENERATIONS_DIR)
                    .join(generation_name(generation));
                if path.exists() {
                    fs::remove_dir_all(path).map_err(StorageError::Io)?;
                    sync_directory(&self.root.join(GENERATIONS_DIR))?;
                }
            }
        }
        Ok(())
    }

    fn publish_initial(
        &self,
        state: &WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<(), StorageError> {
        self.write_generation(state, password, kdf)?;
        self.write_authenticator(password, &WalletMetadata::from_state(state), kdf)?;
        self.publish_pointer_and_metadata(state)
    }

    fn authenticate_password(
        &self,
        password: &str,
        metadata: &WalletMetadata,
    ) -> Result<bool, StorageError> {
        let path = self.root.join(AUTHENTICATION_FILE);
        if !path.exists() {
            return Ok(false);
        }
        let encoded = read_bounded(&path).map_err(|_| StorageError::AuthenticationDataCorrupt)?;
        let envelope = decode(&encoded).map_err(|_| StorageError::AuthenticationDataCorrupt)?;
        let plaintext = match open(
            &envelope,
            password,
            &authentication_context(metadata.wallet_id, &metadata.identity),
        ) {
            Ok(plaintext) => plaintext,
            Err(CryptoError::AuthenticationFailed) => return Err(StorageError::InvalidPassword),
            Err(_) => return Err(StorageError::AuthenticationDataCorrupt),
        };
        if plaintext.as_slice() != AUTHENTICATION_PLAINTEXT {
            return Err(StorageError::AuthenticationDataCorrupt);
        }
        Ok(true)
    }

    fn write_authenticator(
        &self,
        password: &str,
        metadata: &WalletMetadata,
        kdf: KdfParameters,
    ) -> Result<(), StorageError> {
        let path = self.root.join(AUTHENTICATION_FILE);
        if path.exists() {
            return Ok(());
        }
        let envelope = seal(
            AUTHENTICATION_PLAINTEXT,
            password,
            &authentication_context(metadata.wallet_id, &metadata.identity),
            kdf,
        )
        .map_err(StorageError::Crypto)?;
        let encoded = encode(&envelope).map_err(StorageError::Crypto)?;
        atomic_write_private(&path, &encoded, MAX_STATE_BYTES)
    }

    fn write_generation(
        &self,
        state: &WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<(), StorageError> {
        let generation = generation_name(state.generation);
        let generations_dir = self.root.join(GENERATIONS_DIR);
        require_directory(&generations_dir)?;
        let final_dir = generations_dir.join(&generation);
        if final_dir.exists() {
            return Err(StorageError::GenerationAlreadyExists);
        }
        let temporary_dir =
            generations_dir.join(format!(".{generation}.{}.staging", Uuid::new_v4()));
        create_private_directory(&temporary_dir)?;
        let result = (|| {
            let plaintext =
                serde_json::to_vec(state).map_err(|_| StorageError::CanonicalEncoding)?;
            let context = state_context(state.wallet_id, &state.identity, state.generation);
            let envelope =
                seal(&plaintext, password, &context, kdf).map_err(StorageError::Crypto)?;
            let encoded = encode(&envelope).map_err(StorageError::Crypto)?;
            atomic_write(&temporary_dir.join(STATE_FILE), &encoded)?;
            sync_directory(&temporary_dir)?;
            fs::rename(&temporary_dir, &final_dir).map_err(StorageError::Io)?;
            sync_directory(&generations_dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary_dir);
        }
        result
    }

    /// Remove only the exact adjacent generation left complete but
    /// unpublished by a crash before the active pointer changed.
    fn remove_unpublished_generation(&self, generation: u64) -> Result<(), StorageError> {
        let generations = self.root.join(GENERATIONS_DIR);
        let path = generations.join(generation_name(generation));
        if !path.exists() {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(&path).map_err(StorageError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StorageError::UnsafePath);
        }
        let state_path = path.join(STATE_FILE);
        require_regular_file(&state_path)?;
        let encoded = read_bounded(&state_path)?;
        decode(&encoded).map_err(|_| StorageError::AuthenticatedPayloadCorrupt)?;
        fs::remove_dir_all(&path).map_err(StorageError::Io)?;
        sync_directory(&generations)
    }

    fn publish_pointer_and_metadata(&self, state: &WalletState) -> Result<(), StorageError> {
        let generation = generation_name(state.generation);
        atomic_write(&self.root.join(ACTIVE_FILE), generation.as_bytes())?;
        let metadata = serde_json::to_vec(&WalletMetadata::from_state(state))
            .map_err(|_| StorageError::CanonicalEncoding)?;
        atomic_write(&self.root.join(METADATA_FILE), &metadata)?;
        sync_directory(&self.root)
    }

    fn active_generation(&self) -> Result<u64, StorageError> {
        let bytes = read_bounded(&self.root.join(ACTIVE_FILE))?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| StorageError::InvalidActiveGeneration)?;
        parse_generation(text)
    }

    fn load_generation(
        &self,
        generation: u64,
        password: &str,
        metadata: &WalletMetadata,
        password_authenticated: bool,
    ) -> Result<WalletState, StorageError> {
        let encoded = read_bounded(
            &self
                .root
                .join(GENERATIONS_DIR)
                .join(generation_name(generation))
                .join(STATE_FILE),
        )?;
        let envelope = decode(&encoded).map_err(|_| StorageError::AuthenticatedPayloadCorrupt)?;
        let context = state_context(metadata.wallet_id, &metadata.identity, generation);
        let plaintext = open(&envelope, password, &context).map_err(|error| {
            if password_authenticated {
                StorageError::AuthenticatedPayloadCorrupt
            } else if matches!(error, CryptoError::AuthenticationFailed) {
                StorageError::InvalidPassword
            } else {
                StorageError::AuthenticatedPayloadCorrupt
            }
        })?;
        let mut state: WalletState = serde_json::from_slice(&plaintext)
            .map_err(|_| StorageError::AuthenticatedPayloadCorrupt)?;
        state
            .migrate_transaction_exposure()
            .map_err(StorageError::Domain)?;
        Ok(state)
    }
}

pub fn default_node_configuration(identity: NetworkIdentity) -> NodeConfiguration {
    NodeConfiguration {
        endpoint_url: "https://example.invalid/dom-rpc".into(),
        expected_identity: identity,
        source_identity: "configured-dom-node".into(),
        api_compatibility_version: 1,
        connect_timeout_ms: 5_000,
        request_timeout_ms: 10_000,
        poll_interval_ms: 5_000,
        retry_ceiling: 6,
        max_backoff_ms: 60_000,
        stable_success_threshold: 3,
        tls_required: true,
        credential_reference: None,
    }
}

fn generation_name(generation: u64) -> String {
    format!("generation-{generation:020}")
}

fn parse_generation(value: &str) -> Result<u64, StorageError> {
    value
        .strip_prefix("generation-")
        .ok_or(StorageError::InvalidActiveGeneration)?
        .parse()
        .map_err(|_| StorageError::InvalidActiveGeneration)
}

fn state_context(wallet_id: Uuid, identity: &NetworkIdentity, generation: u64) -> Vec<u8> {
    let mut context = Vec::with_capacity(16 + 32 + 32 + 8 + 24);
    context.extend_from_slice(b"DOM-WALLET-V3-STATE-V1");
    context.extend_from_slice(wallet_id.as_bytes());
    context.extend_from_slice(&identity.chain_id);
    context.extend_from_slice(&identity.genesis_id);
    context.extend_from_slice(&generation.to_le_bytes());
    context
}

fn authentication_context(wallet_id: Uuid, identity: &NetworkIdentity) -> Vec<u8> {
    let mut context = Vec::with_capacity(16 + 32 + 32 + 32);
    context.extend_from_slice(b"DOM-WALLET-V3-AUTH-V1");
    context.extend_from_slice(wallet_id.as_bytes());
    context.extend_from_slice(&identity.chain_id);
    context.extend_from_slice(&identity.genesis_id);
    context
}

fn rescan_context(wallet_id: Uuid, identity: &NetworkIdentity) -> Vec<u8> {
    let mut context = Vec::with_capacity(16 + 32 + 32 + 24);
    context.extend_from_slice(b"DOM-WALLET-V3-RESCAN-V1");
    context.extend_from_slice(wallet_id.as_bytes());
    context.extend_from_slice(&identity.chain_id);
    context.extend_from_slice(&identity.genesis_id);
    context
}

fn backup_context(
    created_unix_seconds: u64,
    wallet_id: Uuid,
    identity: &NetworkIdentity,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(8 + 2 + 8 + 16 + 32 + 32);
    context.extend_from_slice(&BACKUP_MAGIC);
    context.extend_from_slice(&BACKUP_FORMAT_VERSION.to_le_bytes());
    context.extend_from_slice(&created_unix_seconds.to_le_bytes());
    context.extend_from_slice(wallet_id.as_bytes());
    context.extend_from_slice(&identity.chain_id);
    context.extend_from_slice(&identity.genesis_id);
    context
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StorageError> {
    read_bounded_with_limit(path, MAX_STATE_BYTES)
}

fn acquire_writer_lock(root: &Path) -> Result<Arc<File>, StorageError> {
    let lock_path = root.join(WRITER_LOCK_FILE);
    if lock_path
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
        .unwrap_or(false)
    {
        return Err(StorageError::UnsafePath);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path).map_err(StorageError::Io)?;
    match FileExt::try_lock_exclusive(&lock) {
        Ok(()) => Ok(Arc::new(lock)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(StorageError::WriterActive)
        }
        Err(error) => Err(StorageError::Io(error)),
    }
}

fn require_regular_file(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(StorageError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::UnsafePath);
    }
    Ok(())
}

fn read_bounded_with_limit(path: &Path, max_bytes: usize) -> Result<Vec<u8>, StorageError> {
    let metadata = fs::metadata(path).map_err(StorageError::Io)?;
    if metadata.len() == 0 || metadata.len() as usize > max_bytes {
        return Err(StorageError::FileSizeOutOfBounds);
    }
    fs::read(path).map_err(StorageError::Io)
}

fn atomic_write_private(path: &Path, bytes: &[u8], max_bytes: usize) -> Result<(), StorageError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(StorageError::FileSizeOutOfBounds);
    }
    validate_atomic_destination(path)?;
    let temporary = unique_temporary_sibling(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(StorageError::Io)?;
    let result = (|| {
        restrict_private_file(&file)?;
        file.write_all(bytes).map_err(StorageError::Io)?;
        file.sync_all().map_err(StorageError::Io)?;
        drop(file);
        fs::rename(&temporary, path).map_err(StorageError::Io)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    atomic_write_private(path, bytes, MAX_STATE_BYTES)
}

fn validate_atomic_destination(path: &Path) -> Result<(), StorageError> {
    let parent = path.parent().ok_or(StorageError::UnsafePath)?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    require_directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(StorageError::UnsafePath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageError::Io(error)),
    }
}

fn unique_temporary_sibling(path: &Path) -> Result<PathBuf, StorageError> {
    let mut name = path
        .file_name()
        .ok_or(StorageError::UnsafePath)?
        .to_os_string();
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    Ok(path.with_file_name(name))
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        File::open(path)
            .map_err(StorageError::Io)?
            .sync_all()
            .map_err(StorageError::Io)?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(StorageError::Io)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path).map_err(StorageError::Io)?;
    restrict_private_directory(path)
}

fn require_directory(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(StorageError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::UnsafePath);
    }
    Ok(())
}

fn restrict_private_directory(path: &Path) -> Result<(), StorageError> {
    require_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(StorageError::Io)?;
    }
    Ok(())
}

fn restrict_private_file(file: &File) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(StorageError::Io)?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("wallet directory already exists")]
    AlreadyExists,
    #[error("wallet directory was not found")]
    NotFound,
    #[error("wallet path is unsafe")]
    UnsafePath,
    #[error("wallet is already open by another writer")]
    WriterActive,
    #[error("wallet password is invalid")]
    InvalidPassword,
    #[error("wallet authentication data is corrupt")]
    AuthenticationDataCorrupt,
    #[error("authenticated wallet payload is corrupt")]
    AuthenticatedPayloadCorrupt,
    #[error("invalid wallet metadata")]
    InvalidMetadata,
    #[error("unsupported wallet version")]
    UnsupportedVersion,
    #[error("invalid active generation pointer")]
    InvalidActiveGeneration,
    #[error("generation conflict")]
    GenerationConflict,
    #[error("expected generation conflict; current generation is {current}")]
    ExpectedGenerationConflict { current: u64 },
    #[error("wallet identity or network identity mismatch")]
    IdentityMismatch,
    #[error("generation already exists")]
    GenerationAlreadyExists,
    #[error("incomplete generation is present")]
    IncompleteGeneration,
    #[error("generation overflow")]
    GenerationOverflow,
    #[error("bounded file size validation failed")]
    FileSizeOutOfBounds,
    #[error("backup destination already exists")]
    BackupDestinationExists,
    #[error("backup data is invalid")]
    InvalidBackup,
    #[error("backup format is unsupported")]
    UnsupportedBackupVersion,
    #[error("system clock is unavailable")]
    Clock,
    #[error("canonical state encoding failed")]
    CanonicalEncoding,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Domain(#[from] dom_wallet_domain::DomainError),
    #[error("filesystem error: {0}")]
    Io(std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_wallet_domain::{
        cancellation_decision, BroadcastExposure, CancellationDecision, LocalTransactionIntent,
        Network, NetworkIdentity, OutputRecord, OutputState, TransactionLifecycle, TransactionRole,
        WalletState,
    };
    use uuid::Uuid;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HistoricalSchemaFixture {
        fixture_version: u16,
        releases: Vec<String>,
        metadata_version: u16,
        schema_version: u16,
        secret_profile_version: u16,
        migration_required: bool,
    }

    fn identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [4; 32],
            genesis_id: [5; 32],
        }
    }

    #[cfg(unix)]
    fn unix_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn create_reopen_and_wrong_password_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &state,
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let reopened = wallet.load("correct").unwrap();
        assert_eq!(reopened.wallet_id, state.wallet_id);
        assert!(matches!(
            wallet.load("wrong"),
            Err(StorageError::InvalidPassword)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn created_and_committed_wallet_tree_is_owner_only() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();

        let generations = root.join(GENERATIONS_DIR);
        let generation_zero = generations.join(generation_name(0));
        for directory in [&root, &generations, &generation_zero] {
            assert_eq!(unix_mode(directory), 0o700, "{directory:?}");
        }
        for file in [
            root.join(METADATA_FILE),
            root.join(ACTIVE_FILE),
            root.join(AUTHENTICATION_FILE),
            root.join(WRITER_LOCK_FILE),
            generation_zero.join(STATE_FILE),
        ] {
            assert_eq!(unix_mode(&file), 0o600, "{file:?}");
        }

        let next = wallet.load("correct").unwrap();
        wallet
            .commit(0, next, "correct", KdfParameters::TEST)
            .unwrap();
        let generation_one = generations.join(generation_name(1));
        assert_eq!(unix_mode(&generation_one), 0o700);
        assert_eq!(unix_mode(&generation_one.join(STATE_FILE)), 0o600);
        assert_eq!(unix_mode(&root.join(METADATA_FILE)), 0o600);
        assert_eq!(unix_mode(&root.join(ACTIVE_FILE)), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn private_creation_and_atomic_writes_reject_symlink_paths() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        let linked_directory = temp.path().join("linked-directory");
        symlink(outside.path(), &linked_directory).unwrap();
        assert!(matches!(
            restrict_private_directory(&linked_directory),
            Err(StorageError::UnsafePath)
        ));
        assert!(matches!(
            WalletDirectory::create(
                linked_directory.join("wallet"),
                &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
                "correct",
                KdfParameters::TEST,
            ),
            Err(StorageError::UnsafePath)
        ));
        assert!(!outside.path().join("wallet").exists());

        let target = outside.path().join("target");
        fs::write(&target, b"preserved").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let linked_file = temp.path().join("linked-file");
        symlink(&target, &linked_file).unwrap();
        assert!(matches!(
            atomic_write(&linked_file, b"replacement"),
            Err(StorageError::UnsafePath)
        ));
        assert_eq!(fs::read(&target).unwrap(), b"preserved");
    }

    #[test]
    fn regression_a1_real_encrypted_fixtures_separate_auth_storage_and_corruption_errors() {
        let temp = tempfile::tempdir().unwrap();
        let create = |name: &str| {
            let state =
                WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
            let root = temp.path().join(name);
            let wallet =
                WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();
            (root, wallet)
        };

        let (_wrong_root, wrong) = create("wrong");
        assert!(matches!(
            wrong.load("incorrect"),
            Err(StorageError::InvalidPassword)
        ));

        let (auth_root, auth_corrupt) = create("auth-corrupt");
        fs::write(auth_root.join(AUTHENTICATION_FILE), b"not-an-envelope").unwrap();
        assert!(matches!(
            auth_corrupt.load("correct"),
            Err(StorageError::AuthenticationDataCorrupt)
        ));

        let (payload_root, payload_corrupt) = create("payload-corrupt");
        fs::write(
            payload_root
                .join(GENERATIONS_DIR)
                .join(generation_name(0))
                .join(STATE_FILE),
            b"not-an-envelope",
        )
        .unwrap();
        assert!(matches!(
            payload_corrupt.load("correct"),
            Err(StorageError::AuthenticatedPayloadCorrupt)
        ));

        let (metadata_root, metadata_corrupt) = create("metadata-corrupt");
        fs::write(metadata_root.join(METADATA_FILE), b"not-json").unwrap();
        assert!(matches!(
            metadata_corrupt.load("correct"),
            Err(StorageError::InvalidMetadata)
        ));

        assert!(matches!(
            WalletDirectory::open(temp.path().join("missing")),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn regression_m9_interrupted_creation_can_resume_or_authenticated_abort_without_consuming_name()
    {
        let temp = tempfile::tempdir().unwrap();
        let staged_state = || {
            let mut state =
                WalletState::new(identity(), [9; 32], default_node_configuration(identity()));
            state.recovery = Some(dom_wallet_domain::RecoveryMetadata {
                scheme: RECOVERY_SCHEME_BIP39_256_V1.into(),
                phrase_confirmed: false,
            });
            state
        };

        let source = temp.path().join("source");
        let wallet =
            WalletDirectory::create(&source, &staged_state(), "correct", KdfParameters::TEST)
                .unwrap();
        drop(wallet);
        let destination = temp.path().join("wallet");
        fs::rename(&source, temp.path().join(".wallet.create-staging")).unwrap();
        assert!(!destination.exists());
        let (resumed, state) = WalletDirectory::resume_create(&destination, "correct").unwrap();
        assert!(!state.recovery.unwrap().phrase_confirmed);
        assert_eq!(resumed.root(), destination);
        drop(resumed);

        let source = temp.path().join("abort-source");
        let wallet =
            WalletDirectory::create(&source, &staged_state(), "correct", KdfParameters::TEST)
                .unwrap();
        drop(wallet);
        let aborted_destination = temp.path().join("aborted");
        let stage = temp.path().join(".aborted.create-staging");
        fs::rename(&source, &stage).unwrap();
        assert!(matches!(
            WalletDirectory::abort_create(&aborted_destination, "wrong"),
            Err(StorageError::InvalidPassword)
        ));
        assert!(stage.exists());
        WalletDirectory::abort_create(&aborted_destination, "correct").unwrap();
        assert!(!stage.exists());
        assert!(!aborted_destination.exists());
    }

    #[test]
    fn regression_c2_submitting_restart_and_post_acceptance_crash_retain_reservations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("wallet");
        let mut state =
            WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let transaction_id = Uuid::new_v4();
        let output_id = Uuid::new_v4();
        let finalized_transaction_bytes = vec![0x44; 256];
        state.outputs.push(OutputRecord {
            id: output_id,
            account_id: state.default_account.id,
            commitment: Some([3; 33]),
            value: 10,
            state: OutputState::PendingOutgoing,
            discovered_height: 1,
            reserved_by: Some(transaction_id),
        });
        state.transactions.push(LocalTransactionIntent {
            id: transaction_id,
            created_at_height: 0,
            created_at_unix_seconds: 0,
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: vec![4; 33],
            lifecycle: TransactionLifecycle::Submitting,
            submitted: false,
            exposure: BroadcastExposure::SubmissionStarted,
            slate_id: Some(Uuid::new_v4()),
            role: Some(TransactionRole::Sender),
            amount: 8,
            fee: 2,
            reserved_output_ids: vec![output_id],
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: finalized_transaction_bytes.clone(),
            transaction_hash: Some([5; 32]),
            attempt_count: 1,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height: 100,
        });
        let wallet =
            WalletDirectory::create(&root, &state, "correct-password", KdfParameters::TEST)
                .unwrap();
        drop(wallet);

        let restarted = WalletDirectory::open(&root)
            .unwrap()
            .load("correct-password")
            .unwrap();
        let transaction = &restarted.transactions[0];
        assert_eq!(transaction.lifecycle, TransactionLifecycle::Submitting);
        assert_eq!(transaction.exposure, BroadcastExposure::SubmissionStarted);
        assert_eq!(
            transaction.finalized_transaction_bytes, finalized_transaction_bytes,
            "exact finalized bytes must survive an encrypted storage restart"
        );
        assert_eq!(
            cancellation_decision(transaction.exposure),
            CancellationDecision::RequireReconciliation
        );
        assert_eq!(restarted.outputs[0].reserved_by, Some(transaction_id));

        let mut accepted_but_not_committed = transaction.clone();
        accepted_but_not_committed.submitted = true;
        accepted_but_not_committed.lifecycle = TransactionLifecycle::Submitted;
        assert_eq!(
            restarted.transactions[0].lifecycle,
            TransactionLifecycle::Submitting,
            "a crash immediately after node acceptance reloads the durable pre-I/O state"
        );
        assert_eq!(
            cancellation_decision(restarted.transactions[0].exposure),
            CancellationDecision::RequireReconciliation
        );
    }

    #[test]
    fn regression_m9_generation_crash_between_write_and_activation_recovers_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct-password", KdfParameters::TEST)
                .unwrap();
        let mut next = wallet.load("correct-password").unwrap();
        next.allocation_floor = 7;
        next.non_reuse_floor = 7;
        let staged = wallet
            .stage_generation(0, next, "correct-password", KdfParameters::TEST)
            .unwrap();
        drop(wallet);

        let before_activation = WalletDirectory::open(&root)
            .unwrap()
            .load("correct-password")
            .unwrap();
        assert_eq!(before_activation.generation, 0);
        assert_eq!(before_activation.allocation_floor, 0);
        drop(before_activation);

        atomic_write(&root.join(ACTIVE_FILE), generation_name(1).as_bytes()).unwrap();
        let after_pointer_crash = WalletDirectory::open(&root)
            .unwrap()
            .load("correct-password")
            .unwrap();
        assert_eq!(after_pointer_crash, staged);
        let repaired: WalletMetadata =
            serde_json::from_slice(&fs::read(root.join(METADATA_FILE)).unwrap()).unwrap();
        assert_eq!(repaired.active_generation, 1);
    }

    #[test]
    fn unpublished_generation_and_stale_temporary_files_are_restart_safe() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct-password", KdfParameters::TEST)
                .unwrap();

        let mut abandoned = wallet.load("correct-password").unwrap();
        abandoned.allocation_floor = 7;
        abandoned.non_reuse_floor = 7;
        wallet
            .stage_generation(0, abandoned, "correct-password", KdfParameters::TEST)
            .unwrap();
        drop(wallet);

        let wallet = WalletDirectory::open(&root).unwrap();
        let mut replacement = wallet.load("correct-password").unwrap();
        replacement.allocation_floor = 8;
        replacement.non_reuse_floor = 8;
        let committed = wallet
            .commit(0, replacement, "correct-password", KdfParameters::TEST)
            .unwrap();
        assert_eq!(committed.allocation_floor, 8);
        assert_eq!(wallet.load("correct-password").unwrap(), committed);

        fs::remove_file(root.join(AUTHENTICATION_FILE)).unwrap();
        fs::write(root.join("authentication.tmp"), b"crash residue").unwrap();
        drop(wallet);
        let reopened = WalletDirectory::open(&root).unwrap();
        assert_eq!(
            reopened.load("correct-password").unwrap().allocation_floor,
            8
        );
        assert!(root.join(AUTHENTICATION_FILE).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn regression_a7_internal_wallet_symlinks_never_escape_the_managed_directory() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = temp.path().join("wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct-password", KdfParameters::TEST)
                .unwrap();
        drop(wallet);

        let metadata = root.join(METADATA_FILE);
        let outside_metadata = outside.path().join("metadata.json");
        fs::rename(&metadata, &outside_metadata).unwrap();
        std::os::unix::fs::symlink(&outside_metadata, &metadata).unwrap();
        assert!(matches!(
            WalletDirectory::inspect_structure(&root),
            Err(StorageError::UnsafePath)
        ));
        fs::remove_file(&metadata).unwrap();
        fs::rename(&outside_metadata, &metadata).unwrap();

        let generations = root.join(GENERATIONS_DIR);
        let outside_generations = outside.path().join("generations");
        fs::rename(&generations, &outside_generations).unwrap();
        std::os::unix::fs::symlink(&outside_generations, &generations).unwrap();
        assert!(matches!(
            WalletDirectory::open(&root),
            Err(StorageError::UnsafePath)
        ));
    }

    #[test]
    fn commits_are_old_or_new_and_generation_checked() {
        let temp = tempfile::tempdir().unwrap();
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &state,
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let mut changed = wallet.load("correct").unwrap();
        changed.allocate().unwrap();
        let committed = wallet
            .commit(0, changed, "correct", KdfParameters::TEST)
            .unwrap();
        assert_eq!(committed.generation, 1);
        assert_eq!(wallet.load("correct").unwrap().generation, 1);
        assert!(matches!(
            wallet.commit(0, committed, "correct", KdfParameters::TEST),
            Err(StorageError::ExpectedGenerationConflict { current: 1 })
        ));
    }

    #[test]
    fn process_lock_rejects_an_active_writer_and_reuses_a_stale_lock_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();
        let shared_owner = wallet.clone();

        assert!(matches!(
            WalletDirectory::open(&root),
            Err(StorageError::WriterActive)
        ));
        drop(wallet);
        assert!(matches!(
            WalletDirectory::open(&root),
            Err(StorageError::WriterActive)
        ));
        drop(shared_owner);

        let reopened = WalletDirectory::open(&root).unwrap();
        assert_eq!(reopened.load("correct").unwrap().wallet_id, state.wallet_id);
        assert!(root.join(WRITER_LOCK_FILE).is_file());
    }

    #[test]
    fn v01_schema_fixture_opens_without_mutating_wallet_data() {
        let fixture: HistoricalSchemaFixture =
            serde_json::from_str(include_str!("../fixtures/v0.1.x-schema-v1.json")).unwrap();
        assert_eq!(fixture.fixture_version, 1);
        assert_eq!(
            fixture
                .releases
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5"]
        );
        assert_eq!(fixture.metadata_version, 1);
        assert_eq!(fixture.schema_version, MODEL_VERSION);
        assert_eq!(fixture.secret_profile_version, SECRET_PROFILE_VERSION);
        assert!(!fixture.migration_required);

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("v0.1.x-wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();
        let metadata_before = fs::read(root.join(METADATA_FILE)).unwrap();
        let generation_path = root
            .join(GENERATIONS_DIR)
            .join(generation_name(0))
            .join(STATE_FILE);
        let generation_before = fs::read(&generation_path).unwrap();
        drop(wallet);

        let reopened = WalletDirectory::open(&root).unwrap();
        let loaded = reopened.load("correct").unwrap();
        assert_eq!(loaded, state);
        drop(reopened);
        assert_eq!(fs::read(root.join(METADATA_FILE)).unwrap(), metadata_before);
        assert_eq!(fs::read(generation_path).unwrap(), generation_before);
    }

    #[test]
    fn unknown_schema_fails_without_overwriting_original_data() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("unknown-schema-wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();
        let mut metadata: WalletMetadata =
            serde_json::from_slice(&fs::read(root.join(METADATA_FILE)).unwrap()).unwrap();
        metadata.schema_version = u16::MAX;
        let unsupported = serde_json::to_vec(&metadata).unwrap();
        atomic_write(&root.join(METADATA_FILE), &unsupported).unwrap();
        let generation_path = root
            .join(GENERATIONS_DIR)
            .join(generation_name(0))
            .join(STATE_FILE);
        let generation_before = fs::read(&generation_path).unwrap();
        drop(wallet);

        assert!(matches!(
            WalletDirectory::open(&root),
            Err(StorageError::UnsupportedVersion)
        ));
        assert_eq!(fs::read(root.join(METADATA_FILE)).unwrap(), unsupported);
        assert_eq!(fs::read(generation_path).unwrap(), generation_before);
    }

    #[test]
    fn mixed_generation_pointer_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &state,
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        fs::write(
            wallet.root().join(ACTIVE_FILE),
            b"generation-00000000000000000009",
        )
        .unwrap();
        assert!(wallet.load("correct").is_err());
    }

    #[test]
    fn authenticated_adjacent_generation_repairs_interrupted_publication() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let mut changed = wallet.load("correct").unwrap();
        changed.allocate().unwrap();
        let staged = wallet
            .stage_generation(0, changed, "correct", KdfParameters::TEST)
            .unwrap();
        atomic_write(
            &wallet.root().join(ACTIVE_FILE),
            generation_name(staged.generation).as_bytes(),
        )
        .unwrap();

        assert!(matches!(
            wallet.load("wrong"),
            Err(StorageError::InvalidPassword)
        ));
        assert_eq!(wallet.metadata().unwrap().active_generation, 0);

        let reopened = wallet.load("correct").unwrap();
        assert_eq!(reopened.generation, 1);
        assert_eq!(wallet.metadata().unwrap().active_generation, 1);
        assert_eq!(wallet.load("correct").unwrap(), reopened);
    }

    #[test]
    fn cleanup_retains_active_and_one_predecessor_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let first = wallet.load("correct").unwrap();
        let second = wallet
            .commit(0, first, "correct", KdfParameters::TEST)
            .unwrap();
        let _third = wallet
            .commit(1, second, "correct", KdfParameters::TEST)
            .unwrap();
        wallet.cleanup_superseded_generations(&[]).unwrap();
        wallet.cleanup_superseded_generations(&[]).unwrap();
        assert!(!wallet
            .root()
            .join(GENERATIONS_DIR)
            .join(generation_name(0))
            .exists());
        assert!(wallet
            .root()
            .join(GENERATIONS_DIR)
            .join(generation_name(1))
            .exists());
        assert!(wallet
            .root()
            .join(GENERATIONS_DIR)
            .join(generation_name(2))
            .exists());
        assert_eq!(wallet.load("correct").unwrap().generation, 2);
    }

    #[test]
    fn cleanup_ambiguous_metadata_fails_closed_without_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let active = wallet.root().join(GENERATIONS_DIR).join(generation_name(0));
        fs::create_dir(
            wallet
                .root()
                .join(GENERATIONS_DIR)
                .join("generation-not-a-number"),
        )
        .unwrap();
        assert!(wallet.cleanup_superseded_generations(&[]).is_err());
        assert!(active.exists());
        assert_eq!(wallet.load("correct").unwrap().generation, 0);
    }

    #[test]
    fn backup_round_trip_authenticates_header_ciphertext_and_identity_before_install() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "wallet-password",
            KdfParameters::TEST,
        )
        .unwrap();
        let backup = temp.path().join("wallet.dombackup");
        wallet
            .export_backup(
                "wallet-password",
                "backup-password",
                KdfParameters::TEST,
                &backup,
            )
            .unwrap();
        let imported = WalletDirectory::import_backup(
            temp.path().join("restored"),
            &backup,
            "backup-password",
            "new-wallet-password",
            &identity(),
            KdfParameters::TEST,
        )
        .unwrap();
        assert_eq!(
            imported.load("new-wallet-password").unwrap().wallet_id,
            wallet.load("wallet-password").unwrap().wallet_id
        );

        assert!(matches!(
            WalletDirectory::import_backup(
                temp.path().join("wrong-password"),
                &backup,
                "wrong-password",
                "new-wallet-password",
                &identity(),
                KdfParameters::TEST,
            ),
            Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
        ));
        let mut wrong = identity();
        wrong.genesis_id[0] ^= 1;
        assert!(matches!(
            WalletDirectory::import_backup(
                temp.path().join("wrong-identity"),
                &backup,
                "backup-password",
                "new-wallet-password",
                &wrong,
                KdfParameters::TEST,
            ),
            Err(StorageError::IdentityMismatch)
        ));
        let mut corrupted = fs::read(&backup).unwrap();
        let last = corrupted.len() - 2;
        corrupted[last] ^= 1;
        let damaged = temp.path().join("damaged.dombackup");
        fs::write(&damaged, corrupted).unwrap();
        assert!(WalletDirectory::import_backup(
            temp.path().join("damaged"),
            &damaged,
            "backup-password",
            "new-wallet-password",
            &identity(),
            KdfParameters::TEST,
        )
        .is_err());
        assert!(!temp.path().join("damaged").exists());
    }
}

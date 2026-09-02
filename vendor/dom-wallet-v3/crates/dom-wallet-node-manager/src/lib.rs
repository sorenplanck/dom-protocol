#![forbid(unsafe_code)]

//! Wallet-owned lifecycle manager for the independently signed DOM node.
//!
//! The sidecar remains an explicit, session-only experiment. Construction,
//! deserialization and environment variables cannot enable it.

pub mod sidecar_keys;

use dom_sidecar::{
    verify_manifest, verify_minisign, verify_promotion_identity, verify_release, RunningIdentity,
    SidecarError, SidecarManifest, SidecarStore,
};
use dom_wallet_updater::{
    persist_node_runtime_state, validate_download, validate_node_manifest, NodeCompatibility,
    NodeDecision, NodeManifest, NodeRuntimeLayout, NodeRuntimeState, UpdateError,
};
use rand::RngCore;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

pub const EXPERIMENTAL_ENABLE_CONFIRMATION: &str =
    "ENABLE EXPERIMENTAL DOM SIDECAR FOR THIS SESSION";

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SidecarLifecycle {
    Disabled,
    Enabled,
    Starting,
    Ready,
    Stopping,
    Promoting,
    RollingBack,
    RolledBack,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarStatus {
    pub enabled_for_session: bool,
    pub lifecycle: SidecarLifecycle,
    pub pid: Option<u32>,
    pub active_revision: Option<String>,
    pub previous_revision: Option<String>,
    pub identity: Option<NodeIdentity>,
    pub sanitized_error: Option<String>,
}

/// Opaque result of authenticating and evaluating `node-latest.json`.
///
/// Callers obtain this before downloading a node. Its private field prevents
/// construction from untrusted deserialized data.
pub struct ValidatedNodeFeed {
    manifest: NodeManifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NodeReleaseMetadata {
    pub node_version: String,
    pub node_revision: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    pub node_version: String,
    pub node_revision: String,
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub rpc_protocol_version: u32,
    pub p2p_protocol_version: u32,
    pub storage_schema_version_supported: u32,
    pub storage_schema_version_on_disk: u32,
    pub height: u64,
}

impl NodeIdentity {
    pub fn promotion_identity(&self) -> RunningIdentity {
        RunningIdentity {
            network: self.network.clone(),
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            storage_schema_version_on_disk: self.storage_schema_version_on_disk,
            rpc_protocol_version: self.rpc_protocol_version,
            p2p_protocol_version: self.p2p_protocol_version,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ManagedNodeConfig {
    pub network: String,
    pub data_directory: PathBuf,
    pub rpc_address: SocketAddr,
    pub p2p_address: SocketAddr,
    pub seed_peers: Vec<SocketAddr>,
}

impl ManagedNodeConfig {
    pub fn validate(&self) -> Result<(), NodeManagerError> {
        if !matches!(self.network.as_str(), "mainnet" | "testnet" | "regtest") {
            return Err(NodeManagerError::InvalidConfiguration);
        }
        if !self.rpc_address.ip().is_loopback() || self.rpc_address.port() == 0 {
            return Err(NodeManagerError::InvalidConfiguration);
        }
        if !self.p2p_address.ip().is_loopback() || self.p2p_address.port() == 0 {
            return Err(NodeManagerError::InvalidConfiguration);
        }
        if self.data_directory.as_os_str().is_empty() {
            return Err(NodeManagerError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum NodeManagerError {
    #[error("experimental sidecar is disabled")]
    Disabled,
    #[error("experimental sidecar activation requires an unlocked local wallet session")]
    WalletLocked,
    #[error("experimental sidecar activation confirmation does not match")]
    ConfirmationMismatch,
    #[error("sidecar runtime directory is not configured")]
    RuntimeNotConfigured,
    #[error("sidecar already has a running process")]
    AlreadyRunning,
    #[error("no authenticated sidecar is active")]
    NoActiveSidecar,
    #[error("sidecar configuration is invalid")]
    InvalidConfiguration,
    #[error("sidecar binary path or permissions are unsafe")]
    UnsafeBinary,
    #[error("Windows runtime ACL setup failed (status {0})")]
    WindowsAclSetupFailed(i32),
    #[error("Windows runtime directory owner is unsafe")]
    WindowsAclOwnerUnsafe,
    #[error("Windows runtime directory grants write access to an untrusted principal")]
    WindowsAclWritablePrincipalUnsafe,
    #[error("Windows runtime ACL validation failed (status {0})")]
    WindowsAclValidationFailed(i32),
    #[error("sidecar process exited before it became ready")]
    StartupFailed,
    #[error("sidecar RPC did not become ready before timeout")]
    StartupTimeout,
    #[error("sidecar RPC identity does not match the promoted revision")]
    IdentityMismatch,
    #[error("sidecar shutdown did not complete cleanly")]
    ShutdownFailed,
    #[error("sidecar trust roots differ")]
    TrustRootMismatch,
    #[error("signed node feed is missing")]
    MissingNodeFeed,
    #[error("signed node feed does not match the sidecar manifest")]
    NodeFeedMismatch,
    #[error("node release is not eligible for node-only promotion")]
    NodeUpdateNotAvailable,
    #[error("node update policy rejected the release: {0}")]
    Update(#[from] UpdateError),
    #[error("sidecar release rejected: {0}")]
    Release(#[from] SidecarError),
    #[error("sidecar I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("sidecar RPC failed")]
    Rpc,
}

#[derive(Debug, Deserialize)]
struct BuildInfoResponse {
    node_version: String,
    node_revision: String,
    rpc_protocol_version: u32,
    p2p_protocol_version: u32,
    storage_schema_version_supported: u32,
}

#[derive(Debug, Deserialize)]
struct NetworkInfoResponse {
    network: String,
    chain_id: String,
    genesis_hash: String,
    storage_schema_version_on_disk: u32,
    height: u64,
}

struct RunningNode {
    child: Child,
    token: String,
    config: ManagedNodeConfig,
    identity: NodeIdentity,
}

pub struct NodeManager {
    enabled_for_session: bool,
    runtime_root: Option<PathBuf>,
    lifecycle: SidecarLifecycle,
    running: Option<RunningNode>,
    previous_revision: Option<String>,
    last_identity: Option<NodeIdentity>,
    sanitized_error: Option<String>,
}

impl Default for NodeManager {
    fn default() -> Self {
        Self {
            enabled_for_session: false,
            runtime_root: None,
            lifecycle: SidecarLifecycle::Disabled,
            running: None,
            previous_revision: None,
            last_identity: None,
            sanitized_error: None,
        }
    }
}

impl NodeManager {
    /// Configure the wallet-owned runtime root. This does not enable sidecars.
    pub fn configure_runtime(
        &mut self,
        runtime_root: impl Into<PathBuf>,
    ) -> Result<(), NodeManagerError> {
        let runtime_root = runtime_root.into();
        let newly_created = !runtime_root.exists();
        if runtime_root.exists()
            && fs::symlink_metadata(&runtime_root)?
                .file_type()
                .is_symlink()
        {
            return Err(NodeManagerError::UnsafeBinary);
        }
        fs::create_dir_all(&runtime_root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        if newly_created {
            secure_new_windows_runtime_root(&runtime_root)?;
        }
        let _ = newly_created;
        validate_runtime_tree(&runtime_root)?;
        self.runtime_root = Some(runtime_root);
        Ok(())
    }

    /// Enable the experiment for this process only.
    ///
    /// The caller must prove that the wallet is currently unlocked. The flag
    /// has no serde representation, no config source and no environment source.
    pub fn enable_for_session(
        &mut self,
        confirmation: &str,
        wallet_is_unlocked: bool,
    ) -> Result<(), NodeManagerError> {
        if !wallet_is_unlocked {
            return Err(NodeManagerError::WalletLocked);
        }
        if confirmation != EXPERIMENTAL_ENABLE_CONFIRMATION {
            return Err(NodeManagerError::ConfirmationMismatch);
        }
        sidecar_keys::enforce_canonical_key_match()
            .map_err(|_| NodeManagerError::TrustRootMismatch)?;
        self.enabled_for_session = true;
        self.lifecycle = SidecarLifecycle::Enabled;
        self.sanitized_error = None;
        Ok(())
    }

    pub fn disable_for_session(&mut self) -> Result<(), NodeManagerError> {
        if self.running.is_some() {
            self.shutdown()?;
        }
        self.enabled_for_session = false;
        self.lifecycle = SidecarLifecycle::Disabled;
        Ok(())
    }

    pub fn status(&mut self) -> SidecarStatus {
        if let Some(running) = self.running.as_mut() {
            match running.child.try_wait() {
                Ok(Some(_)) => {
                    self.running = None;
                    self.lifecycle = SidecarLifecycle::Failed;
                    self.sanitized_error = Some("NODE_PROCESS_EXITED".into());
                }
                Ok(None) => {}
                Err(_) => {
                    self.lifecycle = SidecarLifecycle::Failed;
                    self.sanitized_error = Some("NODE_PROCESS_STATUS_FAILED".into());
                }
            }
        }
        let active_revision = self
            .store()
            .ok()
            .and_then(|store| store.current_revision().ok().flatten());
        SidecarStatus {
            enabled_for_session: self.enabled_for_session,
            lifecycle: self.lifecycle,
            pid: self.running.as_ref().map(|running| running.child.id()),
            active_revision,
            previous_revision: self.previous_revision.clone(),
            identity: self
                .running
                .as_ref()
                .map(|running| running.identity.clone())
                .or_else(|| self.last_identity.clone()),
            sanitized_error: self.sanitized_error.clone(),
        }
    }

    pub fn start_active(
        &mut self,
        configuration: ManagedNodeConfig,
    ) -> Result<NodeIdentity, NodeManagerError> {
        self.require_enabled()?;
        if self.running.is_some() {
            return Err(NodeManagerError::AlreadyRunning);
        }
        configuration.validate()?;
        let store = self.store()?;
        let revision = store
            .current_revision()?
            .ok_or(NodeManagerError::NoActiveSidecar)?;
        let binary = store.binary_path(&revision)?;
        self.lifecycle = SidecarLifecycle::Starting;
        let result = start_process(
            self.runtime_root_path()?,
            &binary,
            configuration,
            Some(&revision),
        );
        match result {
            Ok(running) => {
                let identity = running.identity.clone();
                self.last_identity = Some(identity.clone());
                self.running = Some(running);
                self.lifecycle = SidecarLifecycle::Ready;
                self.sanitized_error = None;
                Ok(identity)
            }
            Err(error) => {
                self.lifecycle = SidecarLifecycle::Failed;
                self.sanitized_error = Some(error.code().into());
                Err(error)
            }
        }
    }

    pub fn shutdown(&mut self) -> Result<(), NodeManagerError> {
        let Some(mut running) = self.running.take() else {
            return Ok(());
        };
        self.lifecycle = SidecarLifecycle::Stopping;
        let result = stop_process(&mut running);
        if result.is_ok() {
            self.lifecycle = if self.enabled_for_session {
                SidecarLifecycle::Enabled
            } else {
                SidecarLifecycle::Disabled
            };
            self.sanitized_error = None;
        } else {
            self.lifecycle = SidecarLifecycle::Failed;
            self.sanitized_error = Some("NODE_SHUTDOWN_FAILED".into());
        }
        result
    }

    /// Verify, install, promote, restart and health-check a signed node release.
    ///
    /// No verifier or public key is accepted from the caller. Authentication
    /// always flows through the pinned canonical `dom-sidecar` verifier.
    pub fn evaluate_signed_node_feed(
        &self,
        node_feed_bytes: Option<&[u8]>,
        current_identity: &NodeIdentity,
    ) -> Result<ValidatedNodeFeed, NodeManagerError> {
        let bytes = node_feed_bytes.ok_or(NodeManagerError::MissingNodeFeed)?;
        let manifest: NodeManifest =
            serde_json::from_slice(bytes).map_err(|_| UpdateError::ManifestInvalid)?;
        let mut signed_payload = manifest.clone();
        let signature = std::mem::take(&mut signed_payload.manifest_signature);
        if signature.trim().is_empty() {
            return Err(UpdateError::SignatureInvalid.into());
        }
        let canonical =
            serde_json::to_vec(&signed_payload).map_err(|_| UpdateError::ManifestInvalid)?;
        verify_minisign(&canonical, &signature)?;
        self.validate_node_feed_policy(manifest, current_identity, time::OffsetDateTime::now_utc())
            .map(|manifest| ValidatedNodeFeed { manifest })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn promote_signed_release(
        &mut self,
        node_feed: &ValidatedNodeFeed,
        manifest_bytes: Option<&[u8]>,
        manifest_signature: Option<&str>,
        platform: &str,
        artifact: &[u8],
        artifact_signature: &str,
        current_identity: &NodeIdentity,
        configuration: ManagedNodeConfig,
    ) -> Result<NodeIdentity, NodeManagerError> {
        self.require_enabled()?;
        sidecar_keys::enforce_canonical_key_match()
            .map_err(|_| NodeManagerError::TrustRootMismatch)?;
        configuration.validate()?;
        let node_feed = self.validate_node_feed_policy(
            node_feed.manifest.clone(),
            current_identity,
            time::OffsetDateTime::now_utc(),
        )?;
        validate_download(artifact, &node_feed.artifact)?;
        let promotion_identity = current_identity.promotion_identity();
        let manifest = verify_release(
            manifest_bytes,
            manifest_signature,
            platform,
            artifact,
            artifact_signature,
            &promotion_identity,
        )?;
        bind_node_feed_to_sidecar(&node_feed, &manifest, platform, artifact_signature)?;
        let runtime_state = self.next_runtime_state(
            &node_feed,
            current_identity,
            time::OffsetDateTime::now_utc(),
        )?;
        self.promote_verified(manifest, artifact, configuration, Some(runtime_state))
    }

    pub fn evaluate_running_signed_release_metadata(
        &self,
        node_feed_bytes: Option<&[u8]>,
        manifest_bytes: Option<&[u8]>,
        manifest_signature: Option<&str>,
        platform: &str,
    ) -> Result<NodeReleaseMetadata, NodeManagerError> {
        let sidecar = verify_manifest(manifest_bytes, manifest_signature)?;
        let current = self
            .running
            .as_ref()
            .map(|running| &running.identity)
            .ok_or(NodeManagerError::NoActiveSidecar)?;
        let feed = self.evaluate_signed_node_feed(node_feed_bytes, current)?;
        bind_node_feed_to_sidecar(
            &feed.manifest,
            &sidecar,
            platform,
            &feed.manifest.artifact.signature,
        )?;
        Ok(NodeReleaseMetadata {
            node_version: feed.manifest.node_version,
            node_revision: feed.manifest.node_revision,
            sequence: feed.manifest.sequence,
        })
    }

    #[cfg(feature = "app-test-support")]
    pub fn app_test_persist_state(
        &self,
        feed: &NodeManifest,
        current: &NodeIdentity,
        installed_at: time::OffsetDateTime,
    ) -> Result<(), NodeManagerError> {
        let state = self.next_runtime_state(feed, current, installed_at)?;
        persist_node_runtime_state(&self.runtime_layout()?, &state).map_err(Into::into)
    }

    #[cfg(feature = "app-test-support")]
    pub fn app_test_evaluate_verified_feed(
        &self,
        feed: NodeManifest,
        current: &NodeIdentity,
        now: time::OffsetDateTime,
    ) -> Result<NodeReleaseMetadata, NodeManagerError> {
        self.validate_node_feed_policy(feed, current, now)
            .map(|feed| NodeReleaseMetadata {
                node_version: feed.node_version,
                node_revision: feed.node_revision,
                sequence: feed.sequence,
            })
    }

    fn promote_verified(
        &mut self,
        manifest: SidecarManifest,
        artifact: &[u8],
        configuration: ManagedNodeConfig,
        runtime_state: Option<NodeRuntimeState>,
    ) -> Result<NodeIdentity, NodeManagerError> {
        let store = self.store()?;
        let previous = store.current_revision()?;
        if self.running.is_some() {
            self.shutdown()?;
        }
        let backup = if configuration.data_directory.exists() {
            Some(store.backup_data_dir(&configuration.data_directory)?)
        } else {
            None
        };
        store.install(&manifest.revision, artifact)?;
        self.lifecycle = SidecarLifecycle::Promoting;
        self.previous_revision = previous.clone();
        store.promote(&manifest.revision)?;
        harden_runtime_permissions(self.runtime_root_path()?)?;
        let candidate = start_process(
            self.runtime_root_path()?,
            &store.binary_path(&manifest.revision)?,
            configuration.clone(),
            Some(&manifest.revision),
        );
        let candidate = match candidate {
            Ok(mut running) => {
                if let Err(error) =
                    verify_promotion_identity(&manifest, &running.identity.promotion_identity())
                {
                    let _ = stop_process(&mut running);
                    Err(NodeManagerError::Release(error))
                } else if let Some(state) = runtime_state.as_ref() {
                    let layout = self.runtime_layout()?;
                    if let Err(error) = persist_node_runtime_state(&layout, state) {
                        let _ = stop_process(&mut running);
                        Err(NodeManagerError::Update(error))
                    } else {
                        Ok(running)
                    }
                } else {
                    Ok(running)
                }
            }
            Err(error) => Err(error),
        };
        match candidate {
            Ok(running) => {
                let identity = running.identity.clone();
                self.last_identity = Some(identity.clone());
                self.running = Some(running);
                self.lifecycle = SidecarLifecycle::Ready;
                self.sanitized_error = None;
                Ok(identity)
            }
            Err(candidate_error) => {
                self.lifecycle = SidecarLifecycle::RollingBack;
                if let Some(mut failed) = self.running.take() {
                    let _ = stop_process(&mut failed);
                }
                if let Some(previous) = previous {
                    store.rollback(&previous)?;
                    harden_runtime_permissions(self.runtime_root_path()?)?;
                    if let Some(backup) = backup.as_deref() {
                        store.restore_data_dir(backup, &configuration.data_directory)?;
                    }
                    let restored = start_process(
                        self.runtime_root_path()?,
                        &store.binary_path(&previous)?,
                        configuration,
                        Some(&previous),
                    )?;
                    self.last_identity = Some(restored.identity.clone());
                    self.running = Some(restored);
                    self.lifecycle = SidecarLifecycle::RolledBack;
                    self.sanitized_error = Some(candidate_error.code().into());
                } else {
                    if let Some(backup) = backup.as_deref() {
                        store.restore_data_dir(backup, &configuration.data_directory)?;
                    }
                    self.lifecycle = SidecarLifecycle::Failed;
                    self.sanitized_error = Some(candidate_error.code().into());
                }
                Err(candidate_error)
            }
        }
    }

    fn validate_node_feed_policy(
        &self,
        manifest: NodeManifest,
        current_identity: &NodeIdentity,
        now: time::OffsetDateTime,
    ) -> Result<NodeManifest, NodeManagerError> {
        let previous_state = self.load_runtime_state()?;
        if let Some(state) = previous_state.as_ref() {
            if state.active_revision != current_identity.node_revision
                || state.active_version != current_identity.node_version
            {
                return Err(NodeManagerError::NodeFeedMismatch);
            }
        }
        let compatibility = NodeCompatibility {
            wallet_version: env!("CARGO_PKG_VERSION").into(),
            active_node_version: current_identity.node_version.clone(),
            active_node_revision: current_identity.node_revision.clone(),
            update_sequence: previous_state
                .as_ref()
                .map_or(0, |state| state.update_sequence),
            network: current_identity.network.clone(),
            chain_id: current_identity.chain_id.clone(),
            genesis_hash: current_identity.genesis_hash.clone(),
            rpc_protocol_version: current_identity.rpc_protocol_version,
            p2p_protocol_version: current_identity.p2p_protocol_version,
            storage_schema_version: current_identity.storage_schema_version_on_disk,
            target: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
        };
        match validate_node_manifest(&manifest, &compatibility, now)? {
            NodeDecision::Available(_) => {}
            NodeDecision::UpToDate | NodeDecision::WalletUpdateRequired => {
                return Err(NodeManagerError::NodeUpdateNotAvailable);
            }
        }
        Ok(manifest)
    }

    fn next_runtime_state(
        &self,
        feed: &NodeManifest,
        current_identity: &NodeIdentity,
        installed_at: time::OffsetDateTime,
    ) -> Result<NodeRuntimeState, NodeManagerError> {
        let compatibility = NodeCompatibility {
            wallet_version: env!("CARGO_PKG_VERSION").into(),
            active_node_version: feed.node_version.clone(),
            active_node_revision: feed.node_revision.clone(),
            update_sequence: feed.sequence,
            network: feed.network.clone(),
            chain_id: feed.chain_id.clone(),
            genesis_hash: feed.genesis_hash.clone(),
            rpc_protocol_version: feed.rpc_protocol_version,
            p2p_protocol_version: feed.p2p_protocol_version,
            storage_schema_version: feed.storage_schema_version,
            target: feed.artifact.target.clone(),
            architecture: feed.artifact.architecture.clone(),
        };
        Ok(NodeRuntimeState {
            schema_version: 1,
            active_version: feed.node_version.clone(),
            active_revision: feed.node_revision.clone(),
            previous_version: Some(current_identity.node_version.clone()),
            previous_revision: Some(current_identity.node_revision.clone()),
            installed_at: installed_at
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| UpdateError::StateIo)?,
            binary_sha256: feed.artifact.sha256.clone(),
            signature_identity: "PINNED_DOM_SIDECAR_RELEASE_KEYS".into(),
            compatibility,
            update_sequence: feed.sequence,
            temporarily_denied_revision: None,
        })
    }

    fn runtime_layout(&self) -> Result<NodeRuntimeLayout, NodeManagerError> {
        let root = self
            .runtime_root
            .as_deref()
            .ok_or(NodeManagerError::RuntimeNotConfigured)?;
        NodeRuntimeLayout::initialize(root).map_err(Into::into)
    }

    fn load_runtime_state(&self) -> Result<Option<NodeRuntimeState>, NodeManagerError> {
        let path = self.runtime_layout()?.state_path();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| UpdateError::StateIo.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(UpdateError::StateIo.into()),
        }
    }

    fn require_enabled(&self) -> Result<(), NodeManagerError> {
        if self.enabled_for_session {
            Ok(())
        } else {
            Err(NodeManagerError::Disabled)
        }
    }

    fn store(&self) -> Result<SidecarStore, NodeManagerError> {
        let root = self.runtime_root_path()?;
        validate_runtime_tree(root)?;
        Ok(SidecarStore::new(root))
    }

    fn runtime_root_path(&self) -> Result<&Path, NodeManagerError> {
        self.runtime_root
            .as_deref()
            .ok_or(NodeManagerError::RuntimeNotConfigured)
    }

    #[cfg(test)]
    fn install_verified_fixture(
        &self,
        revision: &str,
        bytes: &[u8],
    ) -> Result<(), NodeManagerError> {
        let store = self.store()?;
        store.install(revision, bytes)?;
        store.promote(revision)?;
        harden_runtime_permissions(self.runtime_root_path()?)?;
        Ok(())
    }
}

impl NodeManagerError {
    fn code(&self) -> &'static str {
        match self {
            Self::StartupFailed | Self::StartupTimeout => "NODE_START_FAILED",
            Self::IdentityMismatch => "NODE_IDENTITY_MISMATCH",
            Self::ShutdownFailed => "NODE_SHUTDOWN_FAILED",
            Self::UnsafeBinary
            | Self::WindowsAclSetupFailed(_)
            | Self::WindowsAclOwnerUnsafe
            | Self::WindowsAclWritablePrincipalUnsafe
            | Self::WindowsAclValidationFailed(_) => "NODE_BINARY_UNSAFE",
            Self::TrustRootMismatch => "NODE_TRUST_ROOT_MISMATCH",
            Self::MissingNodeFeed | Self::NodeFeedMismatch => "NODE_FEED_INVALID",
            Self::NodeUpdateNotAvailable => "NODE_UPDATE_NOT_AVAILABLE",
            Self::Update(UpdateError::DowngradeRejected) => "UPDATE_DOWNGRADE_REJECTED",
            Self::Update(_) => "NODE_UPDATE_POLICY_REJECTED",
            Self::Release(_) => "NODE_RELEASE_REJECTED",
            _ => "NODE_MANAGER_FAILED",
        }
    }
}

fn bind_node_feed_to_sidecar(
    feed: &NodeManifest,
    sidecar: &SidecarManifest,
    platform: &str,
    artifact_signature: &str,
) -> Result<(), NodeManagerError> {
    let sidecar_artifact = sidecar
        .artifacts
        .iter()
        .find(|artifact| artifact.platform == platform)
        .ok_or(NodeManagerError::NodeFeedMismatch)?;
    let expected_platform = format!("{}-{}", feed.artifact.target, feed.artifact.architecture);
    if platform != expected_platform
        || feed.node_version != sidecar.version
        || feed.node_revision != sidecar.revision
        || feed.network != sidecar.network
        || feed.chain_id != sidecar.chain_id
        || feed.genesis_hash != sidecar.genesis_hash
        || feed.rpc_protocol_version != sidecar.rpc_protocol_version
        || feed.p2p_protocol_version != sidecar.p2p_protocol_version
        || feed.storage_schema_version != sidecar.storage_schema_version_supported
        || feed.published_at != sidecar.published_at
        || feed.artifact.sha256 != sidecar_artifact.sha256
        || feed.artifact.url.as_str() != sidecar_artifact.url
        || feed.artifact.signature != artifact_signature
    {
        return Err(NodeManagerError::NodeFeedMismatch);
    }
    Ok(())
}

fn start_process(
    runtime_root: &Path,
    binary: &Path,
    configuration: ManagedNodeConfig,
    expected_revision: Option<&str>,
) -> Result<RunningNode, NodeManagerError> {
    validate_runtime_tree(runtime_root)?;
    if !binary.starts_with(runtime_root) {
        return Err(NodeManagerError::UnsafeBinary);
    }
    validate_binary(binary)?;
    let token = random_token();
    fs::create_dir_all(&configuration.data_directory)?;
    let mut command = Command::new(binary);
    reset_child_environment(&mut command)?;
    command
        .env("DOM_NETWORK", &configuration.network)
        .env("DOM_DATA_DIR", &configuration.data_directory)
        .env("DOM_RPC_LISTEN_ADDR", configuration.rpc_address.to_string())
        .env("DOM_RPC_TOKEN", &token)
        .env("DOM_P2P_LISTEN_ADDR", configuration.p2p_address.to_string())
        .env("DOM_MINE", "false")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !configuration.seed_peers.is_empty() {
        command.env(
            "DOM_SEED_PEERS",
            configuration
                .seed_peers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    let mut child = command.spawn()?;
    let identity = match wait_for_identity(
        &mut child,
        configuration.rpc_address,
        &token,
        STARTUP_TIMEOUT,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if expected_revision.is_some_and(|revision| identity.node_revision != revision) {
        let mut running = RunningNode {
            child,
            token,
            config: configuration,
            identity,
        };
        let _ = stop_process(&mut running);
        return Err(NodeManagerError::IdentityMismatch);
    }
    Ok(RunningNode {
        child,
        token,
        config: configuration,
        identity,
    })
}

fn wait_for_identity(
    child: &mut Child,
    rpc_address: SocketAddr,
    token: &str,
    timeout: Duration,
) -> Result<NodeIdentity, NodeManagerError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| NodeManagerError::Rpc)?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Err(NodeManagerError::StartupFailed);
        }
        if rpc_get_ok(&client, rpc_address, "/health", None) {
            if let (Ok(build), Ok(network)) = (
                rpc_get_json::<BuildInfoResponse>(&client, rpc_address, "/build-info", Some(token)),
                rpc_get_json::<NetworkInfoResponse>(
                    &client,
                    rpc_address,
                    "/network-info",
                    Some(token),
                ),
            ) {
                return Ok(NodeIdentity {
                    node_version: build.node_version,
                    node_revision: build.node_revision,
                    network: network.network,
                    chain_id: network.chain_id,
                    genesis_hash: network.genesis_hash,
                    rpc_protocol_version: build.rpc_protocol_version,
                    p2p_protocol_version: build.p2p_protocol_version,
                    storage_schema_version_supported: build.storage_schema_version_supported,
                    storage_schema_version_on_disk: network.storage_schema_version_on_disk,
                    height: network.height,
                });
            }
        }
        if Instant::now() >= deadline {
            return Err(NodeManagerError::StartupTimeout);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn stop_process(running: &mut RunningNode) -> Result<(), NodeManagerError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| NodeManagerError::Rpc)?;
    let response = client
        .post(format!("http://{}/shutdown", running.config.rpc_address))
        .bearer_auth(&running.token)
        .send();
    if !response.is_ok_and(|response| response.status().as_u16() == 202) {
        let _ = running.child.kill();
        let _ = running.child.wait();
        return Err(NodeManagerError::ShutdownFailed);
    }
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    loop {
        if running.child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            running.child.kill()?;
            running.child.wait()?;
            return Err(NodeManagerError::ShutdownFailed);
        }
        thread::sleep(Duration::from_millis(50));
    }
    wait_until_ports_released(
        [running.config.rpc_address, running.config.p2p_address],
        Duration::from_secs(5),
    )
}

fn wait_until_ports_released(
    addresses: impl IntoIterator<Item = SocketAddr>,
    timeout: Duration,
) -> Result<(), NodeManagerError> {
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    let deadline = Instant::now() + timeout;
    loop {
        let all_free = addresses
            .iter()
            .all(|address| TcpListener::bind(address).is_ok());
        if all_free {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(NodeManagerError::ShutdownFailed);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn rpc_get_ok(client: &Client, address: SocketAddr, path: &str, token: Option<&str>) -> bool {
    let mut request = client.get(format!("http://{address}{path}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request
        .send()
        .is_ok_and(|response| response.status().is_success())
}

fn rpc_get_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    address: SocketAddr,
    path: &str,
    token: Option<&str>,
) -> Result<T, NodeManagerError> {
    let mut request = client.get(format!("http://{address}{path}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::json)
        .map_err(|_| NodeManagerError::Rpc)
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn reset_child_environment(command: &mut Command) -> Result<(), NodeManagerError> {
    #[cfg(windows)]
    let system_root =
        PathBuf::from(std::env::var_os("SystemRoot").ok_or(NodeManagerError::UnsafeBinary)?);
    #[cfg(windows)]
    if !system_root.is_absolute() {
        return Err(NodeManagerError::UnsafeBinary);
    }
    command.env_clear();
    #[cfg(windows)]
    command
        .env("SystemRoot", &system_root)
        .env("WINDIR", system_root);
    Ok(())
}

fn validate_binary(binary: &Path) -> Result<(), NodeManagerError> {
    let metadata = fs::symlink_metadata(binary)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(NodeManagerError::UnsafeBinary);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        let parent = binary.parent().ok_or(NodeManagerError::UnsafeBinary)?;
        let parent_metadata = fs::metadata(parent)?;
        if mode & 0o022 != 0 || metadata.uid() != parent_metadata.uid() {
            return Err(NodeManagerError::UnsafeBinary);
        }
    }
    Ok(())
}

fn validate_runtime_tree(root: &Path) -> Result<(), NodeManagerError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || unsafe_path_kind(&root_metadata) {
        return Err(NodeManagerError::UnsafeBinary);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = root_metadata.uid();
        if process_file_owner(root)? != owner || root_metadata.permissions().mode() & 0o022 != 0 {
            return Err(NodeManagerError::UnsafeBinary);
        }
        validate_runtime_entries(root, Some(owner))?;
    }
    #[cfg(windows)]
    {
        validate_runtime_entries(root, None)?;
        validate_windows_acl(root)?;
    }
    #[cfg(not(any(unix, windows)))]
    validate_runtime_entries(root, None)?;
    Ok(())
}

fn harden_runtime_permissions(root: &Path) -> Result<(), NodeManagerError> {
    if unsafe_path_kind(&fs::symlink_metadata(root)?) {
        return Err(NodeManagerError::UnsafeBinary);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if unsafe_path_kind(&metadata) {
            return Err(NodeManagerError::UnsafeBinary);
        }
        if metadata.is_dir() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700))?;
            }
            harden_runtime_permissions(&entry.path())?;
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let executable = entry.file_name().to_string_lossy().starts_with("dom-node-");
                fs::set_permissions(
                    entry.path(),
                    fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }),
                )?;
            }
        }
    }
    validate_runtime_tree(root)
}

#[cfg(unix)]
fn process_file_owner(root: &Path) -> Result<u32, NodeManagerError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let probe = root.join(format!(
        ".owner-probe-{}-{}",
        std::process::id(),
        random_token()
    ));
    let result = (|| {
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&probe)?;
        file.sync_all()?;
        Ok::<u32, std::io::Error>(file.metadata()?.uid())
    })();
    let _ = fs::remove_file(probe);
    result.map_err(Into::into)
}

fn validate_runtime_entries(
    path: &Path,
    expected_owner: Option<u32>,
) -> Result<(), NodeManagerError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if unsafe_path_kind(&metadata) {
            return Err(NodeManagerError::UnsafeBinary);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if expected_owner.is_some_and(|owner| metadata.uid() != owner)
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(NodeManagerError::UnsafeBinary);
            }
        }
        let _ = expected_owner;
        if metadata.is_dir() {
            validate_runtime_entries(&entry.path(), expected_owner)?;
        }
    }
    Ok(())
}

fn unsafe_path_kind(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

#[cfg(windows)]
fn validate_windows_acl(root: &Path) -> Result<(), NodeManagerError> {
    let system_root =
        PathBuf::from(std::env::var_os("SystemRoot").ok_or(NodeManagerError::UnsafeBinary)?);
    if !system_root.is_absolute() {
        return Err(NodeManagerError::UnsafeBinary);
    }
    let powershell = system_root.join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let script = r#"
$ErrorActionPreference='Stop'
try {
  Import-Module -Name "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1" -ErrorAction Stop
} catch { exit 40 }
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed=@($current,'S-1-5-18','S-1-5-32-544')
$write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::FullControl -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
$items=@(Get-Item -LiteralPath $env:DOM_RUNTIME_ACL_PATH -Force)+@(Get-ChildItem -LiteralPath $env:DOM_RUNTIME_ACL_PATH -Force -Recurse)
foreach($item in $items){
  $acl=Get-Acl -LiteralPath $item.FullName
  $owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
  if($allowed -notcontains $owner){exit 41}
  foreach($rule in $acl.Access){
    $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $sid -and (($rule.FileSystemRights -band $write) -ne 0)){exit 42}
  }
}
exit 0
"#;
    let status = Command::new(powershell)
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("WINDIR", &system_root)
        .env("DOM_RUNTIME_ACL_PATH", root)
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    match status.code() {
        Some(0) => Ok(()),
        Some(41) => Err(NodeManagerError::WindowsAclOwnerUnsafe),
        Some(42) => Err(NodeManagerError::WindowsAclWritablePrincipalUnsafe),
        Some(code) => Err(NodeManagerError::WindowsAclValidationFailed(code)),
        None => Err(NodeManagerError::WindowsAclValidationFailed(-1)),
    }
}

#[cfg(windows)]
fn secure_new_windows_runtime_root(root: &Path) -> Result<(), NodeManagerError> {
    let system_root =
        PathBuf::from(std::env::var_os("SystemRoot").ok_or(NodeManagerError::UnsafeBinary)?);
    if !system_root.is_absolute() {
        return Err(NodeManagerError::UnsafeBinary);
    }
    let powershell = system_root.join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let script = r#"
$ErrorActionPreference='Stop'
try {
  Import-Module -Name "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1" -ErrorAction Stop
} catch { exit 50 }
try { $identity=[Security.Principal.WindowsIdentity]::GetCurrent() } catch { exit 51 }
try { $acl=Get-Acl -LiteralPath $env:DOM_RUNTIME_ACL_PATH } catch { exit 52 }
try {
  $acl.SetAccessRuleProtection($true,$false)
  foreach($rule in @($acl.Access)){[void]$acl.RemoveAccessRuleSpecific($rule)}
} catch { exit 53 }
try { $acl.SetOwner($identity.User) } catch { exit 54 }
$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$none=[Security.AccessControl.PropagationFlags]::None
$allow=[Security.AccessControl.AccessControlType]::Allow
try {
  foreach($sid in @($identity.User,[Security.Principal.SecurityIdentifier]'S-1-5-18',[Security.Principal.SecurityIdentifier]'S-1-5-32-544')){
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,$none,$allow)
    [void]$acl.AddAccessRule($rule)
  }
} catch { exit 55 }
try { Set-Acl -LiteralPath $env:DOM_RUNTIME_ACL_PATH -AclObject $acl } catch { exit 56 }
exit 0
"#;
    let status = Command::new(powershell)
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("WINDIR", &system_root)
        .env("DOM_RUNTIME_ACL_PATH", root)
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(NodeManagerError::WindowsAclSetupFailed(code)),
        None => Err(NodeManagerError::WindowsAclSetupFailed(-1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minisign::KeyPair;
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        io::{BufRead, BufReader, Read},
        process::Stdio,
    };
    use tempfile::tempdir;

    fn enabled_manager(root: &Path) -> NodeManager {
        let mut manager = NodeManager::default();
        manager.configure_runtime(root).unwrap();
        manager
            .enable_for_session(EXPERIMENTAL_ENABLE_CONFIRMATION, true)
            .unwrap();
        manager
    }

    #[test]
    fn release_build_has_no_runtime_key_or_environment_activation_seam() {
        assert_eq!(
            sidecar_keys::PRIMARY_MINISIGN_KEY,
            dom_sidecar::sidecar_keys::PRIMARY_MINISIGN_KEY
        );
        assert_eq!(
            sidecar_keys::RESERVE_MINISIGN_KEY,
            dom_sidecar::sidecar_keys::RESERVE_MINISIGN_KEY
        );
        assert!(sidecar_keys::TEST_KEY_LABEL.contains("NEVER TRUST"));
        std::env::set_var("DOM_EXPERIMENTAL_SIDECAR", "true");
        let manager = NodeManager::default();
        assert!(!manager.enabled_for_session);
        std::env::remove_var("DOM_EXPERIMENTAL_SIDECAR");
    }

    #[test]
    fn opt_in_requires_unlocked_wallet_and_exact_in_memory_confirmation() {
        let mut manager = NodeManager::default();
        assert!(matches!(
            manager.enable_for_session(EXPERIMENTAL_ENABLE_CONFIRMATION, false),
            Err(NodeManagerError::WalletLocked)
        ));
        assert!(matches!(
            manager.enable_for_session("yes", true),
            Err(NodeManagerError::ConfirmationMismatch)
        ));
        manager
            .enable_for_session(EXPERIMENTAL_ENABLE_CONFIRMATION, true)
            .unwrap();
        assert!(manager.status().enabled_for_session);
        assert!(!NodeManager::default().status().enabled_for_session);
    }

    #[test]
    fn missing_manifest_is_rejected_before_promotion() {
        let root = tempdir().unwrap();
        let manager = enabled_manager(root.path().join("runtime").as_path());
        let current = NodeIdentity {
            node_version: "0.1.2".into(),
            node_revision: "a".repeat(40),
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            storage_schema_version_supported: 1,
            storage_schema_version_on_disk: 1,
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
            height: 0,
        };
        assert!(matches!(
            manager.evaluate_signed_node_feed(None, &current),
            Err(NodeManagerError::MissingNodeFeed)
        ));
        assert_eq!(manager.store().unwrap().current_revision().unwrap(), None);
    }

    #[test]
    fn unknown_test_key_and_tampered_artifact_are_rejected_by_canonical_verifier() {
        let key_pair = KeyPair::generate_unencrypted_keypair().unwrap();
        let data = b"test sidecar";
        let signature =
            minisign::sign(None, &key_pair.sk, std::io::Cursor::new(data), None, None).unwrap();
        assert!(matches!(
            dom_sidecar::verify_artifact(
                data,
                &signature.to_string(),
                &format!("{:x}", Sha256::digest(data))
            ),
            Err(SidecarError::UntrustedSignature)
        ));
        assert!(
            dom_sidecar::verify_artifact(b"changed", "untrusted comment: invalid", "00").is_err()
        );
    }

    #[test]
    fn production_signed_sidecar_manifest_fixture_verifies_locally() {
        const MANIFEST: &[u8] = include_bytes!(
            "../../../tests/fixtures/sidecar/ab45a2944f22fe00f9b12984354f0d5d7cdd229a/sidecar-manifest.json"
        );
        const SIGNATURE: &str = include_str!(
            "../../../tests/fixtures/sidecar/ab45a2944f22fe00f9b12984354f0d5d7cdd229a/sidecar-manifest.json.minisig"
        );

        sidecar_keys::enforce_canonical_key_match().unwrap();
        verify_minisign(MANIFEST, SIGNATURE)
            .expect("production key must verify the exact local manifest bytes");
        let manifest = verify_manifest(Some(MANIFEST), Some(SIGNATURE))
            .expect("canonical sidecar parser must accept the signed fixture");
        assert_eq!(
            manifest.revision,
            "ab45a2944f22fe00f9b12984354f0d5d7cdd229a"
        );
        assert_eq!(manifest.network, "mainnet");
        assert!(
            manifest
                .artifacts
                .iter()
                .all(|artifact| artifact.url.starts_with("https://fixture.invalid/")),
            "fixture verification must never dereference a release URL"
        );
    }

    #[test]
    fn identity_mismatches_are_rejected() {
        let mut manifest = SidecarManifest {
            schema: 1,
            version: "0.1.3".into(),
            revision: "abcdef12".into(),
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
            storage_schema_version_supported: 1,
            min_wallet_version: "0.2.0".into(),
            published_at: "2026-07-23T00:00:00Z".into(),
            artifacts: vec![],
        };
        let running = RunningIdentity {
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            storage_schema_version_on_disk: 1,
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
        };
        for field in 0..6 {
            let mut candidate = manifest.clone();
            match field {
                0 => candidate.chain_id = "wrong".into(),
                1 => candidate.genesis_hash = "wrong".into(),
                2 => candidate.network = "testnet".into(),
                3 => candidate.rpc_protocol_version = 2,
                4 => candidate.p2p_protocol_version = 2,
                _ => candidate.storage_schema_version_supported = 0,
            }
            assert!(verify_promotion_identity(&candidate, &running).is_err());
        }
        manifest.chain_id = running.chain_id.clone();
        assert!(verify_promotion_identity(&manifest, &running).is_ok());
    }

    #[test]
    fn pointer_promotion_rollback_and_data_backup_are_atomic() {
        let root = tempdir().unwrap();
        let manager = enabled_manager(root.path().join("runtime").as_path());
        let store = manager.store().unwrap();
        store.install("aaaa1111", b"old node fixture").unwrap();
        store.promote("aaaa1111").unwrap();
        store.install("bbbb2222", b"new node fixture").unwrap();
        store.promote("bbbb2222").unwrap();
        assert!(
            !fs::symlink_metadata(store.current_pointer())
                .unwrap()
                .file_type()
                .is_symlink(),
            "the active pointer must be an ordinary file, never a symlink"
        );
        assert_eq!(
            store.current_revision().unwrap().as_deref(),
            Some("bbbb2222")
        );
        store.rollback("aaaa1111").unwrap();
        assert_eq!(
            store.current_revision().unwrap().as_deref(),
            Some("aaaa1111")
        );

        let data = root.path().join("chain");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("state"), b"before").unwrap();
        let backup = store.backup_data_dir(&data).unwrap();
        fs::write(data.join("state"), b"after").unwrap();
        store.restore_data_dir(&backup, &data).unwrap();
        assert_eq!(fs::read(data.join("state")).unwrap(), b"before");
    }

    #[test]
    fn persisted_node_sequence_rejects_equal_and_lower_feeds_at_runtime_boundary() {
        let root = tempdir().unwrap();
        let manager = enabled_manager(root.path().join("runtime").as_path());
        let artifact = b"signed node fixture";
        let old_identity = policy_identity("0.1.0", &"b".repeat(40));
        let accepted = policy_feed(8, "0.1.1", &"c".repeat(40), artifact);
        let installed_at = time::OffsetDateTime::parse(
            "2026-07-23T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let state = manager
            .next_runtime_state(&accepted, &old_identity, installed_at)
            .unwrap();
        persist_node_runtime_state(&manager.runtime_layout().unwrap(), &state).unwrap();

        let active_identity = policy_identity("0.1.1", &"c".repeat(40));
        let now = time::OffsetDateTime::parse(
            "2026-07-23T13:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(matches!(
            manager.validate_node_feed_policy(
                policy_feed(8, "0.1.2", &"d".repeat(40), artifact),
                &active_identity,
                now
            ),
            Err(NodeManagerError::Update(UpdateError::DowngradeRejected))
        ));
        assert!(matches!(
            manager.validate_node_feed_policy(
                policy_feed(7, "0.1.2", &"d".repeat(40), artifact),
                &active_identity,
                now
            ),
            Err(NodeManagerError::Update(UpdateError::DowngradeRejected))
        ));
        assert!(manager
            .validate_node_feed_policy(
                policy_feed(9, "0.1.2", &"d".repeat(40), artifact),
                &active_identity,
                now
            )
            .is_ok());
        assert_eq!(
            manager
                .load_runtime_state()
                .unwrap()
                .unwrap()
                .update_sequence,
            8
        );
    }

    #[test]
    fn runtime_security_rejects_writable_or_redirected_subdirectories() {
        let temporary = tempdir().unwrap();
        let runtime = temporary.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        let unsafe_child = runtime.join("unsafe");
        fs::create_dir(&unsafe_child).unwrap();

        #[cfg(unix)]
        {
            fs::set_permissions(&unsafe_child, fs::Permissions::from_mode(0o777)).unwrap();
            let mut manager = NodeManager::default();
            assert!(matches!(
                manager.configure_runtime(&runtime),
                Err(NodeManagerError::UnsafeBinary)
            ));
            fs::set_permissions(&unsafe_child, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_dir(&unsafe_child).unwrap();
            std::os::unix::fs::symlink(temporary.path(), &unsafe_child).unwrap();
            assert!(matches!(
                manager.configure_runtime(&runtime),
                Err(NodeManagerError::UnsafeBinary)
            ));
        }

        #[cfg(windows)]
        {
            let mut manager = NodeManager::default();
            let grant = Command::new("icacls.exe")
                .arg(&unsafe_child)
                .args(["/grant", "*S-1-1-0:(OI)(CI)M", "/Q"])
                .status()
                .unwrap();
            assert!(grant.success());
            assert!(matches!(
                manager.configure_runtime(&runtime),
                Err(NodeManagerError::UnsafeBinary
                    | NodeManagerError::WindowsAclOwnerUnsafe
                    | NodeManagerError::WindowsAclWritablePrincipalUnsafe
                    | NodeManagerError::WindowsAclValidationFailed(_))
            ));
            let remove = Command::new("icacls.exe")
                .arg(&unsafe_child)
                .args(["/remove:g", "*S-1-1-0", "/Q"])
                .status()
                .unwrap();
            assert!(remove.success());
            fs::remove_dir(&unsafe_child).unwrap();
            let target = temporary.path().join("target");
            fs::create_dir(&target).unwrap();
            let junction = Command::new("cmd.exe")
                .args(["/C", "mklink", "/J"])
                .arg(&unsafe_child)
                .arg(&target)
                .status()
                .unwrap();
            assert!(junction.success());
            assert!(matches!(
                manager.configure_runtime(&runtime),
                Err(NodeManagerError::UnsafeBinary)
            ));
        }
    }

    #[test]
    #[ignore = "downloads the published v0.1.2 production artifact"]
    fn published_v012_uses_real_pins_but_has_no_promotable_manifest() {
        const BINARY_URL: &str = "https://github.com/sorenplanck/dom-protocol/releases/download/v0.1.2/dom-node-linux-x86_64";
        const SIGNATURE_URL: &str = "https://github.com/sorenplanck/dom-protocol/releases/download/v0.1.2/dom-node-linux-x86_64.minisig";

        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        let artifact = client
            .get(BINARY_URL)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .unwrap()
            .to_vec();
        let signature = client
            .get(SIGNATURE_URL)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        let sha256 = format!("{:x}", Sha256::digest(&artifact));

        dom_sidecar::verify_artifact(&artifact, &signature, &sha256)
            .expect("published artifact verifies under wallet production pins");
        let mut altered = artifact.clone();
        altered[0] ^= 1;
        assert!(matches!(
            dom_sidecar::verify_artifact(&altered, &signature, &sha256),
            Err(SidecarError::UntrustedSignature)
        ));
        assert!(matches!(
            dom_sidecar::verify_release(
                None,
                None,
                "linux-x86_64",
                &artifact,
                &signature,
                &RunningIdentity {
                    network: "mainnet".into(),
                    chain_id: String::new(),
                    genesis_hash: String::new(),
                    storage_schema_version_on_disk: 1,
                    rpc_protocol_version: 1,
                    p2p_protocol_version: 1,
                }
            ),
            Err(SidecarError::MissingManifest)
        ));
    }

    #[test]
    #[ignore = "requires DOM_TEST_SIDECAR_BINARY built from the pinned protocol revision"]
    fn pinned_sidecar_process_reports_identity_and_rolls_back() {
        let root = tempdir().unwrap();
        let source = std::env::var_os("DOM_TEST_SIDECAR_BINARY")
            .map(PathBuf::from)
            .expect("DOM_TEST_SIDECAR_BINARY is required");
        let artifact = fs::read(source).unwrap();
        let downloaded = root.path().join("pinned-dom-node");
        fs::write(&downloaded, &artifact).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&downloaded, fs::Permissions::from_mode(0o700)).unwrap();
        let revision = probe_fixture_revision(&downloaded);
        assert!(!revision.is_empty());

        let mut manager = enabled_manager(root.path().join("runtime").as_path());
        manager
            .install_verified_fixture(&revision, &artifact)
            .unwrap();
        validate_runtime_tree(manager.runtime_root_path().unwrap())
            .expect("installed runtime tree remains secure");
        validate_binary(&manager.store().unwrap().binary_path(&revision).unwrap())
            .expect("installed runtime binary remains secure");
        let config = test_config(root.path());
        let identity = manager.start_active(config.clone()).unwrap();
        assert_eq!(identity.node_revision, revision);
        assert_eq!(identity.network, "regtest");
        assert!(!identity.chain_id.is_empty());
        assert!(!identity.genesis_hash.is_empty());
        manager.shutdown().unwrap();

        let mut manager = enabled_manager(root.path().join("promoted-runtime").as_path());
        let valid_manifest = SidecarManifest {
            schema: 1,
            version: identity.node_version.clone(),
            revision: revision.clone(),
            network: identity.network.clone(),
            chain_id: identity.chain_id.clone(),
            genesis_hash: identity.genesis_hash.clone(),
            rpc_protocol_version: identity.rpc_protocol_version,
            p2p_protocol_version: identity.p2p_protocol_version,
            storage_schema_version_supported: identity.storage_schema_version_supported,
            min_wallet_version: "0.2.0".into(),
            published_at: "2026-07-23T00:00:00Z".into(),
            artifacts: Vec::new(),
        };
        manager
            .promote_verified(valid_manifest, &artifact, config.clone(), None)
            .expect("verified candidate is promoted, restarted and health checked");
        assert_eq!(
            manager.status().active_revision.as_deref(),
            Some(revision.as_str())
        );
        let old_pid = manager.status().pid.unwrap();
        #[cfg(windows)]
        {
            let active_binary = manager.store().unwrap().binary_path(&revision).unwrap();
            assert!(
                fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(active_binary)
                    .is_err(),
                "Windows must keep the running executable locked"
            );
        }

        fs::write(
            config.data_directory.join("wallet-preservation-marker"),
            b"before",
        )
        .unwrap();
        #[cfg(unix)]
        let failing: &[u8] =
            b"#!/bin/sh\nprintf after > \"$DOM_DATA_DIR/wallet-preservation-marker\"\nexit 1\n";
        #[cfg(windows)]
        let failing: &[u8] = b"not a valid Windows executable";
        let failing_manifest = SidecarManifest {
            schema: 1,
            version: "0.1.3".into(),
            revision: "deadbeef".into(),
            network: identity.network.clone(),
            chain_id: identity.chain_id.clone(),
            genesis_hash: identity.genesis_hash.clone(),
            rpc_protocol_version: identity.rpc_protocol_version,
            p2p_protocol_version: identity.p2p_protocol_version,
            storage_schema_version_supported: identity.storage_schema_version_supported,
            min_wallet_version: "0.2.0".into(),
            published_at: "2026-07-23T00:00:00Z".into(),
            artifacts: Vec::new(),
        };
        assert!(manager
            .promote_verified(failing_manifest, failing, config.clone(), None)
            .is_err());
        let rolled_back = manager.status();
        assert_eq!(rolled_back.lifecycle, SidecarLifecycle::RolledBack);
        assert_eq!(
            rolled_back.active_revision.as_deref(),
            Some(revision.as_str())
        );
        assert_ne!(rolled_back.pid, Some(old_pid));
        assert_eq!(
            fs::read(config.data_directory.join("wallet-preservation-marker")).unwrap(),
            b"before"
        );
        assert_eq!(
            rolled_back.identity.as_ref().unwrap().node_revision,
            revision
        );
        manager.shutdown().unwrap();
    }

    fn probe_fixture_revision(binary: &Path) -> String {
        let mut command = Command::new(binary);
        reset_child_environment(&mut command).unwrap();
        let mut child = command
            .arg("--probe")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        if line.trim().is_empty() {
            let mut error = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            let status = child.wait().unwrap();
            panic!("sidecar probe exited before readiness ({status}): {error}");
        }
        let probe: serde_json::Value = serde_json::from_str(&line).unwrap();
        let address: SocketAddr = probe["rpc_addr"].as_str().unwrap().parse().unwrap();
        let token = probe["token"].as_str().unwrap();
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let build = rpc_get_json::<BuildInfoResponse>(&client, address, "/build-info", Some(token))
            .unwrap();
        let response = client
            .post(format!("http://{address}/shutdown"))
            .bearer_auth(token)
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 202);
        assert!(child.wait().unwrap().success());
        build.node_revision
    }

    fn test_config(root: &Path) -> ManagedNodeConfig {
        ManagedNodeConfig {
            network: "regtest".into(),
            data_directory: root.join("chain"),
            rpc_address: free_loopback(),
            p2p_address: free_loopback(),
            seed_peers: Vec::new(),
        }
    }

    fn free_loopback() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    }

    fn policy_identity(version: &str, revision: &str) -> NodeIdentity {
        NodeIdentity {
            node_version: version.into(),
            node_revision: revision.into(),
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
            storage_schema_version_supported: 1,
            storage_schema_version_on_disk: 1,
            height: 1,
        }
    }

    fn policy_feed(sequence: u64, version: &str, revision: &str, artifact: &[u8]) -> NodeManifest {
        NodeManifest {
            schema_version: 1,
            channel: "stable".into(),
            node_version: version.into(),
            node_revision: revision.into(),
            sequence,
            published_at: "2026-07-23T12:00:00Z".into(),
            expires_at: "2099-08-23T12:00:00Z".into(),
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
            storage_schema_version: 1,
            compatible_wallet_versions: format!("={}", env!("CARGO_PKG_VERSION")),
            requires_wallet_update: false,
            node_only_compatible: true,
            critical_update: false,
            artifact: dom_wallet_updater::ArtifactDescriptor {
                target: std::env::consts::OS.into(),
                architecture: std::env::consts::ARCH.into(),
                url: "https://github.com/sorenplanck/dom-protocol/releases/download/node-test/dom-node"
                    .parse()
                    .unwrap(),
                sha256: format!("{:x}", Sha256::digest(artifact)),
                size: artifact.len() as u64,
                signature: "detached-artifact-signature".into(),
            },
            manifest_signature: "detached-feed-signature".into(),
        }
    }
}

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use dom_wallet_node_manager::ManagedNodeConfig;
use dom_wallet_tauri_shell::{DesktopApplication, UpdateControl};
use dom_wallet_updater::{
    download_verified_artifact_async, validate_artifact_staging_destination,
    validate_wallet_manifest, verify_staged_artifact, verify_wallet_manifest_signature,
    ArtifactDownloadTimeouts, MinisignVerifier, UpdateError, WalletDecision, WalletManifest,
    WalletPolicy, WalletUpdaterState, MAX_INITIAL_JITTER_SECONDS, UPDATE_INTERVAL_SECONDS,
    WALLET_UPDATE_ENDPOINT,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{TcpListener, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;
use zeroize::Zeroizing;

/// Pinned primary DOM release signing key (Minisign key ID 74197A95CA309CF0).
/// The backup key 1BD5CDF20DACC151 stays offline until an explicit rotation
/// release; the Tauri updater plugin accepts a single key, so pinning the
/// backup here would create a verification path that can never succeed.
const UPDATE_PUBLIC_KEY: Option<&str> =
    Some("RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3");

/// The Tauri updater plugin expects the base64 encoding of a complete
/// Minisign public-key file, while [`MinisignVerifier::from_base64`] takes the
/// raw base64 key line. Both derive from the same pinned key.
fn plugin_pubkey(raw_key: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!(
        "untrusted comment: minisign public key\n{raw_key}\n"
    ))
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AutomaticUpdatePreference {
    schema_version: u32,
    enabled: bool,
}

fn load_automatic_update_preference(path: &Path) -> bool {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AutomaticUpdatePreference>(&bytes).ok())
        .filter(|preference| preference.schema_version == 1)
        .map(|preference| preference.enabled)
        .unwrap_or(true)
}

fn persist_automatic_update_preference(path: &Path, enabled: bool) -> Result<(), UpdateError> {
    let parent = path.parent().ok_or(UpdateError::StateIo)?;
    fs::create_dir_all(parent).map_err(|_| UpdateError::StateIo)?;
    let temporary = parent.join(format!(
        ".automatic-update-preference-{}.tmp",
        uuid::Uuid::new_v4()
    ));
    let bytes = serde_json::to_vec(&AutomaticUpdatePreference {
        schema_version: 1,
        enabled,
    })
    .map_err(|_| UpdateError::StateIo)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&temporary).map_err(|_| UpdateError::StateIo)?;
    let result = (|| {
        output.write_all(&bytes).map_err(|_| UpdateError::StateIo)?;
        output.sync_all().map_err(|_| UpdateError::StateIo)?;
        fs::rename(&temporary, path).map_err(|_| UpdateError::StateIo)?;
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| UpdateError::StateIo)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn automatic_update_preference_path(handle: &tauri::AppHandle) -> Result<PathBuf, UpdateError> {
    handle
        .path()
        .app_config_dir()
        .map(|directory| directory.join("automatic-update-preference.json"))
        .map_err(|_| UpdateError::StateIo)
}

fn initialize_file_logging(app: &tauri::App) {
    let file = app.path().app_log_dir().ok().and_then(|directory| {
        fs::create_dir_all(&directory).ok()?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(directory.join("dom-wallet-v3.log"))
            .ok()
    });
    if let Some(file) = file {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
            .with_writer(Mutex::new(file))
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
            .try_init();
    }
}

fn ensure_mainnet_node(
    handle: &tauri::AppHandle,
    app: &DesktopApplication,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    if let Ok(status) = app.embedded_node_status() {
        if status.network.is_some() {
            return Ok(status);
        }
    }
    let data_directory = handle
        .path()
        .app_data_dir()
        .map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "APP_DATA_DIRECTORY_UNAVAILABLE".into(),
            category: "PLATFORM".into(),
            message: "The platform application data directory is unavailable.".into(),
            retryable: false,
        })?
        .join("mainnet")
        .join("node");
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "LOCAL_LISTENER_UNAVAILABLE".into(),
            category: "NODE".into(),
            message: "A private local node listener could not be reserved.".into(),
            retryable: true,
        })?;
    let address = listener
        .local_addr()
        .map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "LOCAL_LISTENER_UNAVAILABLE".into(),
            category: "NODE".into(),
            message: "A private local node listener could not be reserved.".into(),
            retryable: true,
        })?;
    drop(listener);
    app.embedded_node_start_mainnet(data_directory, address)
        .map_err(Into::into)
}

#[tauri::command]
fn native_bridge_status() -> dom_wallet_tauri_shell::NativeBridgeStatusDto {
    dom_wallet_tauri_shell::native_bridge_status()
}

#[tauri::command]
fn get_build_info() -> dom_wallet_tauri_shell::BuildInfoDto {
    dom_wallet_tauri_shell::get_build_info()
}

#[tauri::command]
fn update_status(
    updater: tauri::State<'_, UpdateControl>,
) -> dom_wallet_tauri_shell::UpdateStatusDto {
    updater.snapshot()
}

#[tauri::command]
fn automatic_updates_set(
    handle: tauri::AppHandle,
    updater: tauri::State<'_, UpdateControl>,
    enabled: bool,
) -> Result<dom_wallet_tauri_shell::UpdateStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    let path = automatic_update_preference_path(&handle).map_err(|_| {
        dom_wallet_tauri_shell::CommandErrorDto {
            code: "UPDATE_PREFERENCE_IO".into(),
            category: "UPDATER".into(),
            message: "The automatic update preference could not be persisted.".into(),
            retryable: true,
        }
    })?;
    persist_automatic_update_preference(&path, enabled).map_err(|_| {
        dom_wallet_tauri_shell::CommandErrorDto {
            code: "UPDATE_PREFERENCE_IO".into(),
            category: "UPDATER".into(),
            message: "The automatic update preference could not be persisted.".into(),
            retryable: true,
        }
    })?;
    updater.set_automatic_updates(enabled);
    Ok(updater.snapshot())
}

#[tauri::command]
async fn check_updates_now(handle: tauri::AppHandle) -> dom_wallet_tauri_shell::UpdateStatusDto {
    perform_update_cycle(handle, UpdateAction::Check).await
}

#[tauri::command]
async fn download_update_now(handle: tauri::AppHandle) -> dom_wallet_tauri_shell::UpdateStatusDto {
    perform_update_cycle(handle, UpdateAction::DownloadAndVerify).await
}

#[tauri::command]
async fn apply_update_now(
    handle: tauri::AppHandle,
    confirmed: bool,
) -> dom_wallet_tauri_shell::UpdateStatusDto {
    if !confirmed {
        handle
            .state::<UpdateControl>()
            .fail_wallet_check("UPDATE_APPLY_CONFIRMATION_REQUIRED");
        return handle.state::<UpdateControl>().snapshot();
    }
    perform_update_cycle(handle, UpdateAction::Apply).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateAction {
    Check,
    DownloadAndVerify,
    Apply,
}

impl UpdateAction {
    fn downloads(self) -> bool {
        matches!(self, Self::DownloadAndVerify)
    }

    fn installs_or_restarts(self) -> bool {
        matches!(self, Self::Apply)
    }
}

async fn perform_update_cycle(
    handle: tauri::AppHandle,
    action: UpdateAction,
) -> dom_wallet_tauri_shell::UpdateStatusDto {
    let updater_state = handle.state::<UpdateControl>();
    if !updater_state.begin_check(unix_seconds()) {
        return updater_state.snapshot();
    }
    let Some(public_key) = UPDATE_PUBLIC_KEY.filter(|key| !key.trim().is_empty()) else {
        updater_state.finish_check_without_key();
        return updater_state.snapshot();
    };
    let result = check_wallet_update(&handle, public_key, action).await;
    if let Err(error) = result {
        tracing::warn!(code = %error, "signed update check failed");
        updater_state.fail_wallet_check(error_code(error));
    }
    updater_state.snapshot()
}

async fn check_wallet_update(
    handle: &tauri::AppHandle,
    public_key: &str,
    action: UpdateAction,
) -> Result<(), UpdateError> {
    let endpoint = WALLET_UPDATE_ENDPOINT
        .parse()
        .map_err(|_| UpdateError::ManifestInvalid)?;
    let updater = handle
        .updater_builder()
        .pubkey(plugin_pubkey(public_key))
        .endpoints(vec![endpoint])
        .map_err(|_| UpdateError::CheckFailed)?
        .timeout(Duration::from_secs(20))
        .configure_client(|client| {
            client.redirect(reqwest13::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.stop();
                }
                if dom_wallet_updater::validate_release_url(attempt.url()).is_ok() {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
        })
        .build()
        .map_err(|_| UpdateError::CheckFailed)?;
    let Some(update) = updater
        .check()
        .await
        .map_err(|_| UpdateError::CheckFailed)?
    else {
        handle
            .state::<UpdateControl>()
            .finish_network_check(None, None);
        return Ok(());
    };
    let manifest_value = update
        .raw_json
        .get("dom_manifest")
        .cloned()
        .ok_or(UpdateError::ManifestInvalid)?;
    let manifest: WalletManifest =
        serde_json::from_value(manifest_value).map_err(|_| UpdateError::ManifestInvalid)?;
    let verifier = MinisignVerifier::from_base64(public_key)?;
    verify_wallet_manifest_signature(&manifest, &verifier)?;
    let policy = WalletPolicy {
        installed_version: env!("CARGO_PKG_VERSION"),
        update_channel: dom_wallet_updater::UPDATE_CHANNEL,
        target: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        network: "mainnet",
        wallet_schema: 2,
    };
    let decision = validate_wallet_manifest(&manifest, &policy, time::OffsetDateTime::now_utc())?;
    let artifact =
        dom_wallet_updater::select_artifact(&manifest, policy.target, policy.architecture)
            .ok_or(UpdateError::ManifestInvalid)?;
    if manifest.version != update.version
        || artifact.url.as_str() != update.download_url.as_str()
        || artifact.signature != update.signature
    {
        return Err(UpdateError::ManifestInvalid);
    }
    let WalletDecision::Available(version) = decision else {
        handle
            .state::<UpdateControl>()
            .finish_network_check(None, None);
        return Ok(());
    };
    if !action.downloads() && !action.installs_or_restarts() {
        handle
            .state::<UpdateControl>()
            .finish_network_check(Some(version.to_string()), None);
        return Ok(());
    }
    let state = handle.state::<UpdateControl>();
    let cache_root = handle
        .path()
        .app_cache_dir()
        .map_err(|_| UpdateError::StateIo)?;
    fs::create_dir_all(&cache_root).map_err(|_| UpdateError::StateIo)?;
    let staging_directory = cache_root.join("verified-updates");
    if !staging_directory.exists() {
        fs::create_dir(&staging_directory).map_err(|_| UpdateError::StateIo)?;
    }
    let staging_path = staging_directory.join("wallet-update.stage");
    validate_artifact_staging_destination(&staging_directory, &staging_path)?;
    if action.downloads() {
        state.set_wallet_download_state(WalletUpdaterState::Downloading, Some(0));
        if staging_path.exists() {
            fs::remove_file(&staging_path).map_err(|_| UpdateError::StateIo)?;
        }
        let verifier = MinisignVerifier::from_base64(public_key)?;
        download_verified_artifact_async(
            artifact,
            &verifier,
            &staging_directory,
            &staging_path,
            ArtifactDownloadTimeouts::default(),
        )
        .await?;
        state.finish_verified_download(version.to_string());
        return Ok(());
    }

    state.set_wallet_download_state(WalletUpdaterState::Verifying, Some(100));
    let verifier = MinisignVerifier::from_base64(public_key)?;
    let bytes = verify_staged_artifact(&staging_directory, &staging_path, artifact, &verifier)?;
    let application = handle.state::<DesktopApplication>();
    let lease = application
        .acquire_update_apply_lease()
        .map_err(|_| UpdateError::BusyCriticalOperation)?;
    state.set_wallet_download_state(WalletUpdaterState::Installing, Some(100));
    application
        .prepare_for_update(&lease)
        .map_err(|_| UpdateError::WalletPersistFailed)?;
    let _ = fs::remove_file(&staging_path);
    if update.install(bytes).is_err() {
        tracing::error!("Wallet installer failed; restarting the current signed version");
        handle.restart();
    }
    state.set_wallet_download_state(WalletUpdaterState::Restarting, Some(100));
    handle.restart();
}

fn error_code(error: UpdateError) -> &'static str {
    match error {
        UpdateError::CheckFailed => "UPDATE_CHECK_FAILED",
        UpdateError::ManifestInvalid => "UPDATE_MANIFEST_INVALID",
        UpdateError::SignatureInvalid => "UPDATE_SIGNATURE_INVALID",
        UpdateError::HashMismatch => "UPDATE_HASH_MISMATCH",
        UpdateError::SizeMismatch => "UPDATE_SIZE_MISMATCH",
        UpdateError::UnsupportedPlatform => "UPDATE_UNSUPPORTED_PLATFORM",
        UpdateError::DowngradeRejected => "UPDATE_DOWNGRADE_REJECTED",
        UpdateError::ChannelInvalid => "UPDATE_CHANNEL_INVALID",
        UpdateError::Expired => "UPDATE_MANIFEST_EXPIRED",
        UpdateError::OriginRejected => "UPDATE_ORIGIN_REJECTED",
        UpdateError::BusyCriticalOperation => "UPDATE_BUSY_CRITICAL_OPERATION",
        UpdateError::ConnectTimeout => "UPDATE_CONNECT_TIMEOUT",
        UpdateError::HeaderTimeout => "UPDATE_HEADER_TIMEOUT",
        UpdateError::InactivityTimeout => "UPDATE_INACTIVITY_TIMEOUT",
        UpdateError::TotalTimeout => "UPDATE_TOTAL_TIMEOUT",
        UpdateError::ArtifactTooLarge => "UPDATE_ARTIFACT_TOO_LARGE",
        UpdateError::ArtifactSizeMismatch => "UPDATE_ARTIFACT_SIZE_MISMATCH",
        UpdateError::UnsafePath => "UPDATE_STAGING_PATH_UNSAFE",
        UpdateError::StateIo => "UPDATE_STAGING_IO_FAILED",
        _ => "UPDATE_INSTALL_FAILED",
    }
}

#[tauri::command]
fn application_status(
    app: tauri::State<'_, DesktopApplication>,
) -> dom_wallet_tauri_shell::ApplicationStatusDto {
    app.application_status()
}
/// Root of the managed per-name wallet layout: `<app_data>/mainnet/wallets`.
fn managed_wallets_root(
    handle: &tauri::AppHandle,
) -> Result<std::path::PathBuf, dom_wallet_tauri_shell::CommandErrorDto> {
    Ok(handle
        .path()
        .app_data_dir()
        .map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "APP_DATA_DIRECTORY_UNAVAILABLE".into(),
            category: "PLATFORM".into(),
            message: "The platform application data directory is unavailable.".into(),
            retryable: false,
        })?
        .join("mainnet")
        .join("wallets"))
}

/// Resolve a validated wallet name inside the managed root, which must exist
/// before restore can stage next to its destination.
fn managed_wallet_path(
    handle: &tauri::AppHandle,
    name: &str,
) -> Result<std::path::PathBuf, dom_wallet_tauri_shell::CommandErrorDto> {
    let root = managed_wallets_root(handle)?;
    fs::create_dir_all(&root).map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
        code: "APP_DATA_DIRECTORY_UNAVAILABLE".into(),
        category: "PLATFORM".into(),
        message: "The managed wallets directory could not be prepared.".into(),
        retryable: true,
    })?;
    dom_wallet_tauri_shell::resolve_wallet_directory(&root, name).map_err(Into::into)
}

#[tauri::command]
fn wallet_create_recoverable(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    name: String,
    password: String,
) -> Result<dom_wallet_tauri_shell::RecoveryCreateDto, dom_wallet_tauri_shell::CommandErrorDto> {
    let path = managed_wallet_path(&handle, &name)?;
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_create_recoverable(path, &password)
        .map_err(Into::into)
}

#[tauri::command]
fn wallet_create_resume(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    name: String,
    password: String,
) -> Result<dom_wallet_tauri_shell::RecoveryCreateDto, dom_wallet_tauri_shell::CommandErrorDto> {
    let path = managed_wallet_path(&handle, &name)?;
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_create_resume(path, &password)
        .map_err(Into::into)
}

#[tauri::command]
fn wallet_create_abort(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    name: String,
    password: String,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    let path = managed_wallet_path(&handle, &name)?;
    app.wallet_create_abort(path, &password).map_err(Into::into)
}

#[tauri::command]
fn wallet_restore_from_mnemonic(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    name: String,
    password: String,
    mnemonic: String,
) -> Result<dom_wallet_tauri_shell::RestoreStartedDto, dom_wallet_tauri_shell::CommandErrorDto> {
    let password = Zeroizing::new(password);
    let mnemonic = Zeroizing::new(mnemonic);
    let path = managed_wallet_path(&handle, &name)?;
    // Restore is derivation-only and must NEVER be gated on a chain source
    // (see the regression guard on `wallet_restore_from_mnemonic`). When the
    // embedded node is the selected source it is merely nudged awake — the
    // start is asynchronous and its failure can never fail the restore.
    if app
        .chain_source_get()
        .map(|source| source.source == "EMBEDDED")
        .unwrap_or(true)
    {
        let _ = ensure_mainnet_node(&handle, &app);
    }
    app.wallet_restore_from_mnemonic(path, password.as_str(), mnemonic.as_str())
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_restore_staging_list(
    handle: tauri::AppHandle,
) -> Result<Vec<String>, dom_wallet_tauri_shell::CommandErrorDto> {
    Ok(dom_wallet_core_restore::discover_restore_stages(
        &managed_wallets_root(&handle)?,
    ))
}
#[tauri::command]
fn wallet_restore_abort(
    handle: tauri::AppHandle,
    name: String,
    password: String,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    let destination = managed_wallet_path(&handle, &name)?;
    dom_wallet_core_restore::abort_restore_stage(&destination, &password)
        .map_err(dom_wallet_tauri_shell::CommandError::from)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_backup_export(
    app: tauri::State<'_, DesktopApplication>,
    destination: String,
    backup_password: String,
) -> Result<dom_wallet_core::BackupStatus, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_backup_export(destination, &backup_password)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_backup_import(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    name: String,
    backup_path: String,
    backup_password: String,
    password: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    let destination = managed_wallet_path(&handle, &name)?;
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_backup_import(destination, backup_path, &backup_password, &password)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_recovery_phrase_confirm(
    app: tauri::State<'_, DesktopApplication>,
    password: String,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_recovery_phrase_confirm(&password)
        .map_err(Into::into)
}

#[tauri::command]
fn wallet_recovery_phrase_resume(
    app: tauri::State<'_, DesktopApplication>,
    password: String,
) -> Result<dom_wallet_tauri_shell::RecoveryCreateDto, dom_wallet_tauri_shell::CommandErrorDto> {
    let password = Zeroizing::new(password);
    app.wallet_recovery_phrase_resume(password.as_str())
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_open_named(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    name: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    let root = managed_wallets_root(&handle)?;
    ensure_mainnet_node(&handle, &app)?;
    app.wallet_open_managed(&root, &name).map_err(Into::into)
}
#[tauri::command]
fn wallet_recover_from_disk(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
    name: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.recover_managed_wallet_from_disk(&managed_wallets_root(&handle)?, &name)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_list(
    handle: tauri::AppHandle,
) -> Result<Vec<String>, dom_wallet_tauri_shell::CommandErrorDto> {
    Ok(dom_wallet_tauri_shell::list_wallet_names(
        &managed_wallets_root(&handle)?,
    ))
}
#[tauri::command]
fn wallet_unlock(
    app: tauri::State<'_, DesktopApplication>,
    password: String,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_unlock(&password).map_err(Into::into)
}
#[tauri::command]
fn wallet_lock(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_lock().map_err(Into::into)
}
#[tauri::command]
fn wallet_close(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_close().map_err(Into::into)
}
#[tauri::command]
fn wallet_summary(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_summary().map_err(Into::into)
}
#[tauri::command]
fn account_list(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<Vec<(uuid::Uuid, String)>, dom_wallet_tauri_shell::CommandErrorDto> {
    app.account_list().map_err(Into::into)
}
#[tauri::command]
fn account_summary(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.account_summary().map_err(Into::into)
}
#[tauri::command]
fn embedded_node_start(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    ensure_mainnet_node(&handle, &app)
}
#[tauri::command]
fn embedded_node_stop(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    app.embedded_node_stop().map_err(Into::into)
}
#[tauri::command]
fn embedded_node_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::EmbeddedNodeStatusDto, dom_wallet_tauri_shell::CommandErrorDto>
{
    app.embedded_node_status().map_err(Into::into)
}
#[tauri::command]
fn experimental_sidecar_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_node_manager::SidecarStatus, dom_wallet_tauri_shell::CommandErrorDto> {
    app.experimental_sidecar_status().map_err(Into::into)
}
#[tauri::command]
fn experimental_sidecar_enable(
    app: tauri::State<'_, DesktopApplication>,
    confirmation: String,
) -> Result<dom_wallet_node_manager::SidecarStatus, dom_wallet_tauri_shell::CommandErrorDto> {
    app.experimental_sidecar_enable(&confirmation)
        .map_err(Into::into)
}
#[tauri::command]
fn experimental_sidecar_disable(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_node_manager::SidecarStatus, dom_wallet_tauri_shell::CommandErrorDto> {
    app.experimental_sidecar_disable().map_err(Into::into)
}
#[tauri::command]
fn experimental_sidecar_start(
    handle: tauri::AppHandle,
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_node_manager::SidecarStatus, dom_wallet_tauri_shell::CommandErrorDto> {
    let data_directory = handle
        .path()
        .app_data_dir()
        .map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "APP_DATA_DIRECTORY_UNAVAILABLE".into(),
            category: "PLATFORM".into(),
            message: "The platform application data directory is unavailable.".into(),
            retryable: false,
        })?
        .join("mainnet")
        .join("sidecar-node");
    let rpc_address = reserve_loopback_address()?;
    let p2p_address = reserve_loopback_address()?;
    let seed_peers = dom_wallet_embedded_core::MAINNET_DNS_SEEDS
        .iter()
        .flat_map(|seed| {
            ((*seed, dom_wallet_embedded_core::MAINNET_P2P_PORT).to_socket_addrs())
                .into_iter()
                .flatten()
        })
        .collect();
    app.experimental_sidecar_start(ManagedNodeConfig {
        network: "mainnet".into(),
        data_directory,
        rpc_address,
        p2p_address,
        seed_peers,
    })
    .map_err(Into::into)
}
#[tauri::command]
fn experimental_sidecar_stop(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_node_manager::SidecarStatus, dom_wallet_tauri_shell::CommandErrorDto> {
    app.experimental_sidecar_stop().map_err(Into::into)
}
#[tauri::command]
fn experimental_sidecar_evaluate_release(
    app: tauri::State<'_, DesktopApplication>,
    node_feed_json: Option<String>,
    sidecar_manifest_json: Option<String>,
    sidecar_manifest_signature: Option<String>,
    platform: String,
) -> Result<dom_wallet_node_manager::NodeReleaseMetadata, dom_wallet_tauri_shell::CommandErrorDto> {
    app.experimental_sidecar_evaluate_release(
        node_feed_json.as_deref(),
        sidecar_manifest_json.as_deref(),
        sidecar_manifest_signature.as_deref(),
        &platform,
    )
    .map_err(Into::into)
}

fn reserve_loopback_address(
) -> Result<std::net::SocketAddr, dom_wallet_tauri_shell::CommandErrorDto> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "LOCAL_LISTENER_UNAVAILABLE".into(),
            category: "NODE".into(),
            message: "A private local node listener could not be reserved.".into(),
            retryable: true,
        })?;
    listener
        .local_addr()
        .map_err(|_| dom_wallet_tauri_shell::CommandErrorDto {
            code: "LOCAL_LISTENER_UNAVAILABLE".into(),
            category: "NODE".into(),
            message: "A private local node listener could not be reserved.".into(),
            retryable: true,
        })
}
#[tauri::command]
fn node_network_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::NodeNetworkStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.node_network_status().map_err(Into::into)
}
#[tauri::command]
fn node_peer_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::NodePeerStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.node_peer_status().map_err(Into::into)
}
#[tauri::command]
fn chain_source_get(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::ChainSourceStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.chain_source_get().map_err(Into::into)
}
#[tauri::command]
fn chain_source_set(
    app: tauri::State<'_, DesktopApplication>,
    source: String,
    base_url: Option<String>,
    bearer_token: Option<String>,
) -> Result<dom_wallet_tauri_shell::ChainSourceStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    let bearer_token = bearer_token.map(Zeroizing::new);
    app.chain_source_set(
        source.as_str(),
        base_url.as_deref(),
        bearer_token.as_ref().map(|token| token.as_str()),
    )
    .map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_sync_status().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_start(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_start_live().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_pause(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_pause().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_resume(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_resume_live().map_err(Into::into)
}
#[tauri::command]
fn wallet_sync_retry(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_resume_live().map_err(Into::into)
}
#[tauri::command]
fn wallet_rescan(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_rescan().map_err(Into::into)
}
#[tauri::command]
fn mining_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::MiningStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_status().map_err(Into::into)
}
#[tauri::command]
fn mining_config_get(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::MiningConfigDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_config_get().map_err(Into::into)
}
#[tauri::command]
fn mining_config_set(
    app: tauri::State<'_, DesktopApplication>,
    enabled: bool,
    cpu_threads: usize,
) -> Result<dom_wallet_tauri_shell::MiningConfigDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_config_set(enabled, cpu_threads)
        .map_err(Into::into)
}
#[tauri::command]
fn mining_start(
    app: tauri::State<'_, DesktopApplication>,
    confirmed: bool,
) -> Result<dom_wallet_tauri_shell::MiningStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_start(confirmed).map_err(Into::into)
}
#[tauri::command]
fn mining_stop(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::MiningStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.mining_stop().map_err(Into::into)
}
#[tauri::command]
fn diagnostics_redacted(
    app: tauri::State<'_, DesktopApplication>,
) -> dom_wallet_core::DiagnosticSnapshot {
    app.diagnostics_redacted()
}
#[tauri::command]
fn synchronization_pause(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_pause().map_err(Into::into)
}
#[tauri::command]
fn synchronization_start(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_start_live().map_err(Into::into)
}
#[tauri::command]
fn synchronization_resume(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_resume_live().map_err(Into::into)
}
#[tauri::command]
fn synchronization_retry(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::WalletSyncStatusDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_start_live().map_err(Into::into)
}
#[tauri::command]
fn synchronization_rescan(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_core::WalletSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.synchronization_rescan().map_err(Into::into)
}
#[tauri::command]
fn application_shutdown(
    window: tauri::Window,
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.application_shutdown()
        .map_err(dom_wallet_tauri_shell::CommandErrorDto::from)?;
    window.app_handle().exit(0);
    Ok(())
}

#[tauri::command]
fn transaction_fee_estimate(
    app: tauri::State<'_, DesktopApplication>,
    amount: u64,
    selected_input_count: u32,
    change_output: bool,
) -> Result<dom_wallet_core::FeeEstimate, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_fee_estimate(amount, selected_input_count, change_output)
        .map_err(Into::into)
}
#[tauri::command]
fn wallet_address_validate(
    app: tauri::State<'_, DesktopApplication>,
    address: String,
) -> Result<String, dom_wallet_tauri_shell::CommandErrorDto> {
    app.wallet_address_validate(&address).map_err(Into::into)
}
#[tauri::command]
fn transaction_send_create(
    app: tauri::State<'_, DesktopApplication>,
    amount: u64,
    requested_fee: Option<u64>,
    expires_at_height: u64,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_send_create(amount, requested_fee, expires_at_height)
        .map_err(Into::into)
}
#[tauri::command]
fn slate_request_export(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::SlateExport, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_request_export(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_request_import(
    app: tauri::State<'_, DesktopApplication>,
    text: String,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_request_import(&text).map_err(Into::into)
}
#[tauri::command]
fn slate_response_create(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_response_create(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_response_export(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::SlateExport, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_response_export(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_response_import(
    app: tauri::State<'_, DesktopApplication>,
    text: String,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_response_import(&text).map_err(Into::into)
}
#[tauri::command]
fn slate_summary_redacted(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_summary_redacted(slate_id).map_err(Into::into)
}
#[tauri::command]
fn transaction_finalize(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_finalize(slate_id).map_err(Into::into)
}
#[tauri::command]
fn transaction_submit(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_tauri_shell::SubmissionResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_submit(slate_id).map_err(Into::into)
}
#[tauri::command]
fn transaction_retry_submission(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_tauri_shell::SubmissionResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_retry_submission(slate_id)
        .map_err(Into::into)
}
#[tauri::command]
fn transaction_reconcile_submission(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_tauri_shell::SubmissionResultDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_reconcile_submission(slate_id)
        .map_err(Into::into)
}
#[tauri::command]
fn transaction_cancel(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
    confirm_exported: bool,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_cancel(slate_id, confirm_exported)
        .map_err(Into::into)
}
#[tauri::command]
fn slate_cancel(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
    confirm_exported: bool,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_cancel(slate_id, confirm_exported)
        .map_err(Into::into)
}
#[tauri::command]
fn transaction_list(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<Vec<dom_wallet_core::TransactionSummary>, dom_wallet_tauri_shell::CommandErrorDto> {
    app.transaction_list().map_err(Into::into)
}
#[tauri::command]
fn transaction_detail_redacted(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
) -> Result<dom_wallet_core::TransactionSummary, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_summary_redacted(slate_id).map_err(Into::into)
}
#[tauri::command]
fn slate_qr_encode(
    app: tauri::State<'_, DesktopApplication>,
    slate_id: uuid::Uuid,
    response: bool,
) -> Result<dom_wallet_tauri_shell::SlateQrExportDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_encode(slate_id, response).map_err(Into::into)
}
#[tauri::command]
fn slate_qr_decode_frame(
    app: tauri::State<'_, DesktopApplication>,
    frame: String,
) -> Result<dom_wallet_tauri_shell::SlateQrReassemblyDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_decode_frame(&frame).map_err(Into::into)
}
#[tauri::command]
fn slate_qr_reassembly_status(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<dom_wallet_tauri_shell::SlateQrReassemblyDto, dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_reassembly_status().map_err(Into::into)
}
#[tauri::command]
fn slate_qr_reassembly_clear(
    app: tauri::State<'_, DesktopApplication>,
) -> Result<(), dom_wallet_tauri_shell::CommandErrorDto> {
    app.slate_qr_reassembly_clear().map_err(Into::into)
}

macro_rules! tauri_command_handler {
    ($($command:ident),+ $(,)?) => {
        tauri::generate_handler![$($command),+]
    };
}

fn application_builder() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(UPDATE_PUBLIC_KEY.map(plugin_pubkey).unwrap_or_default())
                .build(),
        )
        .manage(UpdateControl::new(
            UPDATE_PUBLIC_KEY.is_some_and(|key| !key.trim().is_empty()),
        ))
        .manage(DesktopApplication::default())
        .setup(|app| {
            initialize_file_logging(app);
            if let Ok(path) = automatic_update_preference_path(app.handle()) {
                app.state::<UpdateControl>()
                    .set_automatic_updates(load_automatic_update_preference(&path));
            }
            // Bind the persistent app-config directory before anything can read
            // the chain source, so a saved REMOTE selection (and the embedded
            // node map size) survives the restart instead of silently
            // reverting to the embedded default.
            if let Ok(config_directory) = app.path().app_config_dir() {
                if fs::create_dir_all(&config_directory).is_ok() {
                    let _ = app
                        .state::<DesktopApplication>()
                        .configure_app_config_storage(config_directory);
                }
            }
            // The embedded validating node starts with the application, not
            // with wallet creation. A saved remote scan-only source remains
            // authoritative and does not start the local node unnecessarily.
            if app
                .state::<DesktopApplication>()
                .chain_source_get()
                .map(|source| source.source == "EMBEDDED")
                .unwrap_or(true)
            {
                let handle = app.handle().clone();
                let application = app.state::<DesktopApplication>();
                let _ = ensure_mainnet_node(&handle, &application);
            }
            let runtime_root = app
                .path()
                .app_local_data_dir()?
                .join("runtime")
                .join("managed-sidecar");
            app.state::<DesktopApplication>()
                .configure_sidecar_runtime(runtime_root)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let jitter = unix_seconds() % (MAX_INITIAL_JITTER_SECONDS + 1);
                tokio::time::sleep(Duration::from_secs(jitter)).await;
                loop {
                    if handle.state::<UpdateControl>().snapshot().automatic_updates {
                        let _ = perform_update_cycle(handle.clone(), UpdateAction::Check).await;
                    }
                    tokio::time::sleep(Duration::from_secs(UPDATE_INTERVAL_SECONDS)).await;
                }
            });
            Ok(())
        })
        .invoke_handler(dom_wallet_tauri_shell::wallet_command_registry!(
            tauri_command_handler
        ))
}

fn main() {
    let Ok(app) = application_builder().build(tauri::generate_context!()) else {
        std::process::exit(1);
    };
    app.run(|handle, event| match event {
        tauri::RunEvent::Resumed => {
            let handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                if handle.state::<UpdateControl>().snapshot().automatic_updates {
                    let _ = perform_update_cycle(handle, UpdateAction::Check).await;
                }
            });
        }
        tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. } => {
            let _ = handle.state::<DesktopApplication>().application_shutdown();
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_entrypoint_constructs_the_registered_builder() {
        let _builder = application_builder();
        assert!(!dom_wallet_tauri_shell::COMMAND_NAMES.is_empty());
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"native_bridge_status"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"check_updates_now"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"embedded_node_stop"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"slate_cancel"));
    }

    #[test]
    fn regression_m5_check_download_apply_and_preference_are_distinct() {
        assert_ne!(UpdateAction::Check, UpdateAction::DownloadAndVerify);
        assert_ne!(UpdateAction::DownloadAndVerify, UpdateAction::Apply);
        assert!(!UpdateAction::Check.downloads());
        assert!(!UpdateAction::Check.installs_or_restarts());
        assert!(UpdateAction::DownloadAndVerify.downloads());
        assert!(!UpdateAction::DownloadAndVerify.installs_or_restarts());
        assert!(!UpdateAction::Apply.downloads());
        assert!(UpdateAction::Apply.installs_or_restarts());
        let directory = tempfile::tempdir().expect("preference directory");
        let path = directory.path().join("preference.json");
        persist_automatic_update_preference(&path, false).expect("persist preference");
        assert!(!load_automatic_update_preference(&path));
        persist_automatic_update_preference(&path, true).expect("replace preference");
        assert!(load_automatic_update_preference(&path));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"check_updates_now"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"download_update_now"));
        assert!(dom_wallet_tauri_shell::COMMAND_NAMES.contains(&"apply_update_now"));
    }
}

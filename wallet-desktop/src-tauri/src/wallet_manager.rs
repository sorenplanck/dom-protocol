//! Wallet state manager (engine: dom-wallet2 v2).
//!
//! Wraps `dom_wallet2::WalletV2State` — the v2 persistent store where each owned
//! output is a single `StoredOutput` whose blinding is ALWAYS persisted (the
//! property v1 lacked; see `docs/WALLET_V2_DESIGN.md`). We REUSE the whole v2
//! engine (create/restore/balance/send/receive/finalize/submit/sync) and the
//! shared `dom-wallet-keys` BIP-39 seed; this module only exposes the operations
//! the UI needs and keeps the decrypted state inside the Rust backend.
//!
//! V2 vs V1 surface, as adapted here:
//!   * The vault is a SINGLE encrypted file (`save_wallet_state`/
//!     `load_wallet_state`), not a directory. There is no in-memory lock concept
//!     in the crate: "unlocked" = the state is loaded and we hold the password
//!     (needed to re-save on every mutation); "locked" = the state/password are
//!     dropped and zeroized, the on-disk path remembered so `unlock` can reload.
//!   * Chain sync is reconciliation over the node's `GET /chain/scan` via
//!     `RpcChainSource` (a `ChainSource` + `TxSink`); submission is
//!     `submit_finalized` over the same source. Both `/chain/scan` and
//!     `/tx/submit` are the node's PUBLIC (no-bearer) routes, so the source needs
//!     no token — matching v1, the RPC calls are blocking and run inline.
//!
//! SECURITY:
//!   * The decrypted `WalletV2State` and the password live only here, behind a
//!     `Mutex`. The seed *bytes* and derived private keys never cross the Tauri
//!     IPC boundary.
//!   * The BIP-39 *mnemonic phrase* is the one exception: it crosses the IPC
//!     boundary EXACTLY ONCE, at wallet creation, so the onboarding UI can force
//!     the user to write it down (see `create_new`). It is never persisted by the
//!     frontend and the renderer scrubs it after confirmation. After creation the
//!     words are not re-derivable from the opened wallet (only the seed bytes are
//!     stored).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::Slate;
use dom_wallet::Network as V1Network;
use dom_wallet2::{
    cancel as v2_cancel, create_send as v2_create_send,
    export_full_backup as v2_export_full_backup, finalize_tracked as v2_finalize_tracked,
    import_full_backup as v2_import_full_backup, load_wallet_state, receive as v2_receive,
    restore_coinbase_from_seed, save_wallet_state, submit_finalized as v2_submit_finalized,
    ChainSource, DerivIndex, KeychainDeriver, Network as V2Network, OutputOrigin, OutputStatus,
    ReconcileReport, RpcChainSource, RpcSourceError, StoredOutput, SubmitError, WalletV2State,
};
use dom_wallet_keys::seed::{Bip39Seed, SeedAcceptance};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::auto_backup::{assess_login_password_strength, derive_auto_backup_passphrase};
use crate::settings::NodeSettings;

/// Per-request timeout for the node RPC source (mirrors v1's 10s default).
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// R-31(b) freshness policy: minimum gap (in blocks) between the node tip and the
/// store's `last_reconciled_tip` that forces a sync before a send. `1` means
/// "sync whenever the node is ahead at all"; a fresh store skips the scan and the
/// send pays only one cheap `tip()` round-trip.
const STALE_TIP_THRESHOLD: u64 = 1;

/// A receive descriptor flattened for the auto-sweep / UI (the crate types are
/// not all Serialize, and v2's `ReceiveRequest` is thinner than v1's descriptor).
#[derive(Clone, serde::Serialize)]
pub struct ReceiveInfo {
    pub index: u32,
    pub amount: u64,
    pub commitment_hex: String,
    // The receive blinding is DERIVABLE from the seed (unlike v1, where it was a
    // descriptor field). The auto-sweep hands it to the node's `/wallet/spend`
    // over the local, bearer-authenticated RPC so the node can build the output.
    pub blinding_hex: String,
}

/// Non-sensitive metadata about the currently-open wallet, used to populate a
/// Wallet Registry entry. Contains NO secret material — just the vault location
/// and the wallet's network.
#[derive(Clone)]
pub struct OpenWalletMeta {
    pub vault_path: String,
    pub network: String,
}

/// Balance breakdown for the dashboard, all in noms.
#[derive(Clone, Copy, serde::Serialize)]
pub struct BalanceInfo {
    pub total: u64,
    pub spendable: u64,
    pub confirmed: u64,
    pub immature: u64,
}

/// Result of a recover/sync pass, surfaced to the UI by `wallet_rescan`.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct RescanSummary {
    pub scanned_tip: u64,
    pub recovered: usize,
    pub confirmed: usize,
    pub spent: usize,
    pub reorged: usize,
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct PendingResubmitReport {
    pub attempted: usize,
    pub submitted: usize,
    pub already_in_mempool: usize,
    pub retry_later: usize,
    pub failed: usize,
}

/// Outcome of restoring a full backup into a brand-new vault file. Carries NO
/// secret material — only non-sensitive counts and the new vault's location so
/// the UI can open it. The restored seed/blindings stay inside the saved file,
/// never crossing back over IPC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportedSummary {
    /// Filesystem path of the freshly written vault (never the open wallet's).
    pub vault_path: String,
    /// Network of the restored wallet ("mainnet"/"testnet"/"regtest").
    pub network: String,
    /// Number of outputs recovered into the new vault.
    pub outputs: usize,
    /// Number of pending slates recovered.
    pub pending_slates: usize,
    /// Reconciliation tip carried by the backup (informational).
    pub last_reconciled_tip: u64,
}

/// Which auto-backup destination a failure refers to. Drives the severity the
/// UI shows: a LOCAL failure is a strong error (the local target lives next to
/// the vault and should almost never fail); an EXTERNAL failure is usually just
/// "destination unavailable" (removable drive removed, synced folder offline) and
/// is surfaced as a warning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupTarget {
    Local,
    External,
}

impl BackupTarget {
    /// Stable wire string for the emitted event payload.
    pub fn as_str(self) -> &'static str {
        match self {
            BackupTarget::Local => "local",
            BackupTarget::External => "external",
        }
    }

    /// Severity for the UI: local failures are errors, external are warnings.
    pub fn severity(self) -> &'static str {
        match self {
            BackupTarget::Local => "error",
            BackupTarget::External => "warning",
        }
    }
}

/// Sink for auto-backup failure notifications. Abstracted away from Tauri so the
/// backup controller never depends on `AppHandle` directly and so tests can
/// capture emitted failures without a running app. The production sink (in
/// `lib.rs`) emits `"auto-backup-failed"` via the app handle; the default is a
/// no-op (used before the app sets a real sink, and in unit tests that don't
/// assert on events).
pub trait BackupEventSink: Send + Sync {
    /// Report that a backup write to `target` failed, with a human reason. The
    /// auto-backup path is best-effort, so this NEVER affects a vault save.
    fn backup_failed(&self, target: BackupTarget, reason: String);
}

/// Default sink: drops failures (no UI wired). Replaced at app setup.
struct NoopBackupSink;
impl BackupEventSink for NoopBackupSink {
    fn backup_failed(&self, _target: BackupTarget, _reason: String) {}
}

/// Auto-backup configuration for an open wallet. Non-sensitive: holds no
/// password/key. `enabled` gates ALL auto-backup (local + external);
/// `external_dir` is the optional external destination FOLDER (None = local
/// only). Mirrors the two `NodeSettings` fields persisted on disk.
#[derive(Clone, Default)]
pub struct AutoBackupConfig {
    pub enabled: bool,
    pub external_dir: Option<PathBuf>,
}

/// A loaded, decrypted wallet plus the material needed to re-save it. The
/// password is held (zeroized on drop) because every v2 mutation persists via
/// `save_wallet_state(state, path, password)`.
struct OpenWallet {
    state: WalletV2State,
    path: PathBuf,
    password: Zeroizing<String>,
    network: V2Network,
    /// Local auto-backup controller (ETAPA 2): refreshes `<vault>.dombak` on
    /// material funds changes, off-lock and best-effort. Shared via `Arc` so the
    /// spawned write task can outlive the borrow of `self` in `save`.
    backup: Arc<LocalBackup>,
}

impl OpenWallet {
    /// Build an open wallet and its local auto-backup controller. The controller
    /// is seeded with the current funds fingerprint so an immediate, non-material
    /// save (e.g. the create/restore persist) does not write a redundant backup.
    fn new(
        state: WalletV2State,
        path: PathBuf,
        password: Zeroizing<String>,
        network: V2Network,
        config: AutoBackupConfig,
        sink: Arc<dyn BackupEventSink>,
    ) -> Self {
        let dombak = local_backup_path(&path);
        let initial_fp = funds_fingerprint(&state);
        let backup = Arc::new(LocalBackup::new(dombak, initial_fp, config, sink));
        Self {
            state,
            path,
            password,
            network,
            backup,
        }
    }

    /// Persist the current state to disk under the held password, then refresh
    /// the local auto-backup if (and only if) the funds changed materially.
    ///
    /// The vault persist is the source of truth: it runs first and its result is
    /// what `save` returns. The backup is strictly best-effort and NEVER changes
    /// that result — a backup failure cannot fail a vault save. The heavy work
    /// (Argon2id inside `export_full_backup`) runs OFF this call's lock, on a
    /// `spawn_blocking` thread, so it never blocks the async reactor or the UI.
    fn save(&self) -> Result<()> {
        save_wallet_state(&self.state, &self.path, self.password.as_str())
            .map_err(|e| anyhow!("save wallet: {e}"))?;
        self.trigger_local_backup_if_material();
        Ok(())
    }

    /// Fire a local auto-backup iff the funds fingerprint changed since the last
    /// one. Off-lock: it clones the snapshot and derives the passphrase here
    /// (both cheap), then runs the encrypt+write on a blocking thread. Bursts are
    /// coalesced (only the latest snapshot is written) and writers are serialized
    /// so two backups never race on the shared temp path of the atomic write.
    fn trigger_local_backup_if_material(&self) {
        if !self.backup.is_enabled() {
            return; // auto-backup turned off in Settings → do nothing
        }
        let fp = funds_fingerprint(&self.state);
        let Some(seq) = self.backup.note_material(fp) else {
            return; // non-material save (metadata / slate status / sync tip)
        };
        let state = self.state.clone();
        let passphrase = derive_auto_backup_passphrase(self.password.as_str());
        let exported_at = now_unix();
        let backup = Arc::clone(&self.backup);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let job = handle
                    .spawn_blocking(move || backup.write(seq, &state, &passphrase, exported_at));
                self.backup.set_in_flight(job);
            }
            Err(_) => {
                // No async runtime (unit tests): run inline, deterministically.
                backup.write(seq, &state, &passphrase, exported_at);
            }
        }
    }
}

/// Local auto-backup path for a vault: `<vault>.dombak`, alongside the vault
/// file. The suffix is appended to the full vault name so it can never collide
/// with the vault itself.
fn local_backup_path(vault: &Path) -> PathBuf {
    let mut name = vault.as_os_str().to_owned();
    name.push(".dombak");
    PathBuf::from(name)
}

/// Seconds since the Unix epoch (informational `exported_at` stamp; `0` if the
/// clock is before the epoch).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(mut h: u64, byte: u8) -> u64 {
    h ^= byte as u64;
    h.wrapping_mul(FNV_PRIME)
}

fn fnv1a_bytes(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h = fnv1a(h, b);
    }
    h
}

fn status_code(s: OutputStatus) -> u8 {
    match s {
        OutputStatus::Unconfirmed => 1,
        OutputStatus::Confirmed => 2,
        OutputStatus::Spent => 3,
        OutputStatus::Reorged => 4,
    }
}

/// A cheap, order-independent fingerprint of the wallet's FUNDS (the output set),
/// used to decide whether a save changed funds materially. It folds each
/// output's commitment (identity), value and status, so a new output, a spend, a
/// confirmation or a value change all flip it. The reconciliation tip and
/// in-flight slates are deliberately EXCLUDED — a sync that only advances the
/// tip, or a slate-status-only save, is not a funds change and must not trigger a
/// backup. The fold is commutative (`wrapping_add`) so iteration order is
/// irrelevant; commitments are unique in the store, so per-output sub-hashes do
/// not cancel.
fn funds_fingerprint(state: &WalletV2State) -> u64 {
    let mut acc: u64 = 0;
    let mut count: u64 = 0;
    for o in state.outputs.iter() {
        let mut h = FNV_OFFSET;
        h = fnv1a_bytes(h, &o.commitment);
        h = fnv1a_bytes(h, &o.value.to_le_bytes());
        h = fnv1a(h, status_code(o.status));
        acc = acc.wrapping_add(h);
        count = count.wrapping_add(1);
    }
    acc ^ count.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Compute the external backup file path inside the user-chosen folder:
/// `<external_dir>/<vault-file-name>.dombak`, mirroring the local naming so a
/// folder can hold backups of several wallets without collision.
fn external_target_path(external_dir: &Path, local_dombak: &Path) -> PathBuf {
    let file = local_dombak
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("wallet.dombak"));
    external_dir.join(file)
}

/// Probe whether `dir` is present and writable, returning a human reason when
/// not. Cheap: avoids spending Argon2id on an unavailable target (removable drive
/// removed, synced folder offline, read-only, or full). Uses `try_exists` plus a
/// tiny create+remove temp-file probe — the "escrita de temp" availability check.
fn external_availability(dir: &Path) -> Result<(), String> {
    match dir.try_exists() {
        Ok(true) => {}
        Ok(false) => return Err("destino externo indisponível (pasta não encontrada)".to_string()),
        Err(e) => return Err(format!("destino externo indisponível: {e}")),
    }
    let probe = dir.join(".dom-autobak-probe");
    let written = std::fs::File::create(&probe).and_then(|mut f| {
        use std::io::Write as _;
        f.write_all(b"x")
    });
    match written {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(format!("destino externo não gravável: {e}")),
    }
}

/// Auto-backup controller for one open wallet. Writes the local backup always and
/// the optional external backup when a destination folder is configured; both are
/// best-effort and never block the UI or fail a vault save.
///
/// Responsibilities:
///   * **Materiality** — [`LocalBackup::note_material`] returns a write `seq`
///     only when the funds fingerprint changed; it touches only atomics, so the
///     hot path (under the wallet lock) never blocks on a backup in progress.
///   * **Coalescing** — a burst of material saves bumps `latest_seq`; only the
///     latest snapshot is actually written (older spawned writes skip).
///   * **Serialization** — `write_lock` is held across the encrypt+write, so two
///     backups never race on the shared `.tmp` temp path of the underlying atomic
///     write. It is contended only between off-reactor write tasks — never by the
///     hot path.
///   * **Failure reporting** — a failed write emits through `sink` with a
///     [`BackupTarget`] so the UI can differentiate severity (local = error,
///     external = warning). A local success still counts even if the external
///     write fails.
struct LocalBackup {
    /// Whether auto-backup is on at all. When off, the trigger does nothing
    /// (neither local nor external). Toggled from Settings.
    enabled: AtomicBool,
    /// Local destination: `<vault>.dombak`, written on every material save while
    /// enabled.
    path: PathBuf,
    /// Optional external destination FOLDER; the file is
    /// `<external_dir>/<vault-file-name>.dombak`. Behind a mutex so the Settings
    /// flow can update it on the open wallet.
    external_dir: std::sync::Mutex<Option<PathBuf>>,
    /// Funds fingerprint of the most recent material observation.
    last_seen_fp: AtomicU64,
    /// Monotonic request counter; each material save takes the next value.
    seq: AtomicU64,
    /// Highest `seq` requested so far (coalescing: older writes skip).
    latest_seq: AtomicU64,
    /// Count of LOCAL backups actually written (observability / tests).
    writes: AtomicU64,
    /// Count of EXTERNAL backups actually written (observability / tests).
    external_writes: AtomicU64,
    /// Held across the encrypt+write to serialize writers (off-reactor only).
    write_lock: std::sync::Mutex<()>,
    /// Handle to the most recent in-flight write, so it can be awaited on
    /// shutdown / in tests. Replacing it does NOT cancel the task —
    /// `spawn_blocking` tasks run to completion.
    in_flight: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Where backup failures are reported (Tauri event in production, a recorder
    /// in tests, a no-op by default).
    sink: Arc<dyn BackupEventSink>,
}

impl LocalBackup {
    fn new(
        path: PathBuf,
        initial_fp: u64,
        config: AutoBackupConfig,
        sink: Arc<dyn BackupEventSink>,
    ) -> Self {
        Self {
            enabled: AtomicBool::new(config.enabled),
            path,
            external_dir: std::sync::Mutex::new(config.external_dir),
            last_seen_fp: AtomicU64::new(initial_fp),
            seq: AtomicU64::new(0),
            latest_seq: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            external_writes: AtomicU64::new(0),
            write_lock: std::sync::Mutex::new(()),
            in_flight: std::sync::Mutex::new(None),
            sink,
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Apply a new auto-backup config (from the Settings flow) to the open
    /// wallet: on/off and the external destination folder.
    fn set_config(&self, config: AutoBackupConfig) {
        self.enabled.store(config.enabled, Ordering::SeqCst);
        *self.external_dir.lock().expect("poisoned") = config.external_dir;
    }

    /// If `fp` differs from the last observed funds fingerprint, record it and
    /// return the write `seq` to use; otherwise return `None` (non-material).
    /// Lock-free (atomics only): saves are serialized by the wallet lock, so this
    /// is never called concurrently with itself, and it never blocks on a write.
    fn note_material(&self, fp: u64) -> Option<u64> {
        let prev = self.last_seen_fp.swap(fp, Ordering::SeqCst);
        if prev == fp {
            return None;
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.latest_seq.store(seq, Ordering::SeqCst);
        Some(seq)
    }

    fn set_in_flight(&self, job: JoinHandle<()>) {
        if let Ok(mut slot) = self.in_flight.lock() {
            *slot = Some(job);
        }
    }

    /// Encrypt + write the snapshot to the local backup and, when configured, the
    /// external backup. Both writes are atomic (the underlying `save_envelope`
    /// does temp → fsync → rename → dir-fsync, so a crash mid-write cannot
    /// truncate the previous backup). Best-effort: a failure is reported through
    /// `sink` and NEVER affects the vault save. The external write is independent
    /// of the local one — a local success still counts if the external fails.
    /// Coalesced: if a newer `seq` was requested while this one waited for the
    /// lock, this write is skipped.
    fn write(&self, seq: u64, state: &WalletV2State, passphrase: &str, exported_at: u64) {
        if seq < self.latest_seq.load(Ordering::SeqCst) {
            return; // superseded before we even started → coalesce
        }
        let _guard = self
            .write_lock
            .lock()
            .expect("auto-backup write lock poisoned");
        if seq < self.latest_seq.load(Ordering::SeqCst) {
            return; // a newer write ran while we waited → coalesce
        }

        // LOCAL — always. A failure here is a strong error (target lives beside
        // the vault and should almost never fail).
        match v2_export_full_backup(state, &self.path, passphrase, exported_at) {
            Ok(()) => {
                self.writes.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                self.sink.backup_failed(BackupTarget::Local, format!("{e}"));
            }
        }

        // EXTERNAL — only if configured; independent of the local result.
        let external_dir = self.external_dir.lock().expect("poisoned").clone();
        if let Some(dir) = external_dir {
            match self.write_external(&dir, state, passphrase, exported_at) {
                Ok(()) => {
                    self.external_writes.fetch_add(1, Ordering::SeqCst);
                }
                Err(reason) => {
                    self.sink.backup_failed(BackupTarget::External, reason);
                }
            }
        }
    }

    /// Write the external backup into the configured folder, after a cheap
    /// availability probe (so an unavailable drive is reported as such instead of
    /// wasting Argon2id). Returns a human reason on failure.
    fn write_external(
        &self,
        dir: &Path,
        state: &WalletV2State,
        passphrase: &str,
        exported_at: u64,
    ) -> Result<(), String> {
        external_availability(dir)?;
        let target = external_target_path(dir, &self.path);
        v2_export_full_backup(state, &target, passphrase, exported_at).map_err(|e| format!("{e}"))
    }

    #[cfg(test)]
    fn writes(&self) -> u64 {
        self.writes.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn external_writes(&self) -> u64 {
        self.external_writes.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn take_in_flight(&self) -> Option<JoinHandle<()>> {
        self.in_flight.lock().unwrap().take()
    }

    #[cfg(test)]
    fn external_dir(&self) -> Option<PathBuf> {
        self.external_dir.lock().unwrap().clone()
    }
}

/// The wallet slot: empty, locked (path remembered), or unlocked (state loaded).
///
/// The unlocked state carries the whole `WalletV2State` (the output store), so
/// it is boxed to keep the enum small (clippy `large_enum_variant`).
enum Slot {
    Empty,
    Locked { path: PathBuf, network: V2Network },
    Unlocked(Box<OpenWallet>),
}

pub struct WalletManager {
    inner: Mutex<Slot>,
    /// Sink for auto-backup failure notifications, shared into each open wallet's
    /// backup controller. Defaults to a no-op until the app installs a real sink
    /// (see [`WalletManager::set_event_sink`]).
    event_sink: std::sync::Mutex<Arc<dyn BackupEventSink>>,
}

impl WalletManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Slot::Empty),
            event_sink: std::sync::Mutex::new(Arc::new(NoopBackupSink)),
        }
    }

    /// Install the auto-backup failure sink (called once at app setup with a
    /// Tauri-backed sink). Wallets opened after this point report failures
    /// through it.
    pub fn set_event_sink(&self, sink: Arc<dyn BackupEventSink>) {
        *self.event_sink.lock().expect("event sink mutex poisoned") = sink;
    }

    /// Clone of the current failure sink, to hand to a newly opened wallet.
    fn event_sink(&self) -> Arc<dyn BackupEventSink> {
        Arc::clone(&self.event_sink.lock().expect("event sink mutex poisoned"))
    }

    /// Apply an auto-backup config to the OPEN wallet (the Settings flow). This
    /// closes the open/unlock gap: it works for reopened wallets, not just
    /// freshly created ones.
    ///
    /// Security gate: enabling an EXTERNAL destination requires a strong login
    /// password, because the encrypted seed then leaves the machine protected by
    /// that password alone. The strength is checked on the password the wallet
    /// already holds (never re-transmitted), and a weak password is REJECTED with
    /// the reason — without changing any config. The LOCAL backup needs no such
    /// gate (the seed never leaves the machine).
    pub async fn set_auto_backup(
        &self,
        enabled: bool,
        external_dir: Option<PathBuf>,
    ) -> Result<()> {
        let guard = self.inner.lock().await;
        let ow = self.unlocked(&guard)?;
        if enabled && external_dir.is_some() {
            assess_login_password_strength(ow.password.as_str()).map_err(|e| anyhow!("{e}"))?;
        }
        // When disabled, drop any external target too (no backups at all).
        let config = AutoBackupConfig {
            enabled,
            external_dir: if enabled { external_dir } else { None },
        };
        ow.backup.set_config(config);
        Ok(())
    }

    pub async fn is_open(&self) -> bool {
        !matches!(&*self.inner.lock().await, Slot::Empty)
    }

    pub async fn is_unlocked(&self) -> bool {
        matches!(&*self.inner.lock().await, Slot::Unlocked(_))
    }

    /// Non-sensitive metadata about the open wallet, for the Wallet Registry.
    /// Returns `None` when no wallet is open.
    pub async fn open_wallet_meta(&self) -> Option<OpenWalletMeta> {
        match &*self.inner.lock().await {
            Slot::Empty => None,
            Slot::Locked { path, network } => Some(OpenWalletMeta {
                vault_path: path.to_string_lossy().to_string(),
                network: network_str(*network),
            }),
            Slot::Unlocked(ow) => Some(OpenWalletMeta {
                vault_path: ow.path.to_string_lossy().to_string(),
                network: network_str(ow.network),
            }),
        }
    }

    /// The network of the currently-open wallet, if any (M2). Used to refuse
    /// starting the node on a network that doesn't match the open wallet. Mapped
    /// to the v1 `Network` enum the rest of the desktop (settings) speaks.
    pub async fn wallet_network(&self) -> Option<V1Network> {
        match &*self.inner.lock().await {
            Slot::Empty => None,
            Slot::Locked { network, .. } => Some(v2_to_v1_network(*network)),
            Slot::Unlocked(ow) => Some(v2_to_v1_network(ow.network)),
        }
    }

    /// Create a brand-new deterministic wallet from a freshly generated BIP-39
    /// seed. Returns the mnemonic phrase ONCE so the UI can force the user to
    /// write it down and confirm. After confirmation the UI must not keep it.
    pub async fn create_new(
        &self,
        path: &Path,
        password: &str,
        settings: &NodeSettings,
    ) -> Result<Zeroizing<String>> {
        let v1net = settings.wallet_network();
        let network = v1_to_v2_network(v1net);
        let chain_id = genesis_chain_id(v1net)?;

        let seed = Bip39Seed::generate_new().map_err(|e| anyhow!("seed gen: {e}"))?;
        let phrase = Zeroizing::new(seed.phrase().to_string());

        let state = new_state_from_seed(network, chain_id, &seed);
        let ow = OpenWallet::new(
            state,
            path.to_path_buf(),
            Zeroizing::new(password.to_string()),
            network,
            AutoBackupConfig {
                enabled: settings.auto_backup_enabled,
                external_dir: settings
                    .auto_backup_external_path
                    .as_ref()
                    .map(PathBuf::from),
            },
            self.event_sink(),
        );
        ow.save()?;
        *self.inner.lock().await = Slot::Unlocked(Box::new(ow));
        Ok(phrase)
    }

    /// Restore a wallet from an existing BIP-39 phrase. This persists the seed
    /// and an empty output set; the funds are recovered later by
    /// `recover_from_seed` (coinbase) and `RpcChainSource`-driven reconciliation
    /// once the node is available.
    pub async fn restore_from_phrase(
        &self,
        path: &Path,
        password: &str,
        phrase: &str,
        settings: &NodeSettings,
    ) -> Result<()> {
        let v1net = settings.wallet_network();
        let network = v1_to_v2_network(v1net);
        let chain_id = genesis_chain_id(v1net)?;

        let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::LegacyRestore)
            .map_err(|e| anyhow!("invalid seed phrase: {e}"))?;

        let state = new_state_from_seed(network, chain_id, &seed);
        let ow = OpenWallet::new(
            state,
            path.to_path_buf(),
            Zeroizing::new(password.to_string()),
            network,
            AutoBackupConfig {
                enabled: settings.auto_backup_enabled,
                external_dir: settings
                    .auto_backup_external_path
                    .as_ref()
                    .map(PathBuf::from),
            },
            self.event_sink(),
        );
        ow.save()?;
        *self.inner.lock().await = Slot::Unlocked(Box::new(ow));
        Ok(())
    }

    /// Open an existing wallet file (decrypted by password).
    pub async fn open(&self, path: &Path, password: &str) -> Result<()> {
        let state = load_wallet_state(path, password).map_err(|e| anyhow!("open wallet: {e}"))?;
        let network = state.network;
        // Reopened wallets start with auto-backup off here (no settings on this
        // path); the Settings flow re-applies the saved config via
        // `set_auto_backup`, which also gates the external password strength.
        *self.inner.lock().await = Slot::Unlocked(Box::new(OpenWallet::new(
            state,
            path.to_path_buf(),
            Zeroizing::new(password.to_string()),
            network,
            AutoBackupConfig::default(),
            self.event_sink(),
        )));
        Ok(())
    }

    /// Lock: drop (and zeroize) the decrypted state + password, remembering the
    /// path so `unlock` can reload. State is already persisted after every
    /// mutation, so there is nothing to flush here.
    pub async fn lock(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Slot::Unlocked(ow) = &*guard {
            *guard = Slot::Locked {
                path: ow.path.clone(),
                network: ow.network,
            };
        }
        Ok(())
    }

    /// Unlock: reload the remembered file with `password`. Works from `Locked`
    /// (the normal case) and is also tolerant of being called while already
    /// unlocked (re-verifies the password by reloading).
    pub async fn unlock(&self, password: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let path = match &*guard {
            Slot::Locked { path, .. } => path.clone(),
            Slot::Unlocked(ow) => ow.path.clone(),
            Slot::Empty => return Err(anyhow!("no wallet open")),
        };
        let state =
            load_wallet_state(&path, password).map_err(|e| anyhow!("unlock failed: {e}"))?;
        let network = state.network;
        *guard = Slot::Unlocked(Box::new(OpenWallet::new(
            state,
            path,
            Zeroizing::new(password.to_string()),
            network,
            AutoBackupConfig::default(),
            self.event_sink(),
        )));
        Ok(())
    }

    /// Verify a password against the open wallet WITHOUT changing session state.
    ///
    /// v2 has no standalone verify, so we attempt a decrypt of the on-disk file:
    /// a successful `load_wallet_state` proves the password; a decryption error
    /// is a wrong password (`Ok(false)`). Returns an error only when no wallet is
    /// open. As in v1, the BIP-39 *words* cannot be re-derived from an opened
    /// wallet — this only confirms ownership (gate for the "show seed" UI).
    pub async fn verify_password(&self, password: &str) -> Result<bool> {
        let guard = self.inner.lock().await;
        let path = match &*guard {
            Slot::Locked { path, .. } => path.clone(),
            Slot::Unlocked(ow) => ow.path.clone(),
            Slot::Empty => return Err(anyhow!("no wallet open")),
        };
        drop(guard);
        match load_wallet_state(&path, password) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Maturity-aware balance breakdown computed from the store against the
    /// last reconciled tip (the same tip the v2 coin selection uses, so the
    /// "spendable" shown matches what a send can actually select).
    pub async fn balance(&self) -> Result<BalanceInfo> {
        let guard = self.inner.lock().await;
        let ow = self.unlocked(&guard)?;
        Ok(compute_balance(&ow.state))
    }

    /// Create a receive request for an exact amount (noms): derive the next
    /// receive blinding, commit to it, and INSERT the resulting output into the
    /// store at C0 (Unconfirmed) so the swept funds are tracked and later
    /// confirmed by reconciliation. Returns commitment + blinding for the node's
    /// `/wallet/spend` (auto-sweep).
    pub async fn create_receive(&self, amount: u64, now: u64) -> Result<ReceiveInfo> {
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        let req = ow
            .state
            .keychain
            .create_receive_request(amount)
            .map_err(|e| anyhow!("create receive request: {e}"))?;
        let deriver =
            KeychainDeriver::new(&ow.state.keychain).map_err(|e| anyhow!("keychain: {e}"))?;
        let blinding = deriver
            .receive_blinding(req.index)
            .map_err(|e| anyhow!("receive blinding: {e}"))?;
        let blinding_bytes = *blinding.as_bytes();

        // C0: register the owned output now (derivable, so recoverable), so the
        // incoming sweep payment is reconciled to Confirmed once mined.
        ow.state
            .outputs
            .insert(StoredOutput::new_unconfirmed(
                req.commitment,
                amount,
                blinding_bytes,
                OutputOrigin::ReceiveSlate,
                false,
                Some(DerivIndex::ReceiveRequest(req.index)),
                now,
            ))
            .map_err(|e| anyhow!("track receive output: {e}"))?;
        ow.save()?;

        Ok(ReceiveInfo {
            index: req.index,
            amount,
            commitment_hex: hex::encode(req.commitment),
            blinding_hex: hex::encode(blinding_bytes),
        })
    }

    // ── Slate protocol (interactive person-to-person send) ────────────────────
    // Three steps, Mimblewimble-style. The Slate carries only PUBLIC data, so it
    // is safe to export as hex and hand to the other party. Secrets stay in the
    // wallet's encrypted state. We only call the v2 payment functions; no crypto
    // is reimplemented here. `now` is a unix timestamp (for output bookkeeping);
    // coin-selection maturity uses the store's last reconciled tip, not `now`.

    /// Step 1 (sender): create a send slate for `amount`/`fee` (noms).
    /// Returns the slate serialized as hex for the UI to display/share.
    ///
    /// R-31(b): before coin selection we run a freshness short-circuit against the
    /// node — a cheap `tip()` check, and a full reconcile ONLY if the store is
    /// behind ([`STALE_TIP_THRESHOLD`]). This stops coin selection from picking
    /// stale (spent/immature) inputs that the node would later reject at submit
    /// ("input commitment not found"), without paying a full-chain scan on every
    /// send. If the node is unreachable the send fails here with a clear message
    /// rather than building against a possibly-stale store. `dom-wallet2`
    /// `create_send` stays pure (no node I/O of its own).
    pub async fn slate_create_send(
        &self,
        rpc_base_url: &str,
        amount: u64,
        fee: u64,
        now: u64,
    ) -> Result<String> {
        let src = rpc_source(rpc_base_url)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        if ow
            .state
            .sync_if_behind(&src, STALE_TIP_THRESHOLD, now)
            .map_err(|e| anyhow!("could not reach node to sync before send: {e}"))?
            .is_some()
        {
            // Persist the reconciled store before coin selection reads it.
            ow.save()?;
        }

        let sent = v2_create_send(&mut ow.state, amount, fee, now)
            .map_err(|e| anyhow!("create send slate: {e}"))?;
        ow.save()?;
        slate_to_hex(&sent.slate)
    }

    /// Step 2 (recipient): import the sender's slate, respond, return the
    /// responded slate as hex to hand back to the sender.
    pub async fn slate_receive(&self, slate_hex: &str, now: u64) -> Result<String> {
        let slate = slate_from_hex(slate_hex)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;
        let responded =
            v2_receive(&mut ow.state, slate, now).map_err(|e| anyhow!("receive slate: {e}"))?;
        ow.save()?;
        slate_to_hex(&responded)
    }

    /// Step 3 (sender): import the responded slate, finalize into a Transaction,
    /// and submit it to the node over `rpc_base_url`. Returns the tx hash hex.
    ///
    /// Atomicity mirrors v1's L10: `finalize_tracked` is pure and leaves the
    /// slate retryable on a crypto error; `submit_finalized` leaves the slate
    /// `Finalized` (no rollback) on a transport error, so an ambiguous failure
    /// never frees the inputs for a conflicting respend — the next reconcile /
    /// the background resubmit establishes the truth.
    pub async fn slate_finalize(
        &self,
        rpc_base_url: &str,
        slate_hex: &str,
        now: u64,
    ) -> Result<String> {
        let slate = slate_from_hex(slate_hex)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        let (_tx, slate_hash) = v2_finalize_tracked(&mut ow.state, slate, now)
            .map_err(|e| anyhow!("finalize slate: {e}"))?;
        // Persist the Finalized slate (with its tx bytes) BEFORE submitting, so a
        // crash between finalize and submit still leaves a resubmittable tx.
        ow.save()?;

        let sink = rpc_source(rpc_base_url)?;
        match v2_submit_finalized(&mut ow.state, &sink, slate_hash, now) {
            Ok(outcome) => {
                if let Some(warning) = &outcome.warning {
                    tracing::warn!(
                        "slate tx {} accepted with relay warning: {warning}",
                        hex::encode(outcome.tx_hash)
                    );
                }
                ow.save()?;
                Ok(hex::encode(outcome.tx_hash))
            }
            Err(e) => {
                // The slate stays Finalized (persisted above) for resubmit; do
                // NOT roll back — an ambiguous submit may have reached the node.
                tracing::warn!("slate submit failed, keeping tx resubmittable: {e}");
                Err(anyhow!("submit failed: {e}"))
            }
        }
    }

    /// Cancel a still-Unconfirmed send slate by its hash (releases reserved
    /// inputs, D1-deletes the Unconfirmed change). Hex is the sender slate's
    /// 32-byte hash. Kept for completeness / future UI use.
    #[allow(dead_code)]
    pub async fn slate_cancel(&self, slate_hash_hex: &str, now: u64) -> Result<()> {
        let hash = decode_hash32(slate_hash_hex)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;
        v2_cancel(&mut ow.state, hash, now).map_err(|e| anyhow!("cancel slate: {e}"))?;
        ow.save()
    }

    // ── Encrypted full-backup export / import (`wallet.dombak`, schema 4) ──────

    /// Export a complete, encrypted snapshot of the open wallet to `path`
    /// (`wallet.dombak`, schema 4). Captures the seed/keychain, the whole output
    /// store, pending slates, finalized-tx bytes and reconciliation metadata —
    /// the change/receive blindings the seed alone cannot rebuild (design §2.7).
    ///
    /// `passphrase` is the BACKUP's own secret, independent of the wallet
    /// password, so the backup can be restored on another machine. The wallet
    /// must be unlocked. The passphrase is NEVER interpolated into an error or a
    /// log line: only the backup-module error `Display` (which carries no secret
    /// material) is surfaced.
    pub async fn export_full_backup(&self, path: &Path, passphrase: &str) -> Result<()> {
        let exported_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let guard = self.inner.lock().await;
        let ow = self.unlocked(&guard)?;
        v2_export_full_backup(&ow.state, path, passphrase, exported_at)
            .map_err(|e| anyhow!("export backup: {e}"))
    }

    /// Restore a full backup into a BRAND-NEW vault file — the CONFIRMED
    /// non-destructive policy. Works WITHOUT a wallet open: this is the disaster
    /// case (fresh machine, no wallet) where the backup matters most. The caller
    /// supplies the target network EXPLICITLY; nothing reads or mutates an
    /// already-open wallet.
    ///
    /// `target_network` is the network the restored vault belongs to; its genesis
    /// gives the `expected_chain_id` the backup is validated against — the
    /// network check is NOT weakened by dropping the open-wallet dependency, the
    /// user simply asserts the network up front. `passphrase` is the backup's
    /// secret; `new_password` encrypts the new vault. Neither secret is
    /// interpolated into an error or a log line.
    ///
    /// Errors (all surfaced via `Display`, never `{:?}` of a secret):
    /// * the backup belongs to another chain/network (`ChainMismatch`);
    /// * wrong passphrase / tampering (`Decryption`); wrong file kind/schema;
    /// * the chosen new-vault path already exists (refused, never overwritten).
    pub async fn import_full_backup_to_new_vault(
        &self,
        backup_path: &Path,
        passphrase: &str,
        new_vault_path: &Path,
        new_password: &str,
        target_network: V2Network,
    ) -> Result<ImportedSummary> {
        // The backup's chain_id is validated against the EXPLICITLY-chosen target
        // network's genesis. No open wallet is read or required, so a disaster
        // restore on a virgin machine works directly.
        let expected_chain_id = genesis_chain_id(v2_to_v1_network(target_network))?;

        // Decrypt + validate (schema 4, kind == WalletState, chain_id). This call
        // returns the full state and NEVER writes to disk; the passphrase is not
        // interpolated into the surfaced error.
        let state = v2_import_full_backup(backup_path, passphrase, expected_chain_id)
            .map_err(|e| anyhow!("import backup: {e}"))?;

        // Write to a BRAND-NEW vault file. Refuse to overwrite an existing file:
        // defense-in-depth on top of the native save dialog so an import can never
        // clobber the open wallet (or any other wallet) already on disk.
        if new_vault_path.exists() {
            return Err(anyhow!(
                "refusing to overwrite an existing file at the chosen vault path"
            ));
        }
        save_wallet_state(&state, new_vault_path, new_password)
            .map_err(|e| anyhow!("save restored vault: {e}"))?;

        Ok(ImportedSummary {
            vault_path: new_vault_path.to_string_lossy().to_string(),
            network: network_str(state.network),
            outputs: state.outputs.len(),
            pending_slates: state.pending_slates.len(),
            last_reconciled_tip: state.meta.last_reconciled_tip,
        })
    }

    /// Recover derivable coinbase from the seed and reconcile against the node.
    ///
    /// This is the v2 replacement for v1's `rescan_against_node`: it pages the
    /// node's `/chain/scan` ONCE (with per-block fees and input commitments),
    /// rebuilds the derivable coinbase outputs the seed owns, inserts any that
    /// are missing, then reconciles every output's status — and the
    /// `last_reconciled_tip` cursor — from those SAME fetched blocks
    /// (`reconcile_from_restore_blocks`). One walk feeds both consumers; the
    /// previous shape paid a second full-chain `sync(0)` fetch per cycle, which
    /// doubled the RPC traffic and the node's chain-lock hold on every new
    /// block. Change and receive-slate outputs are already tracked at C0, so
    /// reconciliation alone keeps them correct; this method adds back coinbase
    /// a restored wallet owns.
    ///
    /// Idempotent: already-present outputs are skipped, and reconciliation is
    /// status-only (never drops an output).
    pub async fn recover_from_seed(&self, rpc_base_url: &str, now: u64) -> Result<RescanSummary> {
        let src = rpc_source(rpc_base_url)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        let tip = src.tip().map_err(|e| anyhow!("node tip: {e}"))?;

        let mut recovered = 0usize;
        let blocks = src
            .scan_for_restore(0, tip.height)
            .map_err(|e| anyhow!("chain scan for restore: {e}"))?;
        let coinbase = restore_coinbase_from_seed(&ow.state.keychain, &blocks, now)
            .map_err(|e| anyhow!("restore coinbase: {e}"))?;
        for out in coinbase {
            if ow.state.outputs.get(&out.commitment).is_none() {
                ow.state
                    .outputs
                    .insert(out)
                    .map_err(|e| anyhow!("insert recovered coinbase: {e}"))?;
                recovered += 1;
            }
        }

        let report = ow.state.reconcile_from_restore_blocks(&blocks, now);
        ow.save()?;

        Ok(summarize(report, recovered))
    }

    /// Resubmit every finalized-but-not-confirmed sender slate to the node.
    ///
    /// v2 keeps the public finalized tx bytes on each `PendingSlate{Sender}`, so
    /// (unlike v1's journal replay) this just re-runs `submit_finalized` for any
    /// slate still `Finalized`/`Submitted`. Used on unlock/open and on a timer.
    pub async fn resubmit_pending(
        &self,
        rpc_base_url: &str,
        now: u64,
    ) -> Result<PendingResubmitReport> {
        let sink = rpc_source(rpc_base_url)?;
        let mut guard = self.inner.lock().await;
        let ow = self.unlocked_mut(&mut guard)?;

        // Snapshot the hashes to retry so we don't borrow the vec across submits.
        let hashes: Vec<[u8; 32]> = ow
            .state
            .pending_slates
            .iter()
            .filter(|p| p.finalized_tx.is_some() && p.role == dom_wallet2::SlateRole::Sender)
            .filter(|p| {
                matches!(
                    p.status,
                    dom_wallet2::SlateLifecycle::Finalized | dom_wallet2::SlateLifecycle::Submitted
                )
            })
            .map(|p| p.slate_hash)
            .collect();

        let mut report = PendingResubmitReport::default();
        let mut changed = false;
        for hash in hashes {
            report.attempted += 1;
            match v2_submit_finalized(&mut ow.state, &sink, hash, now) {
                Ok(_) => {
                    report.submitted += 1;
                    changed = true;
                }
                // The node already has it (double-spend of an in-mempool tx, or
                // already mined): treated as success — reconcile will confirm it.
                Err(SubmitError::Sink(RpcSourceError::Rejected(reason))) => {
                    tracing::info!(
                        "pending slate {} already known to node: {reason}",
                        hex::encode(hash)
                    );
                    report.already_in_mempool += 1;
                }
                // Transient transport / busy chain → try again later.
                Err(SubmitError::Sink(
                    RpcSourceError::Request(_) | RpcSourceError::Busy | RpcSourceError::Status(_),
                )) => {
                    report.retry_later += 1;
                }
                Err(e) => {
                    tracing::warn!("pending slate {} resubmit failed: {e}", hex::encode(hash));
                    report.failed += 1;
                }
            }
        }
        if changed {
            ow.save()?;
        }
        Ok(report)
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    fn unlocked<'a>(&self, guard: &'a Slot) -> Result<&'a OpenWallet> {
        match guard {
            Slot::Unlocked(ow) => Ok(ow.as_ref()),
            Slot::Empty => Err(anyhow!("no wallet open")),
            Slot::Locked { .. } => Err(anyhow!("wallet is locked")),
        }
    }

    fn unlocked_mut<'a>(&self, guard: &'a mut Slot) -> Result<&'a mut OpenWallet> {
        match guard {
            Slot::Unlocked(ow) => Ok(ow.as_mut()),
            Slot::Empty => Err(anyhow!("no wallet open")),
            Slot::Locked { .. } => Err(anyhow!("wallet is locked")),
        }
    }
}

/// Build a fresh `WalletV2State` carrying the seed bytes (state only — the
/// mnemonic words are never persisted; only the 64-byte derived seed is).
fn new_state_from_seed(network: V2Network, chain_id: [u8; 32], seed: &Bip39Seed) -> WalletV2State {
    let mut state = WalletV2State::new(network, chain_id);
    state.keychain.seed_bytes = Some(Zeroizing::new(*seed.seed_bytes()));
    state.keychain.seed_word_count = Some(seed.word_count() as u8);
    state
}

/// The chain id (= genesis hash bytes) for a wallet on `network`.
fn genesis_chain_id(network: V1Network) -> Result<[u8; 32]> {
    let genesis = dom_core::startup_genesis_hash_for_network_magic(network.magic())
        .map_err(|e| anyhow!("genesis hash: {e}"))?;
    Ok(*genesis.as_bytes())
}

/// Maturity-aware balance over the store at `last_reconciled_tip`.
fn compute_balance(state: &WalletV2State) -> BalanceInfo {
    let tip = state.meta.last_reconciled_tip;
    let maturity = state.network.coinbase_maturity();
    let mut spendable = 0u64;
    let mut reserved = 0u64;
    let mut immature = 0u64;
    for o in state.outputs.iter() {
        if o.status != OutputStatus::Confirmed {
            continue; // Unconfirmed/Spent/Reorged are not part of the balance
        }
        let mature = if o.is_coinbase {
            match o.origin_block {
                Some(b) => tip.saturating_sub(b.height) >= maturity,
                None => false,
            }
        } else {
            true
        };
        if !mature {
            immature = immature.saturating_add(o.value);
        } else if o.is_reserved() {
            reserved = reserved.saturating_add(o.value);
        } else {
            spendable = spendable.saturating_add(o.value);
        }
    }
    let confirmed = spendable.saturating_add(reserved);
    BalanceInfo {
        total: confirmed.saturating_add(immature),
        spendable,
        confirmed,
        immature,
    }
}

fn summarize(report: ReconcileReport, recovered: usize) -> RescanSummary {
    RescanSummary {
        scanned_tip: report.tip.map(|t| t.height).unwrap_or(0),
        recovered,
        confirmed: report.confirmed,
        spent: report.spent,
        reorged: report.reorged,
    }
}

/// Build an `RpcChainSource` (ChainSource + TxSink) for the node at `base_url`.
fn rpc_source(base_url: &str) -> Result<RpcChainSource> {
    RpcChainSource::new(base_url, RPC_REQUEST_TIMEOUT).map_err(|e| anyhow!("rpc source: {e}"))
}

fn v1_to_v2_network(n: V1Network) -> V2Network {
    match n {
        V1Network::Mainnet => V2Network::Mainnet,
        V1Network::Testnet => V2Network::Testnet,
        V1Network::Regtest => V2Network::Regtest,
    }
}

fn v2_to_v1_network(n: V2Network) -> V1Network {
    match n {
        V2Network::Mainnet => V1Network::Mainnet,
        V2Network::Testnet => V1Network::Testnet,
        V2Network::Regtest => V1Network::Regtest,
    }
}

/// Stable lowercase string for a wallet `Network`, used in registry metadata
/// (mirrors the desktop `NodeSettings` lowercase serde values).
fn network_str(network: V2Network) -> String {
    match network {
        V2Network::Mainnet => "mainnet",
        V2Network::Testnet => "testnet",
        V2Network::Regtest => "regtest",
    }
    .to_string()
}

// ── Slate (de)serialization for the UI bridge ────────────────────────────────
// The Slate is exchanged as hex text (copy/paste or QR). It contains only
// public data. `to_bytes`/`from_bytes` come from the DomSerialize/DomDeserialize
// traits (dom-serialization).

fn slate_to_hex(slate: &Slate) -> Result<String> {
    let bytes = slate
        .to_bytes()
        .map_err(|e| anyhow!("slate serialize: {e}"))?;
    Ok(hex::encode(bytes))
}

fn slate_from_hex(value: &str) -> Result<Slate> {
    // Tolerate whitespace/newlines from copy-paste.
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned)
        .map_err(|_| anyhow!("invalid slate: not valid hex (corrupted or truncated)"))?;
    Slate::from_bytes(&bytes).map_err(|e| anyhow!("invalid slate: {e}"))
}

fn decode_hash32(value: &str) -> Result<[u8; 32]> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned).map_err(|_| anyhow!("invalid hash: not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid hash: must be 32 bytes"))
}

#[cfg(test)]
mod backup_wire_tests {
    //! Wire tests for the full-backup export/import path through `WalletManager`.
    //! These cover what the manager layer ADDS on top of `dom-wallet2::backup`
    //! (which already proves format fidelity at the crate level): correct
    //! passphrase passing, write-to-NEW-vault, the non-destructive guarantee, the
    //! cross-chain guard, and that no secret leaks through the wire (error string,
    //! `ImportedSummary`, or `Debug` of the restored state).
    //!
    //! The wallet is injected directly into the manager's `Slot` (same-module
    //! access to the private `inner`/`OpenWallet`/`Slot`) so the tests need no
    //! node for send/receive — the backup wire is independent of chain I/O.

    use super::*;
    use dom_wallet2::{PendingSlate, SlateLifecycle, SlateRole, SlateSecrets};
    use tempfile::TempDir;

    // Canary seed: a distinctive decimal byte (0xAB = 171) so a `Debug` LEAK of
    // the seed would print a long "171, 171, ..." run the anti-leak test detects.
    const SEED_CANARY: [u8; 64] = [0xAB; 64];
    // The non-derivable receiver blinding the backup exists to protect (0xE3=227).
    const SLATE_BLINDING: [u8; 32] = [0xE3; 32];
    // Secret passphrases — must NEVER surface in an error or a `Debug` string.
    const BAK_PASS: &str = "backup-pass-LEAKCANARY-Zx9";
    const NEW_VAULT_PASS: &str = "new-vault-pass-LEAKCANARY-Qw7";

    fn commit(tag: u8) -> [u8; 33] {
        let mut c = [0u8; 33];
        c[0] = tag;
        c
    }

    fn out(tag: u8, value: u64, origin: OutputOrigin) -> StoredOutput {
        StoredOutput::new_unconfirmed(commit(tag), value, [tag; 32], origin, false, None, 1000)
    }

    /// A backup-event sink that records every failure, for asserting the
    /// "never silent" behaviour without a running Tauri app.
    #[derive(Default)]
    struct RecordingSink {
        failures: std::sync::Mutex<Vec<(BackupTarget, String)>>,
    }
    impl BackupEventSink for RecordingSink {
        fn backup_failed(&self, target: BackupTarget, reason: String) {
            self.failures.lock().unwrap().push((target, reason));
        }
    }
    impl RecordingSink {
        fn events(&self) -> Vec<(BackupTarget, String)> {
            self.failures.lock().unwrap().clone()
        }
    }

    fn noop_sink() -> Arc<dyn BackupEventSink> {
        Arc::new(NoopBackupSink)
    }

    /// A real regtest state: seed + 2 outputs + 1 pending receiver slate. The
    /// `chain_id` is the REAL regtest genesis so the manager's import (which
    /// derives `expected_chain_id` from the target network) accepts it.
    fn populated_regtest_state() -> WalletV2State {
        let chain_id = genesis_chain_id(V1Network::Regtest).unwrap();
        let mut state = WalletV2State::new(V2Network::Regtest, chain_id);
        state.keychain.seed_bytes = Some(Zeroizing::new(SEED_CANARY));
        state.keychain.seed_word_count = Some(24);
        state.keychain.next_change_index = 3;
        state.keychain.next_receive_index = 5;
        state.meta.last_reconciled_tip = 42;
        state
            .outputs
            .insert(out(1, 1000, OutputOrigin::Coinbase))
            .unwrap();
        state
            .outputs
            .insert(out(2, 500, OutputOrigin::Change))
            .unwrap();
        state.pending_slates.push(PendingSlate {
            slate_hash: [0xB2; 32],
            role: SlateRole::Receiver,
            slate_bytes: vec![5, 6, 7],
            secrets: Some(SlateSecrets::Receiver {
                output_blinding: Zeroizing::new(SLATE_BLINDING),
            }),
            reserved_inputs: vec![],
            produced_output: Some([0xC7; 33]),
            finalized_tx: None,
            status: SlateLifecycle::Submitted,
        });
        state
    }

    /// Build a manager with an UNLOCKED wallet holding `state`, injected directly
    /// (no node needed). `path` is a placeholder; export/import never re-save the
    /// open wallet, so it need not exist on disk.
    async fn manager_with_open(state: WalletV2State, dir: &TempDir) -> WalletManager {
        let manager = WalletManager::new();
        *manager.inner.lock().await = Slot::Unlocked(Box::new(OpenWallet::new(
            state,
            dir.path().join("open-wallet.dat"),
            Zeroizing::new("wallet-login-pass".to_string()),
            V2Network::Regtest,
            AutoBackupConfig {
                enabled: true,
                external_dir: None,
            },
            noop_sink(),
        )));
        manager
    }

    /// Manager with an open wallet under a chosen login `password`, auto-backup
    /// starting OFF (mirrors a freshly reopened wallet). For the ETAPA 4 gate.
    async fn manager_with_open_pass(dir: &TempDir, password: &str) -> WalletManager {
        let manager = WalletManager::new();
        *manager.inner.lock().await = Slot::Unlocked(Box::new(OpenWallet::new(
            populated_regtest_state(),
            dir.path().join("open-wallet.dat"),
            Zeroizing::new(password.to_string()),
            V2Network::Regtest,
            AutoBackupConfig::default(),
            noop_sink(),
        )));
        manager
    }

    /// Read the open wallet's `(enabled, external_dir)` for assertions.
    async fn backup_state(manager: &WalletManager) -> (bool, Option<PathBuf>) {
        match &*manager.inner.lock().await {
            Slot::Unlocked(ow) => (ow.backup.is_enabled(), ow.backup.external_dir()),
            _ => panic!("wallet not unlocked"),
        }
    }

    // ── T1: round-trip export → import → new vault preserves the state ─────────
    #[tokio::test]
    async fn t1_round_trip_to_new_vault_preserves_state() {
        let dir = TempDir::new().unwrap();
        let original = populated_regtest_state();
        let manager = manager_with_open(original.clone(), &dir).await;

        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();
        assert!(dombak.exists(), "backup file written");

        let new_vault = dir.path().join("restored.dat");
        let summary = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap();

        // Summary reflects the recovered state (non-sensitive counts only).
        assert_eq!(summary.outputs, 2);
        assert_eq!(summary.pending_slates, 1);
        assert_eq!(summary.network, "regtest");
        assert_eq!(summary.last_reconciled_tip, 42);
        assert_eq!(summary.vault_path, new_vault.to_string_lossy());

        // The new vault decrypts with its OWN password to the same state.
        let restored = load_wallet_state(&new_vault, NEW_VAULT_PASS).unwrap();
        assert_eq!(restored.chain_id, original.chain_id);
        assert_eq!(restored.outputs.len(), 2);
        assert_eq!(restored.outputs.get(&commit(1)).unwrap().value, 1000);
        assert_eq!(restored.outputs.get(&commit(2)).unwrap().value, 500);
        assert_eq!(restored.keychain.seed_bytes.as_deref(), Some(&SEED_CANARY));
        assert_eq!(restored.keychain.next_change_index, 3);
        assert_eq!(restored.pending_slates.len(), 1);
        match restored.pending_slates[0].secrets.as_ref() {
            Some(SlateSecrets::Receiver { output_blinding }) => {
                assert_eq!(**output_blinding, SLATE_BLINDING);
            }
            other => panic!("expected receiver secret, got {other:?}"),
        }
    }

    // ── T2: wrong passphrase → Decryption, no file created, no leak ────────────
    #[tokio::test]
    async fn t2_wrong_passphrase_rejected_no_file_no_leak() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open(populated_regtest_state(), &dir).await;
        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();

        let new_vault = dir.path().join("restored.dat");
        let err = manager
            .import_full_backup_to_new_vault(
                &dombak,
                "WRONG-ATTEMPT-PASS",
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("decryption failed"), "got: {msg}");
        assert!(
            !new_vault.exists(),
            "no vault file created on wrong passphrase"
        );
        // Neither the (wrong) attempt nor any real secret leaks into the message.
        assert!(
            !msg.contains("WRONG-ATTEMPT-PASS"),
            "attempt passphrase leaked"
        );
        assert!(!msg.contains(BAK_PASS), "backup passphrase leaked");
        assert!(!msg.contains(NEW_VAULT_PASS), "vault passphrase leaked");
    }

    // ── T3: import is non-destructive — the open wallet is untouched ───────────
    #[tokio::test]
    async fn t3_import_non_destructive_open_wallet_intact() {
        let dir = TempDir::new().unwrap();
        // The open wallet deliberately DIFFERS from the backup so any clobber shows.
        let chain_id = genesis_chain_id(V1Network::Regtest).unwrap();
        let mut open_state = WalletV2State::new(V2Network::Regtest, chain_id);
        open_state.keychain.seed_bytes = Some(Zeroizing::new([0x11; 64]));
        open_state
            .outputs
            .insert(out(9, 4242, OutputOrigin::Change))
            .unwrap();
        let manager = manager_with_open(open_state, &dir).await;

        // A DIFFERENT backup (the rich 2-output state) written via the crate fn.
        let dombak = dir.path().join("other.dombak");
        v2_export_full_backup(&populated_regtest_state(), &dombak, BAK_PASS, 0).unwrap();

        let new_vault = dir.path().join("restored.dat");
        let summary = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap();
        assert_eq!(summary.outputs, 2, "new vault got the backup's outputs");
        assert!(new_vault.exists(), "new vault written separately");

        // The OPEN wallet inside the manager is byte-for-byte unchanged.
        let guard = manager.inner.lock().await;
        match &*guard {
            Slot::Unlocked(ow) => {
                assert_eq!(ow.state.outputs.len(), 1, "open wallet outputs untouched");
                assert!(
                    ow.state.outputs.get(&commit(9)).is_some(),
                    "open wallet's own output preserved"
                );
                assert_eq!(
                    ow.state.keychain.seed_bytes.as_deref(),
                    Some(&[0x11; 64]),
                    "open wallet seed untouched"
                );
                assert!(
                    ow.state.pending_slates.is_empty(),
                    "open wallet slates untouched"
                );
            }
            _ => panic!("wallet should still be unlocked after import"),
        }
    }

    // ── T4: no secret leaks via the summary or the restored state's Debug ──────
    #[tokio::test]
    async fn t4_no_secret_leaks_summary_or_debug() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open(populated_regtest_state(), &dir).await;
        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();

        let new_vault = dir.path().join("restored.dat");
        let summary = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Regtest,
            )
            .await
            .unwrap();

        // (a) The summary returned over IPC carries no secret material.
        let summary_dbg = format!("{summary:?}");
        assert!(
            !summary_dbg.contains("171, 171"),
            "seed bytes leaked into the summary"
        );
        assert!(
            !summary_dbg.contains(BAK_PASS),
            "backup passphrase in summary"
        );
        assert!(
            !summary_dbg.contains(NEW_VAULT_PASS),
            "vault passphrase in summary"
        );

        // (b) `Debug` of the restored state redacts seed + slate secrets.
        let restored = load_wallet_state(&new_vault, NEW_VAULT_PASS).unwrap();
        let dump = format!("{restored:?}");
        assert!(dump.contains("<redacted>"), "redaction marker missing");
        assert!(
            !dump.contains("171, 171, 171, 171"),
            "seed leaked via Debug"
        );
        assert!(
            !dump.contains("227, 227, 227, 227"),
            "slate output blinding leaked via Debug"
        );
    }

    // ── T5: cross-chain target rejected BEFORE any write ───────────────────────
    #[tokio::test]
    async fn t5_cross_chain_target_rejected_before_write() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open(populated_regtest_state(), &dir).await;
        let dombak = dir.path().join("wallet.dombak");
        manager.export_full_backup(&dombak, BAK_PASS).await.unwrap();

        let new_vault = dir.path().join("restored.dat");
        // Assert the WRONG target network (testnet) for a regtest backup. Testnet
        // has a finalized, distinct genesis, so this exercises the real
        // `ChainMismatch` guard (mainnet's genesis is intentionally not finalized
        // in this build, which would error earlier — also before any write).
        let err = manager
            .import_full_backup_to_new_vault(
                &dombak,
                BAK_PASS,
                &new_vault,
                NEW_VAULT_PASS,
                V2Network::Testnet,
            )
            .await
            .unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("chain id does not match"), "got: {msg}");
        assert!(
            !new_vault.exists(),
            "no vault written on chain mismatch (refused before write)"
        );
        assert!(
            !msg.contains(BAK_PASS),
            "passphrase leaked on chain mismatch"
        );
    }

    // ── ETAPA 2: local auto-backup on material funds change ───────────────────

    const LOGIN_PASS: &str = "login-pass-123";

    /// (a) + (c): a save that changes funds writes `<vault>.dombak`, and that
    /// backup decrypts under the seed-derived passphrase to the same funds.
    #[test]
    fn material_save_writes_local_backup_that_matches() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        let dombak = local_backup_path(&vault);
        let mut ow = OpenWallet::new(
            populated_regtest_state(),
            vault.clone(),
            Zeroizing::new(LOGIN_PASS.to_string()),
            V2Network::Regtest,
            AutoBackupConfig {
                enabled: true,
                external_dir: None,
            },
            noop_sink(),
        );

        // Baseline save (funds unchanged since construction) → no backup.
        ow.save().unwrap();
        assert!(vault.exists(), "vault persisted");
        assert!(
            !dombak.exists(),
            "baseline non-material save must not back up"
        );
        assert_eq!(ow.backup.writes(), 0);

        // Materially change funds: add an output → backup is written.
        ow.state
            .outputs
            .insert(out(9, 777, OutputOrigin::Change))
            .unwrap();
        ow.save().unwrap();
        assert!(dombak.exists(), "material save writes the local backup");
        assert_eq!(ow.backup.writes(), 1);

        // (c) The backup decrypts (seed-derived passphrase) and matches funds.
        let chain_id = genesis_chain_id(V1Network::Regtest).unwrap();
        let pass = derive_auto_backup_passphrase(LOGIN_PASS);
        let restored = v2_import_full_backup(&dombak, pass.as_str(), chain_id).unwrap();
        assert_eq!(restored.outputs.len(), 3);
        assert_eq!(restored.outputs.get(&commit(9)).unwrap().value, 777);
    }

    /// (b): metadata-only saves (sync tip, pending-slate churn) do NOT re-backup.
    #[test]
    fn metadata_only_save_does_not_write_backup() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        let mut ow = OpenWallet::new(
            populated_regtest_state(),
            vault.clone(),
            Zeroizing::new(LOGIN_PASS.to_string()),
            V2Network::Regtest,
            AutoBackupConfig {
                enabled: true,
                external_dir: None,
            },
            noop_sink(),
        );

        // Establish one backup via a material change.
        ow.state
            .outputs
            .insert(out(9, 777, OutputOrigin::Change))
            .unwrap();
        ow.save().unwrap();
        assert_eq!(ow.backup.writes(), 1);

        // Metadata-only mutations: advance the tip and drop a pending slate.
        ow.state.meta.last_reconciled_tip = 99;
        ow.state.pending_slates.clear();
        ow.save().unwrap();
        assert_eq!(
            ow.backup.writes(),
            1,
            "tip/slate-only save must not re-backup"
        );
    }

    /// (d): a backup failure NEVER fails the vault save (best-effort), and leaves
    /// no partial file at the target.
    #[test]
    fn vault_save_succeeds_even_if_backup_fails() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        // Backup target under a non-existent directory → the write will fail.
        let bad = dir.path().join("missing-subdir").join("x.dombak");
        let state = populated_regtest_state();
        // Seed the controller with a fingerprint that differs from the real one
        // so the first save counts as material and actually attempts a backup.
        let ow = OpenWallet {
            state: state.clone(),
            path: vault.clone(),
            password: Zeroizing::new(LOGIN_PASS.to_string()),
            network: V2Network::Regtest,
            backup: Arc::new(LocalBackup::new(
                bad.clone(),
                funds_fingerprint(&state) ^ 1,
                AutoBackupConfig {
                    enabled: true,
                    external_dir: None,
                },
                noop_sink(),
            )),
        };

        ow.save().unwrap(); // must NOT error despite the backup failing
        assert!(vault.exists(), "vault persisted despite backup failure");
        assert!(!bad.exists(), "failed backup leaves no (partial) file");
        assert_eq!(ow.backup.writes(), 0, "no successful backup recorded");
    }

    /// (e) + coalescing: a superseded write is skipped; only the latest snapshot
    /// is written. Also pins that the written file is complete (decryptable),
    /// i.e. never a truncated artifact.
    #[test]
    fn coalescing_skips_superseded_writes_and_file_is_complete() {
        let dir = TempDir::new().unwrap();
        let dombak = dir.path().join("w.dat.dombak");
        let chain_id = genesis_chain_id(V1Network::Regtest).unwrap();
        let state = populated_regtest_state();
        let pass = derive_auto_backup_passphrase(LOGIN_PASS);
        let backup = LocalBackup::new(
            dombak.clone(),
            0,
            AutoBackupConfig {
                enabled: true,
                external_dir: None,
            },
            noop_sink(),
        );

        let s1 = backup.note_material(10).unwrap();
        let s2 = backup.note_material(20).unwrap();
        assert_eq!((s1, s2), (1, 2));

        // The older request was superseded by the newer one → it must skip.
        backup.write(s1, &state, pass.as_str(), 0);
        assert!(!dombak.exists(), "superseded write must be skipped");
        assert_eq!(backup.writes(), 0);

        // The latest request writes a complete, decryptable backup.
        backup.write(s2, &state, pass.as_str(), 0);
        assert!(dombak.exists());
        assert_eq!(backup.writes(), 1);
        let restored = v2_import_full_backup(&dombak, pass.as_str(), chain_id).unwrap();
        assert_eq!(restored.outputs.len(), 2);
    }

    /// `note_material` returns a seq only when the funds fingerprint changes.
    #[test]
    fn note_material_is_some_only_on_change() {
        let b = LocalBackup::new(
            PathBuf::from("/unused"),
            42,
            AutoBackupConfig {
                enabled: true,
                external_dir: None,
            },
            noop_sink(),
        );
        assert_eq!(b.note_material(42), None, "unchanged → no backup");
        assert!(b.note_material(43).is_some(), "changed → backup");
        assert_eq!(b.note_material(43), None, "unchanged again → no backup");
        assert!(b.note_material(42).is_some(), "changed back → backup");
    }

    /// The fingerprint tracks funds, not metadata: tip/slate churn does not move
    /// it; a new output does.
    #[test]
    fn fingerprint_tracks_funds_not_metadata() {
        let mut s = populated_regtest_state();
        let base = funds_fingerprint(&s);
        s.meta.last_reconciled_tip += 100;
        s.pending_slates.clear();
        assert_eq!(funds_fingerprint(&s), base, "tip/slate are not funds");
        s.outputs.insert(out(9, 1, OutputOrigin::Change)).unwrap();
        assert_ne!(
            funds_fingerprint(&s),
            base,
            "a new output is a funds change"
        );
    }

    /// AUTO-BACKUP ENFORCEMENT: `save()` refreshes the auto-backup iff
    /// `funds_fingerprint` moved, so the fingerprint MUST register every
    /// output-lifecycle event — including the ones that create no output at
    /// all (a send without change only flips its inputs to `Spent`; a reorg
    /// only flips `Confirmed` to `Reorged`). If any transition were invisible
    /// here, that material fund change would silently skip its auto-backup.
    #[test]
    fn fingerprint_registers_every_output_lifecycle_transition() {
        let statuses = [
            OutputStatus::Unconfirmed,
            OutputStatus::Confirmed,
            OutputStatus::Spent,
            OutputStatus::Reorged,
        ];
        let fp_with_status = |status: OutputStatus| {
            let mut s = populated_regtest_state();
            s.outputs
                .get_mut(&commit(1))
                .expect("output 1 present")
                .status = status;
            funds_fingerprint(&s)
        };
        for (i, a) in statuses.iter().enumerate() {
            for b in statuses.iter().skip(i + 1) {
                assert_ne!(
                    fp_with_status(*a),
                    fp_with_status(*b),
                    "a {a:?} -> {b:?} transition must read as a material funds change"
                );
            }
        }

        // A value difference on an otherwise identical output set is material
        // too (a rewritten amount must never skip the backup).
        let base = funds_fingerprint(&populated_regtest_state());
        let mut bumped = populated_regtest_state();
        bumped
            .outputs
            .get_mut(&commit(1))
            .expect("output 1 present")
            .value += 1;
        assert_ne!(
            funds_fingerprint(&bumped),
            base,
            "a value change must read as a material funds change"
        );
    }

    /// Under an async runtime, a material save spawns the backup OFF the reactor
    /// (`spawn_blocking`) and the awaited job writes the file.
    #[tokio::test]
    async fn async_material_save_spawns_backup_off_reactor() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        let dombak = local_backup_path(&vault);
        let mut ow = OpenWallet::new(
            populated_regtest_state(),
            vault.clone(),
            Zeroizing::new(LOGIN_PASS.to_string()),
            V2Network::Regtest,
            AutoBackupConfig {
                enabled: true,
                external_dir: None,
            },
            noop_sink(),
        );

        ow.state
            .outputs
            .insert(out(9, 777, OutputOrigin::Change))
            .unwrap();
        ow.save().unwrap();

        // The vault save returned immediately; the backup runs on a blocking
        // thread. Await it to assert completion deterministically.
        let job = ow.backup.take_in_flight().expect("a backup was spawned");
        job.await.unwrap();
        assert!(dombak.exists(), "spawned backup wrote the file");
        assert_eq!(ow.backup.writes(), 1);
    }

    // ── ETAPA 3: external destination + "never silent" failure events ─────────

    fn add_output(ow: &mut OpenWallet, tag: u8, value: u64) {
        ow.state
            .outputs
            .insert(out(tag, value, OutputOrigin::Change))
            .unwrap();
    }

    /// (a): with an available external folder, a material save writes BOTH the
    /// local and external backups; both decrypt to the same funds; no events.
    #[test]
    fn external_available_writes_both_destinations() {
        let dir = TempDir::new().unwrap();
        let ext = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        let local = local_backup_path(&vault);
        let external = external_target_path(ext.path(), &local);
        let sink = Arc::new(RecordingSink::default());
        let mut ow = OpenWallet::new(
            populated_regtest_state(),
            vault.clone(),
            Zeroizing::new(LOGIN_PASS.to_string()),
            V2Network::Regtest,
            AutoBackupConfig {
                enabled: true,
                external_dir: Some(ext.path().to_path_buf()),
            },
            sink.clone(),
        );
        add_output(&mut ow, 9, 777);
        ow.save().unwrap();

        assert!(local.exists(), "local backup written");
        assert!(external.exists(), "external backup written");
        assert_eq!(ow.backup.writes(), 1);
        assert_eq!(ow.backup.external_writes(), 1);
        assert!(sink.events().is_empty(), "no failures on the happy path");

        let chain_id = genesis_chain_id(V1Network::Regtest).unwrap();
        let pass = derive_auto_backup_passphrase(LOGIN_PASS);
        for f in [&local, &external] {
            let restored = v2_import_full_backup(f, pass.as_str(), chain_id).unwrap();
            assert_eq!(restored.outputs.len(), 3);
            assert_eq!(restored.outputs.get(&commit(9)).unwrap().value, 777);
        }
    }

    /// (b): an unavailable external folder → the local backup still writes, the
    /// vault save is Ok, and exactly one EXTERNAL warning event is emitted.
    #[test]
    fn external_unavailable_emits_warning_and_local_still_writes() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        let local = local_backup_path(&vault);
        let missing = dir.path().join("removed-drive"); // never created
        let sink = Arc::new(RecordingSink::default());
        let mut ow = OpenWallet::new(
            populated_regtest_state(),
            vault.clone(),
            Zeroizing::new(LOGIN_PASS.to_string()),
            V2Network::Regtest,
            AutoBackupConfig {
                enabled: true,
                external_dir: Some(missing),
            },
            sink.clone(),
        );
        add_output(&mut ow, 9, 777);
        ow.save().unwrap(); // vault save must be Ok

        assert!(vault.exists());
        assert!(local.exists(), "local backup still written");
        assert_eq!(ow.backup.writes(), 1);
        assert_eq!(ow.backup.external_writes(), 0);

        let events = sink.events();
        assert_eq!(events.len(), 1, "exactly one failure event");
        assert_eq!(events[0].0, BackupTarget::External);
        assert_eq!(events[0].0.severity(), "warning");
        assert!(
            events[0].1.contains("indisponível"),
            "external reason should say unavailable: {}",
            events[0].1
        );
    }

    /// (c): a LOCAL failure emits an event with target=Local (error severity); the
    /// vault save still succeeds.
    #[test]
    fn local_failure_emits_error_event() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        let bad_local = dir.path().join("missing").join("w.dat.dombak"); // parent missing
        let state = populated_regtest_state();
        let sink = Arc::new(RecordingSink::default());
        let ow = OpenWallet {
            state: state.clone(),
            path: vault.clone(),
            password: Zeroizing::new(LOGIN_PASS.to_string()),
            network: V2Network::Regtest,
            backup: Arc::new(LocalBackup::new(
                bad_local.clone(),
                funds_fingerprint(&state) ^ 1, // force material
                AutoBackupConfig {
                    enabled: true,
                    external_dir: None,
                },
                sink.clone(),
            )),
        };
        ow.save().unwrap(); // vault must persist despite the local backup failing

        assert!(
            vault.exists(),
            "vault persisted despite local backup failure"
        );
        assert!(!bad_local.exists());
        assert_eq!(ow.backup.writes(), 0);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, BackupTarget::Local);
        assert_eq!(events[0].0.severity(), "error");
    }

    /// (d): no external configured → only the local backup runs, and no events.
    #[test]
    fn external_not_set_writes_local_only_no_events() {
        let dir = TempDir::new().unwrap();
        let vault = dir.path().join("w.dat");
        let local = local_backup_path(&vault);
        let sink = Arc::new(RecordingSink::default());
        let mut ow = OpenWallet::new(
            populated_regtest_state(),
            vault.clone(),
            Zeroizing::new(LOGIN_PASS.to_string()),
            V2Network::Regtest,
            AutoBackupConfig {
                enabled: true,
                external_dir: None,
            },
            sink.clone(),
        );
        add_output(&mut ow, 9, 777);
        ow.save().unwrap();

        assert!(local.exists());
        assert_eq!(ow.backup.writes(), 1);
        assert_eq!(ow.backup.external_writes(), 0);
        assert!(sink.events().is_empty(), "no events when external is unset");
    }

    /// Target → wire/severity mapping the UI relies on.
    #[test]
    fn target_wire_and_severity_mapping() {
        assert_eq!(BackupTarget::Local.as_str(), "local");
        assert_eq!(BackupTarget::External.as_str(), "external");
        assert_eq!(BackupTarget::Local.severity(), "error");
        assert_eq!(BackupTarget::External.severity(), "warning");
    }

    /// The external file lands inside the chosen folder, named after the vault.
    #[test]
    fn external_target_path_names_file_in_folder() {
        let folder = PathBuf::from("/some/usb");
        let local = local_backup_path(Path::new("/home/u/w.dat"));
        let target = external_target_path(&folder, &local);
        assert_eq!(target, PathBuf::from("/some/usb/w.dat.dombak"));
    }

    // ── ETAPA 4: set_auto_backup — strong-password gate for the external dest ──

    // 17 chars, lowercase + hyphen only → 2 classes → weak.
    const WEAK_PASS: &str = "weak-login-phrase";
    // lower + upper + digit + symbol → strong.
    const STRONG_PASS: &str = "Str0ng-Login-Pass!";

    /// Enabling an EXTERNAL destination with a weak login password is rejected,
    /// and NOTHING is applied (the config stays off / no external).
    #[tokio::test]
    async fn set_auto_backup_rejects_weak_password_for_external() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open_pass(&dir, WEAK_PASS).await;
        let err = manager
            .set_auto_backup(true, Some(dir.path().join("usb")))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too simple") || msg.contains("too short"),
            "reason should explain the weakness: {msg}"
        );
        // No secret in the message, and nothing applied.
        assert!(!msg.contains(WEAK_PASS), "password must not leak: {msg}");
        assert_eq!(backup_state(&manager).await, (false, None));
    }

    /// A strong login password lets the external destination be set on the OPEN
    /// wallet (closing the open/unlock gap).
    #[tokio::test]
    async fn set_auto_backup_accepts_strong_password_and_sets_external() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open_pass(&dir, STRONG_PASS).await;
        let folder = dir.path().join("usb");
        manager
            .set_auto_backup(true, Some(folder.clone()))
            .await
            .unwrap();
        assert_eq!(backup_state(&manager).await, (true, Some(folder)));
    }

    /// LOCAL-only auto-backup needs NO password gate (the seed never leaves the
    /// machine), even with a weak password.
    #[tokio::test]
    async fn set_auto_backup_local_only_needs_no_password_gate() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open_pass(&dir, WEAK_PASS).await;
        manager.set_auto_backup(true, None).await.unwrap();
        assert_eq!(backup_state(&manager).await, (true, None));
    }

    /// Disabling drops the external target too (no backups at all), no gate.
    #[tokio::test]
    async fn set_auto_backup_disable_clears_external() {
        let dir = TempDir::new().unwrap();
        let manager = manager_with_open_pass(&dir, STRONG_PASS).await;
        manager
            .set_auto_backup(true, Some(dir.path().join("usb")))
            .await
            .unwrap();
        manager
            .set_auto_backup(false, Some(dir.path().join("usb")))
            .await
            .unwrap();
        assert_eq!(backup_state(&manager).await, (false, None));
    }
}

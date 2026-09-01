//! At-rest persistence of the [`WalletV2State`] (design §2.1–§2.3).
//!
//! The whole wallet state is written to disk through the shared, audited
//! [`dom_wallet_crypto`] envelope — the same crypto v1 uses (Argon2id + HKDF key
//! derivation, ChaCha20Poly1305 AEAD, atomic write with fsync). The secrets it
//! carries — the output blindings AND the keychain seed — persist **encrypted**,
//! never in plaintext.
//!
//! ## Two-level versioning
//! - **Envelope:** magic [`WALLET_V2_MAGIC`] (`DOM-WALLET-V2\0`) + header
//!   [`ENVELOPE_VERSION`]. The magic rejects v1 files by construction; an
//!   unknown envelope version is rejected by [`dom_wallet_crypto`] before
//!   decryption.
//! - **Payload:** the inner [`WalletV2State::schema_version`] gates future
//!   in-place migration. An unknown schema is rejected after decryption with a
//!   clear [`PersistError::UnsupportedSchema`] — never reinterpreted, never a
//!   panic.

use crate::store::StoreError;
use crate::wallet_state::{WalletV2State, LEGACY_SCHEMA_VERSION_V2, SCHEMA_VERSION};
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// v2 wallet-file magic. 14 bytes, distinct from v1's `DOM-WALLET-V1\0`, so a
/// v1 file is rejected by construction (and vice versa).
pub const WALLET_V2_MAGIC: &[u8; dom_wallet_crypto::MAGIC_LEN] = b"DOM-WALLET-V2\0";

/// Envelope (file-format) version written in the header.
pub const ENVELOPE_VERSION: u16 = 1;

/// Errors from persisting / loading the wallet state.
#[derive(Debug, Error)]
pub enum PersistError {
    /// Key derivation / AEAD / IO / header-validation error from the shared
    /// envelope (wrong password and tampering surface here as
    /// [`dom_wallet_crypto::EnvelopeError::Decryption`]).
    #[error(transparent)]
    Envelope(#[from] dom_wallet_crypto::EnvelopeError),
    /// The decrypted payload declares a schema this build does not understand.
    #[error("unsupported wallet schema version: {0}")]
    UnsupportedSchema(u16),
    /// The decrypted state violated a store invariant (e.g. a duplicate
    /// commitment) — corruption that the AEAD tag did not catch.
    #[error("invalid persisted wallet state: {0}")]
    Store(#[from] StoreError),
    /// The migration caller did not retain the exact owner-lock file belonging
    /// to this wallet path.
    #[error("invalid wallet migration owner lock")]
    InvalidOwnerLock,
    /// The exact owner-lock inode is already exclusively retained through a
    /// different open-file description/process.
    #[error("wallet migration owner lock is already held")]
    ProcessLocked,
    /// A purported legacy V2 payload already contains a field introduced in
    /// V3 and therefore cannot be interpreted as an authentic legacy state.
    #[error("legacy wallet payload contains a payout pin")]
    LegacyContainsPayoutPin,
}

/// Outcome of an owner-locked wallet payload migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletMigrationDispositionV1 {
    /// An exact schema-V2 payload was atomically replaced by schema V3.
    MigratedV2ToV3,
    /// The retained wallet already used schema V3; no bytes were rewritten.
    AlreadyCurrent,
}

/// Encrypt and atomically write the whole wallet state to `path`.
///
/// A fresh salt and nonce are generated per call (by the envelope). The on-disk
/// layout is the shared v2 envelope; the blindings AND the keychain seed are
/// written only encrypted.
pub fn save_wallet_state(
    state: &WalletV2State,
    path: &Path,
    password: &str,
) -> Result<(), PersistError> {
    if state.schema_version != SCHEMA_VERSION {
        return Err(PersistError::UnsupportedSchema(state.schema_version));
    }
    dom_wallet_crypto::save_envelope(path, WALLET_V2_MAGIC, ENVELOPE_VERSION, state, password)?;
    Ok(())
}

/// Atomically migrate one exact schema-V2 wallet to schema V3 while retaining
/// the wallet's production owner lock.
///
/// `owner_lock` must be the open file at `<wallet-path>.interop.lock`. This
/// function validates that path/handle identity and itself acquires (or verifies
/// on the exact already-locked handle) a nonblocking exclusive OS lock before
/// decrypting or writing. The lock remains attached to the caller's retained
/// handle after return. A separately opened handle is refused even in the same
/// process, so correctness does not depend on a caller honoring documentation.
/// Callers must open/pass this handle before retaining the wallet ciphertext
/// inode, because the successful atomic replacement changes that inode.
///
/// V2 can migrate losslessly because it predates payout pins: every decoded
/// output must have `payout_for == None`. Unknown schemas and V2 payloads that
/// contain a V3-only pin fail without writing. V3 is an idempotent read-only
/// success.
pub fn migrate_wallet_state_v2_to_v3_under_owner_lock(
    path: &Path,
    password: &str,
    owner_lock: &mut File,
) -> Result<WalletMigrationDispositionV1, PersistError> {
    acquire_and_validate_migration_owner_lock(path, owner_lock)?;

    let mut state: WalletV2State =
        dom_wallet_crypto::load_envelope(path, WALLET_V2_MAGIC, ENVELOPE_VERSION, password)?;
    match state.schema_version {
        SCHEMA_VERSION => Ok(WalletMigrationDispositionV1::AlreadyCurrent),
        LEGACY_SCHEMA_VERSION_V2 => {
            if state
                .outputs
                .iter()
                .any(|output| output.payout_for().is_some())
            {
                return Err(PersistError::LegacyContainsPayoutPin);
            }
            state.schema_version = SCHEMA_VERSION;
            acquire_and_validate_migration_owner_lock(path, owner_lock)?;
            save_wallet_state(&state, path, password)?;
            let reopened = load_wallet_state(path, password)?;
            if reopened
                .outputs
                .iter()
                .any(|output| output.payout_for().is_some())
            {
                return Err(PersistError::LegacyContainsPayoutPin);
            }
            acquire_and_validate_migration_owner_lock(path, owner_lock)?;
            Ok(WalletMigrationDispositionV1::MigratedV2ToV3)
        }
        version => Err(PersistError::UnsupportedSchema(version)),
    }
}

#[cfg(unix)]
fn acquire_and_validate_migration_owner_lock(
    path: &Path,
    owner_lock: &File,
) -> Result<(), PersistError> {
    validate_migration_owner_lock(path, owner_lock)?;
    fs2::FileExt::try_lock_exclusive(owner_lock).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            PersistError::ProcessLocked
        } else {
            PersistError::InvalidOwnerLock
        }
    })?;
    // Close the path/handle substitution window around lock acquisition before
    // any ciphertext is read or an atomic replacement can begin.
    validate_migration_owner_lock(path, owner_lock)
}

#[cfg(not(unix))]
fn acquire_and_validate_migration_owner_lock(
    _path: &Path,
    _owner_lock: &File,
) -> Result<(), PersistError> {
    Err(PersistError::InvalidOwnerLock)
}

fn migration_owner_lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".interop.lock");
    PathBuf::from(value)
}

#[cfg(unix)]
fn validate_migration_owner_lock(path: &Path, owner_lock: &File) -> Result<(), PersistError> {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() {
        return Err(PersistError::InvalidOwnerLock);
    }
    let lock_path = migration_owner_lock_path(path);
    let named =
        std::fs::symlink_metadata(&lock_path).map_err(|_| PersistError::InvalidOwnerLock)?;
    let retained = owner_lock
        .metadata()
        .map_err(|_| PersistError::InvalidOwnerLock)?;
    if !named.file_type().is_file()
        || !retained.file_type().is_file()
        || named.dev() != retained.dev()
        || named.ino() != retained.ino()
        || named.nlink() != 1
        || retained.nlink() != 1
        || named.mode() & 0o077 != 0
        || retained.mode() & 0o077 != 0
        || named.len() != 0
        || retained.len() != 0
    {
        return Err(PersistError::InvalidOwnerLock);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_migration_owner_lock(_path: &Path, _owner_lock: &File) -> Result<(), PersistError> {
    Err(PersistError::InvalidOwnerLock)
}

/// Decrypt and reconstruct the wallet state from `path`.
///
/// Verifies the v2 magic and envelope version (rejecting v1 files and unknown
/// versions before decryption), then the payload schema version. A wrong
/// password or tampered file fails with [`PersistError::Envelope`]
/// ([`dom_wallet_crypto::EnvelopeError::Decryption`]). The `OutputStore`
/// primary-key invariant is re-checked on deserialization. Never panics on a
/// bad file.
pub fn load_wallet_state(path: &Path, password: &str) -> Result<WalletV2State, PersistError> {
    let state: WalletV2State =
        dom_wallet_crypto::load_envelope(path, WALLET_V2_MAGIC, ENVELOPE_VERSION, password)?;

    if state.schema_version != SCHEMA_VERSION {
        return Err(PersistError::UnsupportedSchema(state.schema_version));
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::{PendingSlate, SlateLifecycle, SlateRole, SlateSecrets};
    use crate::store::OutputStore;
    use crate::types::{
        BlockRef, DerivIndex, Network, OutputOrigin, OutputStatus, PayoutForV1, StoredOutput,
    };
    use zeroize::Zeroizing;

    /// Distinctive 64-byte seed pattern, so the "not in plaintext" scan is exact.
    const SEED: [u8; 64] = [0x5eu8; 64];
    /// A non-derivable (random) blinding on the reorged receive output.
    const RECEIVE_BLINDING: [u8; 32] = [0x9au8; 32];
    /// Distinctive slate-secret patterns (sender excess / nonce / receiver output).
    const EXCESS: [u8; 32] = [0xe1u8; 32];
    const NONCE: [u8; 32] = [0xe2u8; 32];
    const OUTPUT_BLINDING: [u8; 32] = [0xe3u8; 32];

    /// Two in-flight slates carrying secrets — a sender and a receiver.
    fn populated_pending_slates() -> Vec<PendingSlate> {
        vec![
            PendingSlate {
                slate_hash: [0xa1u8; 32],
                role: SlateRole::Sender,
                slate_bytes: vec![1, 2, 3, 4],
                secrets: Some(SlateSecrets::Sender {
                    excess_blinding: Zeroizing::new(EXCESS),
                    nonce: Zeroizing::new(NONCE),
                }),
                reserved_inputs: vec![[0x01u8; 33]],
                produced_output: Some([0xCCu8; 33]),
                finalized_tx: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                status: SlateLifecycle::Finalized,
            },
            PendingSlate {
                slate_hash: [0xb2u8; 32],
                role: SlateRole::Receiver,
                slate_bytes: vec![5, 6, 7],
                secrets: Some(SlateSecrets::Receiver {
                    output_blinding: Zeroizing::new(OUTPUT_BLINDING),
                }),
                reserved_inputs: vec![],
                produced_output: Some([0xC7u8; 33]),
                finalized_tx: None,
                status: SlateLifecycle::Submitted,
            },
        ]
    }

    /// A store holding one output of each origin, in different statuses.
    fn populated_store() -> OutputStore {
        let mut store = OutputStore::new();

        let mut coinbase = StoredOutput::new_unconfirmed(
            [0x01u8; 33],
            1000,
            [0x11u8; 32],
            OutputOrigin::Coinbase,
            true,
            Some(DerivIndex::CoinbaseHeight(1)),
            1000,
        );
        coinbase
            .confirm(
                BlockRef {
                    height: 1,
                    hash: [1u8; 32],
                },
                1000,
            )
            .unwrap();
        store.insert(coinbase).unwrap();

        // Receive-slate, reorged (random blinding) — must survive intact.
        let mut receive = StoredOutput::new_unconfirmed(
            [0xC7u8; 33],
            500,
            RECEIVE_BLINDING,
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1001,
        );
        receive
            .confirm(
                BlockRef {
                    height: 2,
                    hash: [2u8; 32],
                },
                1001,
            )
            .unwrap();
        receive.mark_reorged(1002).unwrap();
        receive
            .pin_payout(PayoutForV1::new([0xD4; 32]).unwrap(), 1003)
            .unwrap();
        store.insert(receive).unwrap();

        store
            .insert(StoredOutput::new_unconfirmed(
                [0xCCu8; 33],
                400,
                [0xcau8; 32],
                OutputOrigin::Change,
                false,
                None,
                1003,
            ))
            .unwrap();

        store
    }

    /// A full wallet state: outputs + a keychain carrying the seed + meta cursors.
    fn populated_state() -> WalletV2State {
        let mut state = WalletV2State::new(Network::Regtest, [0x7eu8; 32]);
        state.keychain.seed_bytes = Some(Zeroizing::new(SEED));
        state.keychain.seed_word_count = Some(24);
        state.keychain.next_change_index = 3;
        state.keychain.next_receive_index = 5;
        state.keychain.account = 0;
        state.meta.last_reconciled_tip = 42;
        state.meta.last_reconciled_hash = Some([0x42u8; 32]);
        state.outputs = populated_store();
        state.pending_slates = populated_pending_slates();
        state
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let state = populated_state();

        save_wallet_state(&state, &path, "pw").unwrap();
        let back = load_wallet_state(&path, "pw").unwrap();

        // Identity + cursors.
        assert_eq!(back.schema_version, state.schema_version);
        assert_eq!(back.network, Network::Regtest);
        assert_eq!(back.chain_id, [0x7eu8; 32]);
        assert_eq!(back.meta, state.meta);
        // Keychain (including the seed).
        assert_eq!(back.keychain.seed_bytes.as_ref().unwrap()[..], SEED[..]);
        assert_eq!(back.keychain.seed_word_count, Some(24));
        assert_eq!(back.keychain.next_change_index, 3);
        assert_eq!(back.keychain.next_receive_index, 5);
        // Outputs (status / blinding / origin_block).
        assert_eq!(back.outputs.len(), state.outputs.len());
        for original in state.outputs.iter() {
            let b = back.outputs.get(&original.commitment).unwrap();
            assert_eq!(b.value, original.value);
            assert_eq!(*b.blinding, *original.blinding);
            assert_eq!(b.status, original.status);
            assert_eq!(b.origin_block, original.origin_block);
            assert_eq!(b.derivable, original.derivable);
        }
        let receive = back.outputs.get(&[0xC7u8; 33]).unwrap();
        assert_eq!(receive.status, OutputStatus::Reorged);
        assert_eq!(
            receive.payout_for(),
            Some(PayoutForV1::new([0xD4; 32]).unwrap())
        );

        // Pending slates (and their secrets) round-trip.
        assert_eq!(back.pending_slates.len(), 2);
        let sender = back
            .pending_slates
            .iter()
            .find(|p| p.role == SlateRole::Sender)
            .unwrap();
        assert_eq!(sender.slate_hash, [0xa1u8; 32]);
        assert_eq!(sender.reserved_inputs, vec![[0x01u8; 33]]);
        assert_eq!(sender.produced_output, Some([0xCCu8; 33]));
        assert_eq!(sender.finalized_tx, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(sender.status, SlateLifecycle::Finalized);
        match sender.secrets.as_ref() {
            Some(SlateSecrets::Sender {
                excess_blinding,
                nonce,
            }) => {
                assert_eq!(**excess_blinding, EXCESS);
                assert_eq!(**nonce, NONCE);
            }
            _ => panic!("expected sender secrets"),
        }
        let receiver = back
            .pending_slates
            .iter()
            .find(|p| p.role == SlateRole::Receiver)
            .unwrap();
        match receiver.secrets.as_ref() {
            Some(SlateSecrets::Receiver { output_blinding }) => {
                assert_eq!(**output_blinding, OUTPUT_BLINDING);
            }
            _ => panic!("expected receiver secrets"),
        }
    }

    #[test]
    fn slate_secrets_persist_encrypted_never_plaintext() {
        // The same rigor as the seed: in-flight slate secrets must never appear
        // in plaintext on disk, yet round-trip identically after decryption.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_wallet_state(&populated_state(), &path, "pw").unwrap();

        let raw = std::fs::read(&path).unwrap();
        for (label, secret) in [
            ("excess_blinding", EXCESS),
            ("nonce", NONCE),
            ("output_blinding", OUTPUT_BLINDING),
        ] {
            assert!(
                !raw.windows(32).any(|w| w == secret),
                "slate secret {label} leaked in plaintext on disk"
            );
        }

        // And Debug of the whole state must not leak them either.
        let dump = format!("{:?}", populated_state());
        for secret in [EXCESS, NONCE, OUTPUT_BLINDING] {
            let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
            assert!(!dump.contains(&hex), "slate secret leaked via Debug");
        }
        assert!(!dump.contains("e1, e1, e1"), "excess leaked via Debug");
        assert!(!dump.contains("e2, e2, e2"), "nonce leaked via Debug");
        assert!(
            !dump.contains("e3, e3, e3"),
            "output_blinding leaked via Debug"
        );

        // Decryption recovers them intact.
        let back = load_wallet_state(&path, "pw").unwrap();
        let sender = back
            .pending_slates
            .iter()
            .find(|p| p.role == SlateRole::Sender)
            .unwrap();
        match sender.secrets.as_ref() {
            Some(SlateSecrets::Sender {
                excess_blinding,
                nonce,
            }) => {
                assert_eq!(**excess_blinding, EXCESS);
                assert_eq!(**nonce, NONCE);
            }
            _ => panic!("expected sender secrets"),
        }
    }

    #[test]
    fn seed_and_blinding_persist_encrypted_never_plaintext() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_wallet_state(&populated_state(), &path, "pw").unwrap();

        let raw = std::fs::read(&path).unwrap();
        // Neither the seed nor a blinding may appear in plaintext on disk.
        assert!(
            !raw.windows(64).any(|w| w == SEED),
            "seed leaked in plaintext on disk"
        );
        assert!(
            !raw.windows(32).any(|w| w == RECEIVE_BLINDING),
            "blinding leaked in plaintext on disk"
        );

        // …but both come back identical after decryption.
        let back = load_wallet_state(&path, "pw").unwrap();
        assert_eq!(back.keychain.seed_bytes.as_ref().unwrap()[..], SEED[..]);
        assert_eq!(
            *back.outputs.get(&[0xC7u8; 33]).unwrap().blinding,
            RECEIVE_BLINDING
        );
    }

    #[test]
    fn debug_redacts_seed_and_blinding() {
        let state = populated_state();
        let dump = format!("{state:?}");
        assert!(dump.contains("<redacted>"), "expected redaction markers");
        // The raw seed / blinding bytes must not show up in Debug output.
        let seed_hex: String = SEED.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dump.contains(&seed_hex), "seed bytes leaked via Debug");
        assert!(!dump.contains("5e, 5e, 5e"), "seed bytes leaked via Debug");
        assert!(
            !dump.contains("9a, 9a, 9a"),
            "blinding bytes leaked via Debug"
        );
    }

    #[test]
    fn wrong_password_is_rejected_without_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_wallet_state(&populated_state(), &path, "pw").unwrap();

        let err = load_wallet_state(&path, "wrong").unwrap_err();
        assert!(
            matches!(
                err,
                PersistError::Envelope(dom_wallet_crypto::EnvelopeError::Decryption)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn v1_magic_file_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        dom_wallet_crypto::save_envelope(
            &path,
            b"DOM-WALLET-V1\0",
            1,
            &WalletV2State::new(Network::Regtest, [0u8; 32]),
            "pw",
        )
        .unwrap();

        let err = load_wallet_state(&path, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                PersistError::Envelope(dom_wallet_crypto::EnvelopeError::BadMagic)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_envelope_version_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        dom_wallet_crypto::save_envelope(
            &path,
            WALLET_V2_MAGIC,
            ENVELOPE_VERSION + 1,
            &WalletV2State::new(Network::Regtest, [0u8; 32]),
            "pw",
        )
        .unwrap();

        let err = load_wallet_state(&path, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                PersistError::Envelope(dom_wallet_crypto::EnvelopeError::UnsupportedVersion(v))
                    if v == ENVELOPE_VERSION + 1
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_payload_schema_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let mut future = WalletV2State::new(Network::Regtest, [0u8; 32]);
        future.schema_version = SCHEMA_VERSION + 7;
        dom_wallet_crypto::save_envelope(&path, WALLET_V2_MAGIC, ENVELOPE_VERSION, &future, "pw")
            .unwrap();

        let err = load_wallet_state(&path, "pw").unwrap_err();
        assert!(
            matches!(err, PersistError::UnsupportedSchema(v) if v == SCHEMA_VERSION + 7),
            "got {err:?}"
        );
    }

    #[cfg(unix)]
    fn open_migration_lock(path: &Path) -> File {
        use std::fs::OpenOptions;
        use std::os::unix::fs::PermissionsExt;

        let lock_path = migration_owner_lock_path(path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(lock_path)
            .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        file
    }

    #[cfg(unix)]
    fn migration_lock(path: &Path) -> File {
        let file = open_migration_lock(path);
        fs2::FileExt::try_lock_exclusive(&file).unwrap();
        file
    }

    #[cfg(unix)]
    #[test]
    fn legacy_v2_golden_requires_owner_locked_atomic_migration() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let mut legacy = WalletV2State::new(Network::Regtest, [0x7E; 32]);
        legacy
            .outputs
            .insert(StoredOutput::new_unconfirmed(
                [0xC7; 33],
                500,
                RECEIVE_BLINDING,
                OutputOrigin::ReceiveSlate,
                false,
                None,
                1001,
            ))
            .unwrap();
        // Build an authentic pre-payout V2 fixture: no output may carry the
        // V3-only field, and skip_serializing_if makes its JSON shape identical
        // to the old schema.
        legacy.schema_version = LEGACY_SCHEMA_VERSION_V2;
        dom_wallet_crypto::save_envelope(&path, WALLET_V2_MAGIC, ENVELOPE_VERSION, &legacy, "pw")
            .unwrap();
        assert!(matches!(
            load_wallet_state(&path, "pw").unwrap_err(),
            PersistError::UnsupportedSchema(LEGACY_SCHEMA_VERSION_V2)
        ));

        let mut lock = migration_lock(&path);
        assert_eq!(
            migrate_wallet_state_v2_to_v3_under_owner_lock(&path, "pw", &mut lock).unwrap(),
            WalletMigrationDispositionV1::MigratedV2ToV3
        );
        let migrated = load_wallet_state(&path, "pw").unwrap();
        assert_eq!(migrated.schema_version, SCHEMA_VERSION);
        assert!(migrated
            .outputs
            .iter()
            .all(|output| output.payout_for().is_none()));

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            migrate_wallet_state_v2_to_v3_under_owner_lock(&path, "pw", &mut lock).unwrap(),
            WalletMigrationDispositionV1::AlreadyCurrent
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_wrong_owner_lock_without_mutating_wallet() {
        use std::fs::OpenOptions;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_wallet_state(&populated_state(), &path, "pw").unwrap();
        let before = std::fs::read(&path).unwrap();
        let wrong_path = dir.path().join("unrelated.lock");
        let mut wrong = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(wrong_path)
            .unwrap();
        wrong
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(matches!(
            migrate_wallet_state_v2_to_v3_under_owner_lock(&path, "pw", &mut wrong).unwrap_err(),
            PersistError::InvalidOwnerLock
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn migration_acquires_and_retains_lock_on_an_unlocked_exact_handle() {
        use std::fs::OpenOptions;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_wallet_state(&populated_state(), &path, "pw").unwrap();
        let mut owner = open_migration_lock(&path);

        assert_eq!(
            migrate_wallet_state_v2_to_v3_under_owner_lock(&path, "pw", &mut owner).unwrap(),
            WalletMigrationDispositionV1::AlreadyCurrent
        );

        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(migration_owner_lock_path(&path))
            .unwrap();
        let error = fs2::FileExt::try_lock_exclusive(&contender).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_second_handle_lock_without_decrypt_or_mutation() {
        use std::fs::OpenOptions;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let mut legacy = WalletV2State::new(Network::Regtest, [0x73; 32]);
        legacy.schema_version = LEGACY_SCHEMA_VERSION_V2;
        dom_wallet_crypto::save_envelope(&path, WALLET_V2_MAGIC, ENVELOPE_VERSION, &legacy, "pw")
            .unwrap();
        let before = std::fs::read(&path).unwrap();

        let _owner = migration_lock(&path);
        let mut contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(migration_owner_lock_path(&path))
            .unwrap();
        assert!(matches!(
            migrate_wallet_state_v2_to_v3_under_owner_lock(&path, "wrong-password", &mut contender)
                .unwrap_err(),
            PersistError::ProcessLocked
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_a_v3_pin_disguised_as_legacy_without_mutation() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let mut disguised = populated_state();
        disguised.schema_version = LEGACY_SCHEMA_VERSION_V2;
        dom_wallet_crypto::save_envelope(
            &path,
            WALLET_V2_MAGIC,
            ENVELOPE_VERSION,
            &disguised,
            "pw",
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut lock = migration_lock(&path);
        assert!(matches!(
            migrate_wallet_state_v2_to_v3_under_owner_lock(&path, "pw", &mut lock).unwrap_err(),
            PersistError::LegacyContainsPayoutPin
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn ordinary_save_refuses_a_legacy_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let mut state = WalletV2State::new(Network::Regtest, [1; 32]);
        state.schema_version = LEGACY_SCHEMA_VERSION_V2;
        assert!(matches!(
            save_wallet_state(&state, &path, "pw").unwrap_err(),
            PersistError::UnsupportedSchema(LEGACY_SCHEMA_VERSION_V2)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn tampered_file_is_rejected_without_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_wallet_state(&populated_state(), &path, "pw").unwrap();

        let mut data = std::fs::read(&path).unwrap();
        let n = data.len();
        data[n - 8] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let err = load_wallet_state(&path, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                PersistError::Envelope(dom_wallet_crypto::EnvelopeError::Decryption)
            ),
            "got {err:?}"
        );
    }
}

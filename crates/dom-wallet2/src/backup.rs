//! Encrypted store export / import — `wallet.dombak` (design §2.7).
//!
//! The backup is a **self-contained, encrypted snapshot of the output set**,
//! written through the same shared [`dom_wallet_crypto`] envelope as the wallet
//! file, but with its own magic ([`BACKUP_MAGIC`]) and its own passphrase. Its
//! purpose is to recover the **non-derivable** outputs (receive-slate, change)
//! whose random blindings — by Mimblewimble construction — exist nowhere but
//! the store; the seed alone cannot rebuild them.
//!
//! ## Magic length note (deviation from §2.7.1)
//! §2.7.1 sketches a 15-byte magic `DOM-WALLET-BAK\0`. The shared envelope's
//! header is byte-identical to v1's `wallet.dat` (14-byte magic + 4-byte pad),
//! and §2.7 mandates *"reuse the same crypto envelope ... no new crypto"*. The
//! stronger principle wins: we use a **14-byte** magic `DOM-WALLET-BAK` (the
//! design name without the trailing NUL). `wallet.dombak` is a brand-new
//! artifact, so there is no backward-compatibility constraint.
//!
//! ## Non-destructive import (the INV-RET guarantee)
//! [`import_backup`] **merges** into the current store via
//! [`OutputStore::merge_backup`]: it inserts missing outputs and, for outputs
//! present in both, keeps the status of higher [`crate::OutputStatus::merge_rank`]
//! — never downgrading, never deleting. After importing, the caller SHOULD run
//! [`crate::reconcile`] to bring statuses up to the current tip (§2.7).
//!
//! ## Scope note (3D)
//! This carries the output set (the funds the seed cannot recover). The full
//! `BackupV2Envelope` of §2.7.1 (keychain seed superset, pending slates,
//! chain_id, network, meta) gains those fields with their features in later
//! sub-steps, gated by `schema_version` — same staging as 3C.

use crate::store::{MergeReport, OutputStore, StoreError};
use crate::types::StoredOutput;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Backup file magic. 14 bytes, distinct from `wallet.dat` v1
/// (`DOM-WALLET-V1\0`) and v2 (`DOM-WALLET-V2\0`), so a store file or a v1 file
/// is rejected by the backup loader (and vice versa).
pub const BACKUP_MAGIC: &[u8; dom_wallet_crypto::MAGIC_LEN] = b"DOM-WALLET-BAK";

/// Backup envelope (file-format) version written in the header (§2.7.1 = 1).
pub const BACKUP_VERSION: u16 = 1;

/// Backup payload schema version; an unknown value is rejected, gating future
/// growth of [`BackupEnvelopeV2`].
pub const BACKUP_SCHEMA: u16 = 2;

/// Errors from exporting / importing a backup.
#[derive(Debug, Error)]
pub enum BackupError {
    /// Key derivation / AEAD / IO / header-validation error from the shared
    /// envelope (wrong passphrase and tampering surface as
    /// [`dom_wallet_crypto::EnvelopeError::Decryption`]; a store/v1 file as
    /// [`dom_wallet_crypto::EnvelopeError::BadMagic`]).
    #[error(transparent)]
    Envelope(#[from] dom_wallet_crypto::EnvelopeError),
    /// The decrypted backup declares a schema this build does not understand.
    #[error("unsupported backup schema version: {0}")]
    UnsupportedSchema(u16),
    /// The decrypted output set violated a store invariant.
    #[error("invalid backup contents: {0}")]
    Store(#[from] StoreError),
}

/// The serialized backup payload. Versioned independently of the envelope.
#[derive(Serialize, Deserialize)]
struct BackupEnvelopeV2 {
    schema_version: u16,
    /// Informational unix timestamp of the export (caller-supplied; kept as data
    /// so this module stays pure / deterministically testable).
    exported_at: u64,
    outputs: Vec<StoredOutput>,
}

/// Write an encrypted backup of the whole output set to `path`.
///
/// `passphrase` is the backup's own secret (independent of any wallet password)
/// so a backup can be restored on another machine. `exported_at` is recorded as
/// informational metadata.
pub fn export_backup(
    store: &OutputStore,
    path: &Path,
    passphrase: &str,
    exported_at: u64,
) -> Result<(), BackupError> {
    let payload = BackupEnvelopeV2 {
        schema_version: BACKUP_SCHEMA,
        exported_at,
        outputs: store.iter().cloned().collect(),
    };
    dom_wallet_crypto::save_envelope(path, BACKUP_MAGIC, BACKUP_VERSION, &payload, passphrase)?;
    Ok(())
}

/// Decrypt a backup and **non-destructively merge** it into `store`
/// (design §2.7). Returns the [`MergeReport`].
///
/// Rejects a `wallet.dat` (store) file or a v1 file by magic, and an unknown
/// envelope/payload version, before/after decryption — never a panic. Importing
/// into an empty store is a pure restore (every output is inserted); importing
/// into a populated store recovers what is missing without overwriting,
/// downgrading or deleting anything (INV-RET). Run [`crate::reconcile`] after to
/// reconcile statuses against the current tip.
pub fn import_backup(
    store: &mut OutputStore,
    path: &Path,
    passphrase: &str,
) -> Result<MergeReport, BackupError> {
    let payload: BackupEnvelopeV2 =
        dom_wallet_crypto::load_envelope(path, BACKUP_MAGIC, BACKUP_VERSION, passphrase)?;

    if payload.schema_version != BACKUP_SCHEMA {
        return Err(BackupError::UnsupportedSchema(payload.schema_version));
    }

    Ok(store.merge_backup(payload.outputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BlockRef, OutputOrigin, OutputStatus};

    fn confirmed_output(tag: u8, value: u64, origin: OutputOrigin, h: u64) -> StoredOutput {
        let mut commitment = [0u8; 33];
        commitment[0] = tag;
        let mut o =
            StoredOutput::new_unconfirmed(commitment, value, [tag; 32], origin, false, None, 1000);
        o.confirm(
            BlockRef {
                height: h,
                hash: [h as u8; 32],
            },
            1000,
        )
        .unwrap();
        o
    }

    fn unconfirmed_output(tag: u8, value: u64, origin: OutputOrigin) -> StoredOutput {
        let mut commitment = [0u8; 33];
        commitment[0] = tag;
        StoredOutput::new_unconfirmed(commitment, value, [tag; 32], origin, false, None, 1000)
    }

    fn key(tag: u8) -> [u8; 33] {
        let mut c = [0u8; 33];
        c[0] = tag;
        c
    }

    #[test]
    fn export_import_round_trip_into_empty_store_restores_all() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dombak");

        let mut source = OutputStore::new();
        source
            .insert(confirmed_output(1, 1000, OutputOrigin::Coinbase, 1))
            .unwrap();
        source
            .insert(confirmed_output(2, 500, OutputOrigin::ReceiveSlate, 2))
            .unwrap();
        source
            .insert(unconfirmed_output(3, 400, OutputOrigin::Change))
            .unwrap();
        export_backup(&source, &path, "bakpass", 1_700_000_000).unwrap();

        let mut restored = OutputStore::new();
        let report = import_backup(&mut restored, &path, "bakpass").unwrap();
        assert_eq!(report.inserted, 3);
        assert_eq!(report.advanced, 0);
        assert_eq!(report.kept, 0);
        assert_eq!(restored.len(), 3);

        for original in source.iter() {
            let back = restored.get(&original.commitment).unwrap();
            assert_eq!(back.value, original.value);
            assert_eq!(*back.blinding, *original.blinding);
            assert_eq!(back.status, original.status);
            assert_eq!(back.origin_block, original.origin_block);
        }
    }

    #[test]
    fn import_is_non_destructive_recovers_missing_only() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dombak");

        // Backup holds outputs 1 (coinbase) and 2 (receive).
        let mut backup_src = OutputStore::new();
        backup_src
            .insert(confirmed_output(1, 1000, OutputOrigin::Coinbase, 1))
            .unwrap();
        backup_src
            .insert(confirmed_output(2, 500, OutputOrigin::ReceiveSlate, 2))
            .unwrap();
        export_backup(&backup_src, &path, "pw", 1).unwrap();

        // Current store already has output 1 (same status) and a local output 9
        // NOT in the backup — which must be preserved.
        let mut store = OutputStore::new();
        store
            .insert(confirmed_output(1, 1000, OutputOrigin::Coinbase, 1))
            .unwrap();
        store
            .insert(unconfirmed_output(9, 42, OutputOrigin::Change))
            .unwrap();

        let report = import_backup(&mut store, &path, "pw").unwrap();
        assert_eq!(report.inserted, 1, "only the missing output 2 is inserted");
        assert_eq!(report.kept, 1, "output 1 already present, same status");
        assert_eq!(store.len(), 3, "1 (kept) + 9 (preserved) + 2 (recovered)");
        // The local-only output 9 is untouched.
        assert!(
            store.get(&key(9)).is_some(),
            "local output not deleted by import"
        );
        assert_eq!(store.get(&key(2)).unwrap().value, 500);
    }

    #[test]
    fn stale_backup_never_downgrades_a_spent_output() {
        // Backup (stale) has output 1 as Confirmed; the store has since spent it.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dombak");
        let mut backup_src = OutputStore::new();
        backup_src
            .insert(confirmed_output(1, 1000, OutputOrigin::Coinbase, 1))
            .unwrap();
        export_backup(&backup_src, &path, "pw", 1).unwrap();

        let mut store = OutputStore::new();
        let mut spent = confirmed_output(1, 1000, OutputOrigin::Coinbase, 1);
        spent.mark_spent(2000).unwrap();
        store.insert(spent).unwrap();

        let report = import_backup(&mut store, &path, "pw").unwrap();
        assert_eq!(report.kept, 1);
        assert_eq!(report.advanced, 0);
        assert_eq!(
            store.get(&key(1)).unwrap().status,
            OutputStatus::Spent,
            "stale backup must NOT pull Spent back to Confirmed"
        );
    }

    #[test]
    fn backup_advances_a_more_stale_store_status() {
        // The reverse: the store has output 1 Unconfirmed; a (newer) backup has
        // it Confirmed. The merge adopts the more advanced status.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dombak");
        let mut backup_src = OutputStore::new();
        backup_src
            .insert(confirmed_output(1, 1000, OutputOrigin::Coinbase, 5))
            .unwrap();
        export_backup(&backup_src, &path, "pw", 1).unwrap();

        let mut store = OutputStore::new();
        store
            .insert(unconfirmed_output(1, 1000, OutputOrigin::Coinbase))
            .unwrap();

        let report = import_backup(&mut store, &path, "pw").unwrap();
        assert_eq!(report.advanced, 1);
        let merged = store.get(&key(1)).unwrap();
        assert_eq!(merged.status, OutputStatus::Confirmed);
        assert_eq!(merged.origin_block.unwrap().height, 5);
    }

    #[test]
    fn wrong_passphrase_is_rejected_without_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dombak");
        let mut src = OutputStore::new();
        src.insert(unconfirmed_output(1, 1, OutputOrigin::Change))
            .unwrap();
        export_backup(&src, &path, "right", 1).unwrap();

        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "wrong").unwrap_err();
        assert!(
            matches!(
                err,
                BackupError::Envelope(dom_wallet_crypto::EnvelopeError::Decryption)
            ),
            "got {err:?}"
        );
        assert!(store.is_empty(), "failed import left the store untouched");
    }

    #[test]
    fn store_file_is_rejected_by_backup_loader() {
        // A v2 store file (wallet.dat) must NOT be importable as a backup.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let mut src = OutputStore::new();
        src.insert(unconfirmed_output(1, 1, OutputOrigin::Change))
            .unwrap();
        crate::persist::save_store(&src, &path, "pw").unwrap();

        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                BackupError::Envelope(dom_wallet_crypto::EnvelopeError::BadMagic)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn v1_magic_file_is_rejected_by_backup_loader() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("legacy");
        dom_wallet_crypto::save_envelope(
            &path,
            b"DOM-WALLET-V1\0",
            1,
            &BackupEnvelopeV2 {
                schema_version: BACKUP_SCHEMA,
                exported_at: 0,
                outputs: vec![],
            },
            "pw",
        )
        .unwrap();
        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                BackupError::Envelope(dom_wallet_crypto::EnvelopeError::BadMagic)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn backup_file_is_rejected_by_the_store_loader() {
        // Symmetry: a backup must NOT load as a store.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dombak");
        let mut src = OutputStore::new();
        src.insert(unconfirmed_output(1, 1, OutputOrigin::Change))
            .unwrap();
        export_backup(&src, &path, "pw", 1).unwrap();

        let err = crate::persist::load_store(&path, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                crate::PersistError::Envelope(dom_wallet_crypto::EnvelopeError::BadMagic)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_backup_schema_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dombak");
        dom_wallet_crypto::save_envelope(
            &path,
            BACKUP_MAGIC,
            BACKUP_VERSION,
            &BackupEnvelopeV2 {
                schema_version: BACKUP_SCHEMA + 9,
                exported_at: 0,
                outputs: vec![],
            },
            "pw",
        )
        .unwrap();
        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "pw").unwrap_err();
        assert!(
            matches!(err, BackupError::UnsupportedSchema(v) if v == BACKUP_SCHEMA + 9),
            "got {err:?}"
        );
    }
}

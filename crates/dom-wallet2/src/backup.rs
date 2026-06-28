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
use crate::wallet_state::WalletV2State;
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
pub const BACKUP_SCHEMA: u16 = 3;

/// Full wallet-state backup payload schema.
pub const FULL_BACKUP_SCHEMA: u16 = 4;

/// Explicit backup payload kind. Legacy schema-3 files omit this field and are
/// interpreted as [`BackupKind::OutputStore`] by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupKind {
    /// Legacy non-destructive output-store backup.
    #[default]
    OutputStore,
    /// Complete [`WalletV2State`] backup.
    WalletState,
}

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
    /// The backup belongs to a different chain than the destination wallet.
    #[error("backup chain id does not match wallet chain id")]
    ChainMismatch,
    /// The decrypted payload is not the kind expected by the import API used.
    #[error("backup kind mismatch: expected {expected:?}, got {actual:?}")]
    KindMismatch {
        /// Kind expected by the caller.
        expected: BackupKind,
        /// Kind found in the payload.
        actual: BackupKind,
    },
    /// A full backup payload was missing its wallet state.
    #[error("full backup payload missing wallet state")]
    MissingWalletState,
}

/// The serialized backup payload. Versioned independently of the envelope.
#[derive(Serialize, Deserialize)]
struct BackupEnvelopeV2 {
    schema_version: u16,
    /// Distinguishes legacy output-store backups from full wallet-state backups.
    #[serde(default)]
    kind: BackupKind,
    /// Chain identifier of the wallet that produced the backup.
    #[serde(default)]
    chain_id: [u8; 32],
    /// Informational unix timestamp of the export (caller-supplied; kept as data
    /// so this module stays pure / deterministically testable).
    exported_at: u64,
    #[serde(default)]
    outputs: Vec<StoredOutput>,
    /// Complete wallet state for schema-4 full backups.
    #[serde(default)]
    wallet_state: Option<WalletV2State>,
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
    chain_id: [u8; 32],
    exported_at: u64,
) -> Result<(), BackupError> {
    let payload = BackupEnvelopeV2 {
        schema_version: BACKUP_SCHEMA,
        kind: BackupKind::OutputStore,
        chain_id,
        exported_at,
        outputs: store.iter().cloned().collect(),
        wallet_state: None,
    };
    dom_wallet_crypto::save_envelope(path, BACKUP_MAGIC, BACKUP_VERSION, &payload, passphrase)?;
    Ok(())
}

/// Write an encrypted, authenticated backup of the complete wallet v2 state.
///
/// This is intentionally separate from [`export_backup`]: the legacy API
/// remains an output-store snapshot for non-destructive merges, while this API
/// captures the seed/keychain, output store, pending slates, finalized tx bytes,
/// slate secrets and reconciliation metadata already present in
/// [`WalletV2State`].
pub fn export_full_backup(
    state: &WalletV2State,
    path: &Path,
    passphrase: &str,
    exported_at: u64,
) -> Result<(), BackupError> {
    let payload = BackupEnvelopeV2 {
        schema_version: FULL_BACKUP_SCHEMA,
        kind: BackupKind::WalletState,
        chain_id: state.chain_id,
        exported_at,
        outputs: Vec::new(),
        wallet_state: Some(state.clone()),
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
    expected_chain_id: [u8; 32],
) -> Result<MergeReport, BackupError> {
    let payload: BackupEnvelopeV2 =
        dom_wallet_crypto::load_envelope(path, BACKUP_MAGIC, BACKUP_VERSION, passphrase)?;

    if payload.schema_version != BACKUP_SCHEMA {
        return Err(BackupError::UnsupportedSchema(payload.schema_version));
    }
    if payload.kind != BackupKind::OutputStore {
        return Err(BackupError::KindMismatch {
            expected: BackupKind::OutputStore,
            actual: payload.kind,
        });
    }
    if payload.chain_id != expected_chain_id {
        return Err(BackupError::ChainMismatch);
    }

    Ok(store.merge_backup(payload.outputs))
}

/// Decrypt and return a complete [`WalletV2State`] backup.
///
/// This API does not merge into an existing wallet and therefore cannot
/// silently overwrite newer local state. Callers restore the returned state into
/// an explicit destination, then run chain reconciliation against their node.
pub fn import_full_backup(
    path: &Path,
    passphrase: &str,
    expected_chain_id: [u8; 32],
) -> Result<WalletV2State, BackupError> {
    let payload: BackupEnvelopeV2 =
        dom_wallet_crypto::load_envelope(path, BACKUP_MAGIC, BACKUP_VERSION, passphrase)?;

    if payload.schema_version != FULL_BACKUP_SCHEMA {
        return Err(BackupError::UnsupportedSchema(payload.schema_version));
    }
    if payload.kind != BackupKind::WalletState {
        return Err(BackupError::KindMismatch {
            expected: BackupKind::WalletState,
            actual: payload.kind,
        });
    }
    if payload.chain_id != expected_chain_id {
        return Err(BackupError::ChainMismatch);
    }

    let state = payload
        .wallet_state
        .ok_or(BackupError::MissingWalletState)?;
    if state.chain_id != expected_chain_id {
        return Err(BackupError::ChainMismatch);
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::{PendingSlate, SlateLifecycle, SlateRole, SlateSecrets};
    use crate::tx_sink::InMemoryTxSink;
    use crate::types::{
        BlockRef, DerivIndex, KeychainV2, Network, OutputOrigin, OutputStatus, StoreMeta,
    };
    use crate::{create_send, receive, submit_finalized};
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use zeroize::Zeroizing;

    const CHAIN_ID: [u8; 32] = [0xA5; 32];
    const FULL_CHAIN_ID: [u8; 32] = [0x7E; 32];
    const FOREIGN_CHAIN_ID: [u8; 32] = [0xF0; 32];
    const SEED: [u8; 64] = [0x5e; 64];
    const EXCESS: [u8; 32] = [0xe1; 32];
    const NONCE: [u8; 32] = [0xe2; 32];
    const OUTPUT_BLINDING: [u8; 32] = [0xe3; 32];

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

    fn spendable_output(value: u64, height: u64) -> StoredOutput {
        let blinding = BlindingFactor::random();
        let commitment = *Commitment::commit(value, &blinding).as_bytes();
        let mut output = StoredOutput::new_unconfirmed(
            commitment,
            value,
            *blinding.as_bytes(),
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1000,
        );
        output
            .confirm(
                BlockRef {
                    height,
                    hash: [height as u8; 32],
                },
                1000,
            )
            .unwrap();
        output
    }

    fn key(tag: u8) -> [u8; 33] {
        let mut c = [0u8; 33];
        c[0] = tag;
        c
    }

    fn keychain() -> KeychainV2 {
        KeychainV2 {
            seed_bytes: Some(Zeroizing::new(SEED)),
            seed_word_count: Some(24),
            next_change_index: 3,
            next_receive_index: 5,
            account: 0,
        }
    }

    fn populated_pending_slates() -> Vec<PendingSlate> {
        vec![
            PendingSlate {
                slate_hash: [0xa1; 32],
                role: SlateRole::Sender,
                slate_bytes: vec![1, 2, 3, 4],
                secrets: Some(SlateSecrets::Sender {
                    excess_blinding: Zeroizing::new(EXCESS),
                    nonce: Zeroizing::new(NONCE),
                }),
                reserved_inputs: vec![[0x01; 33]],
                produced_output: Some([0xCC; 33]),
                finalized_tx: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                status: SlateLifecycle::Finalized,
            },
            PendingSlate {
                slate_hash: [0xb2; 32],
                role: SlateRole::Receiver,
                slate_bytes: vec![5, 6, 7],
                secrets: Some(SlateSecrets::Receiver {
                    output_blinding: Zeroizing::new(OUTPUT_BLINDING),
                }),
                reserved_inputs: vec![],
                produced_output: Some([0xC7; 33]),
                finalized_tx: None,
                status: SlateLifecycle::Submitted,
            },
        ]
    }

    fn populated_full_state() -> WalletV2State {
        let mut state = WalletV2State::new(Network::Regtest, FULL_CHAIN_ID);
        state.keychain = keychain();
        state.meta = StoreMeta {
            last_reconciled_tip: 42,
            last_reconciled_hash: Some([0x42; 32]),
        };
        state
            .outputs
            .insert(confirmed_output(1, 1000, OutputOrigin::Coinbase, 1))
            .unwrap();
        let mut receive = confirmed_output(2, 500, OutputOrigin::ReceiveSlate, 2);
        receive.derivable = Some(DerivIndex::ReceiveRequest(7));
        state.outputs.insert(receive).unwrap();
        state
            .outputs
            .insert(unconfirmed_output(3, 400, OutputOrigin::Change))
            .unwrap();
        state.pending_slates = populated_pending_slates();
        state
    }

    fn assert_full_state_eq(actual: &WalletV2State, expected: &WalletV2State) {
        assert_eq!(actual.schema_version, expected.schema_version);
        assert_eq!(actual.network, expected.network);
        assert_eq!(actual.chain_id, expected.chain_id);
        assert_eq!(actual.meta, expected.meta);
        assert_eq!(
            actual.keychain.seed_bytes.as_ref().map(|s| &s[..]),
            expected.keychain.seed_bytes.as_ref().map(|s| &s[..])
        );
        assert_eq!(
            actual.keychain.seed_word_count,
            expected.keychain.seed_word_count
        );
        assert_eq!(
            actual.keychain.next_change_index,
            expected.keychain.next_change_index
        );
        assert_eq!(
            actual.keychain.next_receive_index,
            expected.keychain.next_receive_index
        );
        assert_eq!(actual.keychain.account, expected.keychain.account);
        assert_eq!(actual.outputs.len(), expected.outputs.len());
        for original in expected.outputs.iter() {
            let back = actual.outputs.get(&original.commitment).unwrap();
            assert_eq!(back.value, original.value);
            assert_eq!(*back.blinding, *original.blinding);
            assert_eq!(back.origin, original.origin);
            assert_eq!(back.status, original.status);
            assert_eq!(back.origin_block, original.origin_block);
            assert_eq!(back.derivable, original.derivable);
            assert_eq!(back.reserved_for, original.reserved_for);
            assert_eq!(back.created_at, original.created_at);
            assert_eq!(back.updated_at, original.updated_at);
        }
        assert_eq!(actual.pending_slates.len(), expected.pending_slates.len());
        for expected_slate in &expected.pending_slates {
            let actual_slate = actual
                .pending_slates
                .iter()
                .find(|slate| slate.slate_hash == expected_slate.slate_hash)
                .unwrap();
            assert_eq!(actual_slate.role, expected_slate.role);
            assert_eq!(actual_slate.slate_bytes, expected_slate.slate_bytes);
            assert_eq!(actual_slate.reserved_inputs, expected_slate.reserved_inputs);
            assert_eq!(actual_slate.produced_output, expected_slate.produced_output);
            assert_eq!(actual_slate.finalized_tx, expected_slate.finalized_tx);
            assert_eq!(actual_slate.status, expected_slate.status);
            match (&actual_slate.secrets, &expected_slate.secrets) {
                (
                    Some(SlateSecrets::Sender {
                        excess_blinding: a_excess,
                        nonce: a_nonce,
                    }),
                    Some(SlateSecrets::Sender {
                        excess_blinding: e_excess,
                        nonce: e_nonce,
                    }),
                ) => {
                    assert_eq!(**a_excess, **e_excess);
                    assert_eq!(**a_nonce, **e_nonce);
                }
                (
                    Some(SlateSecrets::Receiver { output_blinding: a }),
                    Some(SlateSecrets::Receiver { output_blinding: e }),
                ) => assert_eq!(**a, **e),
                (None, None) => {}
                _ => panic!("slate secrets mismatch"),
            }
        }
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
        export_backup(&source, &path, "bakpass", CHAIN_ID, 1_700_000_000).unwrap();

        let mut restored = OutputStore::new();
        let report = import_backup(&mut restored, &path, "bakpass", CHAIN_ID).unwrap();
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
    fn full_backup_round_trip_preserves_wallet_v2_state() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet-full.dombak");
        let state = populated_full_state();

        export_full_backup(&state, &path, "fullpass", 1_800_000_000).unwrap();
        let restored = import_full_backup(&path, "fullpass", FULL_CHAIN_ID).unwrap();

        assert_full_state_eq(&restored, &state);
    }

    #[test]
    fn full_backup_wrong_passphrase_rejected_without_mutation() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet-full.dombak");
        let state = populated_full_state();

        export_full_backup(&state, &path, "right", 1).unwrap();
        let err = import_full_backup(&path, "wrong", FULL_CHAIN_ID).unwrap_err();

        assert!(
            matches!(
                err,
                BackupError::Envelope(dom_wallet_crypto::EnvelopeError::Decryption)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn full_backup_rejects_foreign_chain_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet-full.dombak");
        let state = populated_full_state();

        export_full_backup(&state, &path, "pw", 1).unwrap();
        let err = import_full_backup(&path, "pw", FOREIGN_CHAIN_ID).unwrap_err();

        assert!(matches!(err, BackupError::ChainMismatch), "got {err:?}");
    }

    #[test]
    fn legacy_output_backup_still_imports_after_full_backup_schema_added() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("legacy-output.dombak");
        let mut src = OutputStore::new();
        src.insert(unconfirmed_output(7, 700, OutputOrigin::Change))
            .unwrap();

        export_backup(&src, &path, "pw", CHAIN_ID, 123).unwrap();
        let mut dst = OutputStore::new();
        let report = import_backup(&mut dst, &path, "pw", CHAIN_ID).unwrap();

        assert_eq!(report.inserted, 1);
        assert_eq!(dst.get(&key(7)).unwrap().value, 700);
        let err = import_full_backup(&path, "pw", CHAIN_ID).unwrap_err();
        assert!(
            matches!(err, BackupError::UnsupportedSchema(BACKUP_SCHEMA)),
            "got {err:?}"
        );
    }

    #[test]
    fn full_backup_file_not_loadable_as_wallet_dat() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet-full.dombak");
        let state = populated_full_state();

        export_full_backup(&state, &path, "pw", 1).unwrap();
        let err = crate::persist::load_wallet_state(&path, "pw").unwrap_err();

        assert!(
            matches!(
                err,
                crate::PersistError::Envelope(dom_wallet_crypto::EnvelopeError::BadMagic)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn wallet_dat_not_importable_as_full_backup() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let state = populated_full_state();

        crate::persist::save_wallet_state(&state, &path, "pw").unwrap();
        let err = import_full_backup(&path, "pw", FULL_CHAIN_ID).unwrap_err();

        assert!(
            matches!(
                err,
                BackupError::Envelope(dom_wallet_crypto::EnvelopeError::BadMagic)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn full_backup_pending_sender_slate_survives_restore_and_can_submit_finalized_tx() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sender-full.dombak");
        let mut sender = WalletV2State::new(Network::Regtest, FULL_CHAIN_ID);
        sender.meta.last_reconciled_tip = 100;
        sender.outputs.insert(spendable_output(1200, 10)).unwrap();
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let mut receiver = WalletV2State::new(Network::Regtest, FULL_CHAIN_ID);
        let answered = receive(&mut receiver, sent.slate, 3000).unwrap();
        let (_tx, slate_hash) = crate::finalize_tracked(&mut sender, answered, 4000).unwrap();
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
        assert!(sender.pending_slates[0].finalized_tx.is_some());

        export_full_backup(&sender, &path, "pw", 5000).unwrap();
        let mut restored = import_full_backup(&path, "pw", FULL_CHAIN_ID).unwrap();
        let expected_tx = sender.pending_slates[0].finalized_tx.clone();
        assert_eq!(restored.pending_slates[0].finalized_tx, expected_tx);
        assert!(restored.pending_slates[0].secrets.is_none());

        let sink = InMemoryTxSink::accepting([0x55; 32]);
        submit_finalized(&mut restored, &sink, slate_hash, 6000).unwrap();
        assert_eq!(restored.pending_slates[0].status, SlateLifecycle::Submitted);
    }

    #[test]
    fn full_backup_receiver_slate_preserves_output_blinding() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("receiver-full.dombak");
        let mut sender = WalletV2State::new(Network::Regtest, FULL_CHAIN_ID);
        sender.meta.last_reconciled_tip = 100;
        sender.outputs.insert(spendable_output(1200, 10)).unwrap();
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let mut receiver = WalletV2State::new(Network::Regtest, FULL_CHAIN_ID);
        let _answered = receive(&mut receiver, sent.slate, 3000).unwrap();
        let produced = receiver.pending_slates[0].produced_output.unwrap();
        let original_blinding = *receiver.outputs.get(&produced).unwrap().blinding;

        export_full_backup(&receiver, &path, "pw", 4000).unwrap();
        let restored = import_full_backup(&path, "pw", FULL_CHAIN_ID).unwrap();

        assert_eq!(
            *restored.outputs.get(&produced).unwrap().blinding,
            original_blinding
        );
        match restored.pending_slates[0].secrets.as_ref() {
            Some(SlateSecrets::Receiver { output_blinding }) => {
                assert_eq!(**output_blinding, original_blinding);
            }
            other => panic!("expected receiver secrets, got {other:?}"),
        }
    }

    #[test]
    fn full_backup_does_not_debug_or_log_secret_material() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet-full.dombak");
        let state = populated_full_state();

        export_full_backup(&state, &path, "pw", 1).unwrap();
        let restored = import_full_backup(&path, "pw", FULL_CHAIN_ID).unwrap();
        let dump = format!("{restored:?}");

        assert!(dump.contains("<redacted>"));
        assert!(!dump.contains("5e, 5e, 5e"), "seed leaked via Debug");
        assert!(
            !dump.contains("e1, e1, e1"),
            "sender excess leaked via Debug"
        );
        assert!(
            !dump.contains("e2, e2, e2"),
            "sender nonce leaked via Debug"
        );
        assert!(
            !dump.contains("e3, e3, e3"),
            "receiver output blinding leaked via Debug"
        );
        assert!(!dump.contains("pw"), "passphrase leaked via Debug");
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
        export_backup(&backup_src, &path, "pw", CHAIN_ID, 1).unwrap();

        // Current store already has output 1 (same status) and a local output 9
        // NOT in the backup — which must be preserved.
        let mut store = OutputStore::new();
        store
            .insert(confirmed_output(1, 1000, OutputOrigin::Coinbase, 1))
            .unwrap();
        store
            .insert(unconfirmed_output(9, 42, OutputOrigin::Change))
            .unwrap();

        let report = import_backup(&mut store, &path, "pw", CHAIN_ID).unwrap();
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
        export_backup(&backup_src, &path, "pw", CHAIN_ID, 1).unwrap();

        let mut store = OutputStore::new();
        let mut spent = confirmed_output(1, 1000, OutputOrigin::Coinbase, 1);
        spent.mark_spent(2000).unwrap();
        store.insert(spent).unwrap();

        let report = import_backup(&mut store, &path, "pw", CHAIN_ID).unwrap();
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
        export_backup(&backup_src, &path, "pw", CHAIN_ID, 1).unwrap();

        let mut store = OutputStore::new();
        store
            .insert(unconfirmed_output(1, 1000, OutputOrigin::Coinbase))
            .unwrap();

        let report = import_backup(&mut store, &path, "pw", CHAIN_ID).unwrap();
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
        export_backup(&src, &path, "right", CHAIN_ID, 1).unwrap();

        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "wrong", CHAIN_ID).unwrap_err();
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
        let mut state = crate::WalletV2State::new(crate::Network::Regtest, [0u8; 32]);
        state
            .outputs
            .insert(unconfirmed_output(1, 1, OutputOrigin::Change))
            .unwrap();
        crate::persist::save_wallet_state(&state, &path, "pw").unwrap();

        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "pw", CHAIN_ID).unwrap_err();
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
                kind: BackupKind::OutputStore,
                chain_id: CHAIN_ID,
                exported_at: 0,
                outputs: vec![],
                wallet_state: None,
            },
            "pw",
        )
        .unwrap();
        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "pw", CHAIN_ID).unwrap_err();
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
        export_backup(&src, &path, "pw", CHAIN_ID, 1).unwrap();

        let err = crate::persist::load_wallet_state(&path, "pw").unwrap_err();
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
                kind: BackupKind::OutputStore,
                chain_id: CHAIN_ID,
                exported_at: 0,
                outputs: vec![],
                wallet_state: None,
            },
            "pw",
        )
        .unwrap();
        let mut store = OutputStore::new();
        let err = import_backup(&mut store, &path, "pw", CHAIN_ID).unwrap_err();
        assert!(
            matches!(err, BackupError::UnsupportedSchema(v) if v == BACKUP_SCHEMA + 9),
            "got {err:?}"
        );
    }
}

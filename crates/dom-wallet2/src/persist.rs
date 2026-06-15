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
use crate::wallet_state::{WalletV2State, SCHEMA_VERSION};
use std::path::Path;
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
    dom_wallet_crypto::save_envelope(path, WALLET_V2_MAGIC, ENVELOPE_VERSION, state, password)?;
    Ok(())
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
    use crate::types::{BlockRef, DerivIndex, Network, OutputOrigin, OutputStatus, StoredOutput};
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
                secrets: SlateSecrets::Sender {
                    excess_blinding: Zeroizing::new(EXCESS),
                    nonce: Zeroizing::new(NONCE),
                },
                reserved_inputs: vec![[0x01u8; 33]],
                produced_output: Some([0xCCu8; 33]),
                status: SlateLifecycle::Built,
            },
            PendingSlate {
                slate_hash: [0xb2u8; 32],
                role: SlateRole::Receiver,
                slate_bytes: vec![5, 6, 7],
                secrets: SlateSecrets::Receiver {
                    output_blinding: Zeroizing::new(OUTPUT_BLINDING),
                },
                reserved_inputs: vec![],
                produced_output: Some([0xC7u8; 33]),
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
        assert_eq!(sender.status, SlateLifecycle::Built);
        match &sender.secrets {
            SlateSecrets::Sender {
                excess_blinding,
                nonce,
            } => {
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
        match &receiver.secrets {
            SlateSecrets::Receiver { output_blinding } => {
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
        match &sender.secrets {
            SlateSecrets::Sender {
                excess_blinding,
                nonce,
            } => {
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

//! At-rest persistence of the [`OutputStore`] (design §2.1–§2.3).
//!
//! The store is written to disk through the shared, audited
//! [`dom_wallet_crypto`] envelope — the same crypto v1 uses (Argon2id + HKDF
//! key derivation, ChaCha20Poly1305 AEAD, atomic write with fsync). The
//! blinding factors therefore persist **encrypted**, never in plaintext.
//!
//! ## Two-level versioning
//! - **Envelope:** magic [`WALLET_V2_MAGIC`] (`DOM-WALLET-V2\0`) + header
//!   [`ENVELOPE_VERSION`]. The magic rejects v1 files by construction; an
//!   unknown envelope version is rejected by [`dom_wallet_crypto`] before
//!   decryption.
//! - **Payload:** an inner [`SCHEMA_VERSION`] gates future in-place migration of
//!   the serialized layout. An unknown schema is rejected after decryption with
//!   a clear [`PersistError::UnsupportedSchema`] — never reinterpreted, never a
//!   panic.
//!
//! Scope note (3C): this persists the output set, which is the v2 balance source
//! of truth. The full `WalletV2State` of §2.3 (keychain, pending slates, meta
//! cursors) wraps additional fields that land with their features in later
//! sub-steps; `schema_version` is the gate that lets the payload grow.

use crate::store::{OutputStore, StoreError};
use crate::types::StoredOutput;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// v2 wallet-file magic. 14 bytes, distinct from v1's `DOM-WALLET-V1\0`, so a
/// v1 file is rejected by construction (and vice versa).
pub const WALLET_V2_MAGIC: &[u8; dom_wallet_crypto::MAGIC_LEN] = b"DOM-WALLET-V2\0";

/// Envelope (file-format) version written in the header.
pub const ENVELOPE_VERSION: u16 = 1;

/// Payload schema version. Bumped when the serialized layout changes; an
/// unknown value is rejected, gating future in-place migration.
pub const SCHEMA_VERSION: u16 = 2;

/// Errors from persisting / loading the store.
#[derive(Debug, Error)]
pub enum PersistError {
    /// Key derivation / AEAD / IO / header-validation error from the shared
    /// envelope (wrong password and tampering surface here as
    /// [`dom_wallet_crypto::EnvelopeError::Decryption`]).
    #[error(transparent)]
    Envelope(#[from] dom_wallet_crypto::EnvelopeError),
    /// The decrypted payload declares a schema this build does not understand.
    #[error("unsupported store schema version: {0}")]
    UnsupportedSchema(u16),
    /// The decrypted output set violated a store invariant (e.g. a duplicate
    /// commitment) — corruption that the AEAD tag did not catch.
    #[error("invalid persisted store: {0}")]
    Store(#[from] StoreError),
}

/// The serialized payload. Versioned independently of the envelope so the
/// layout can evolve without changing the file magic.
#[derive(Serialize, Deserialize)]
struct PersistedStoreV2 {
    schema_version: u16,
    outputs: Vec<StoredOutput>,
}

/// Encrypt and atomically write the store to `path`.
///
/// A fresh salt and nonce are generated per call (by the envelope). The on-disk
/// layout is the shared v2 envelope; the blindings are written only encrypted.
pub fn save_store(store: &OutputStore, path: &Path, password: &str) -> Result<(), PersistError> {
    let payload = PersistedStoreV2 {
        schema_version: SCHEMA_VERSION,
        outputs: store.iter().cloned().collect(),
    };
    dom_wallet_crypto::save_envelope(path, WALLET_V2_MAGIC, ENVELOPE_VERSION, &payload, password)?;
    Ok(())
}

/// Decrypt and reconstruct the store from `path`.
///
/// Verifies the v2 magic and envelope version (rejecting v1 files and unknown
/// versions before decryption), then the payload schema version. A wrong
/// password or tampered file fails with [`PersistError::Envelope`]
/// ([`dom_wallet_crypto::EnvelopeError::Decryption`]). Never panics on a bad
/// file.
pub fn load_store(path: &Path, password: &str) -> Result<OutputStore, PersistError> {
    let payload: PersistedStoreV2 =
        dom_wallet_crypto::load_envelope(path, WALLET_V2_MAGIC, ENVELOPE_VERSION, password)?;

    if payload.schema_version != SCHEMA_VERSION {
        return Err(PersistError::UnsupportedSchema(payload.schema_version));
    }

    Ok(OutputStore::from_outputs(payload.outputs)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BlockRef, DerivIndex, OutputOrigin, OutputStatus};

    /// A store holding one output of each origin, in different statuses, so the
    /// round-trip exercises status / blinding / origin_block / derivable.
    fn populated_store() -> OutputStore {
        let mut store = OutputStore::new();

        // Coinbase, confirmed (derivable by height).
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

        // Receive-slate, reorged (random blinding, non-derivable) — the case v1
        // loses; must survive persistence with its blinding intact.
        let mut receive = StoredOutput::new_unconfirmed(
            [0xC7u8; 33],
            500,
            [0x9au8; 32],
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

        // Change, unconfirmed (random blinding).
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

    fn assert_output_eq(a: &StoredOutput, b: &StoredOutput) {
        assert_eq!(a.commitment, b.commitment);
        assert_eq!(a.value, b.value);
        assert_eq!(*a.blinding, *b.blinding, "blinding must survive round-trip");
        assert_eq!(a.origin, b.origin);
        assert_eq!(a.status, b.status, "status must survive round-trip");
        assert_eq!(a.origin_block, b.origin_block, "origin_block must survive");
        assert_eq!(a.is_coinbase, b.is_coinbase);
        assert_eq!(a.derivable, b.derivable);
        assert_eq!(a.reserved_for, b.reserved_for);
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = populated_store();

        save_store(&store, &path, "pw").unwrap();
        let loaded = load_store(&path, "pw").unwrap();

        assert_eq!(loaded.len(), store.len());
        for original in store.iter() {
            let back = loaded
                .get(&original.commitment)
                .expect("every output present after load");
            assert_output_eq(original, back);
        }
    }

    #[test]
    fn reorged_receive_blinding_persists_encrypted() {
        // The non-derivable blinding (the WDSF case) must come back identical.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        let store = populated_store();
        save_store(&store, &path, "pw").unwrap();

        // The plaintext blinding must NOT appear on disk.
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(32).any(|w| w == [0x9au8; 32]),
            "blinding leaked in plaintext on disk"
        );

        let loaded = load_store(&path, "pw").unwrap();
        let receive = loaded.get(&[0xC7u8; 33]).unwrap();
        assert_eq!(receive.status, OutputStatus::Reorged);
        assert_eq!(*receive.blinding, [0x9au8; 32]);
    }

    #[test]
    fn wrong_password_is_rejected_without_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_store(&populated_store(), &path, "pw").unwrap();

        let err = load_store(&path, "wrong").unwrap_err();
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
        // A file written with the v1 magic must be rejected by the v2 loader.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        dom_wallet_crypto::save_envelope(
            &path,
            b"DOM-WALLET-V1\0",
            1,
            &PersistedStoreV2 {
                schema_version: SCHEMA_VERSION,
                outputs: vec![],
            },
            "pw",
        )
        .unwrap();

        let err = load_store(&path, "pw").unwrap_err();
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
        // Same v2 magic, but a future envelope version.
        dom_wallet_crypto::save_envelope(
            &path,
            WALLET_V2_MAGIC,
            ENVELOPE_VERSION + 1,
            &PersistedStoreV2 {
                schema_version: SCHEMA_VERSION,
                outputs: vec![],
            },
            "pw",
        )
        .unwrap();

        let err = load_store(&path, "pw").unwrap_err();
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
        // Correct magic + envelope version, but a future payload schema.
        dom_wallet_crypto::save_envelope(
            &path,
            WALLET_V2_MAGIC,
            ENVELOPE_VERSION,
            &PersistedStoreV2 {
                schema_version: SCHEMA_VERSION + 7,
                outputs: vec![],
            },
            "pw",
        )
        .unwrap();

        let err = load_store(&path, "pw").unwrap_err();
        assert!(
            matches!(err, PersistError::UnsupportedSchema(v) if v == SCHEMA_VERSION + 7),
            "got {err:?}"
        );
    }

    #[test]
    fn tampered_file_is_rejected_without_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wallet.dat");
        save_store(&populated_store(), &path, "pw").unwrap();

        let mut data = std::fs::read(&path).unwrap();
        let n = data.len();
        data[n - 8] ^= 0xFF; // flip a byte inside the ciphertext
        std::fs::write(&path, &data).unwrap();

        let err = load_store(&path, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                PersistError::Envelope(dom_wallet_crypto::EnvelopeError::Decryption)
            ),
            "got {err:?}"
        );
    }
}

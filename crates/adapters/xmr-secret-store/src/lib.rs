//! Encrypted restart-safe storage for local XMR private material.

#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{CryptoRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};

const AAD_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SECRET-STORE/V2\0";
const PLAINTEXT_LEN: usize = 64;

/// Secret-store failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretStoreError {
    /// Invalid zero/private material.
    #[error("invalid XMR secret material")]
    InvalidMaterial,
    /// Existing row differs.
    #[error("conflicting XMR secret material")]
    Conflict,
    /// Row absent.
    #[error("XMR secret material not found")]
    NotFound,
    /// Database/mutex unavailable.
    #[error("XMR secret store unavailable")]
    Unavailable,
    /// Ciphertext/schema authentication failed.
    #[error("XMR secret store authentication failed")]
    AuthenticationFailed,
}

/// Local spend share and private view key. Both zeroize on drop.
pub struct XmrSecretMaterial {
    local_spend_share: Zeroizing<[u8; 32]>,
    private_view_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for XmrSecretMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XmrSecretMaterial(<redacted>)")
    }
}

impl XmrSecretMaterial {
    /// Constructs non-zero material; canonical scalar validation occurs at use.
    pub fn new(
        local_spend_share: [u8; 32],
        private_view_key: [u8; 32],
    ) -> Result<Self, SecretStoreError> {
        if local_spend_share == [0; 32] || private_view_key == [0; 32] {
            return Err(SecretStoreError::InvalidMaterial);
        }
        Ok(Self {
            local_spend_share: Zeroizing::new(local_spend_share),
            private_view_key: Zeroizing::new(private_view_key),
        })
    }

    /// Closure-only access.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32], &[u8; 32]) -> R) -> R {
        operation(&self.local_spend_share, &self.private_view_key)
    }

    fn plaintext(&self) -> Zeroizing<[u8; PLAINTEXT_LEN]> {
        let mut output = Zeroizing::new([0; PLAINTEXT_LEN]);
        output[..32].copy_from_slice(&self.local_spend_share[..]);
        output[32..].copy_from_slice(&self.private_view_key[..]);
        output
    }

    fn from_plaintext(mut plaintext: [u8; PLAINTEXT_LEN]) -> Result<Self, SecretStoreError> {
        let mut local = [0; 32];
        let mut view = [0; 32];
        local.copy_from_slice(&plaintext[..32]);
        view.copy_from_slice(&plaintext[32..]);
        plaintext.zeroize();
        Self::new(local, view)
    }
}

/// Restart-safe storage port.
pub trait SecretMaterialStore: Send + Sync {
    /// Inserts exactly once.
    fn insert(
        &self,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        material: &XmrSecretMaterial,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(), SecretStoreError>;
    /// Decrypts one row.
    fn load(
        &self,
        settlement_id: &[u8; 32],
        terms_hash: &[u8; 32],
    ) -> Result<XmrSecretMaterial, SecretStoreError>;
    /// Deletes after exact raw transaction durability.
    fn delete(&self, settlement_id: &[u8; 32]) -> Result<(), SecretStoreError>;
}

/// External non-zero master key; never persisted by this crate.
pub struct SecretStoreMasterKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for SecretStoreMasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretStoreMasterKey(<redacted>)")
    }
}

impl SecretStoreMasterKey {
    /// Imports a key.
    pub fn new(bytes: [u8; 32]) -> Result<Self, SecretStoreError> {
        if bytes == [0; 32] {
            return Err(SecretStoreError::InvalidMaterial);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}

/// SQLite XChaCha20-Poly1305 store.
pub struct EncryptedSqliteSecretStore {
    connection: Mutex<Connection>,
    master_key: SecretStoreMasterKey,
}

impl core::fmt::Debug for EncryptedSqliteSecretStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedSqliteSecretStore")
            .field("master_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EncryptedSqliteSecretStore {
    /// Opens/creates encrypted storage.
    pub fn open(
        path: impl AsRef<Path>,
        master_key: SecretStoreMasterKey,
    ) -> Result<Self, SecretStoreError> {
        let connection = Connection::open(path).map_err(|_| SecretStoreError::Unavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS xmr_secret_material_v2(
               settlement_id BLOB PRIMARY KEY NOT NULL CHECK(length(settlement_id)=32),
               terms_hash BLOB NOT NULL CHECK(length(terms_hash)=32),
               nonce BLOB NOT NULL CHECK(length(nonce)=24),
               ciphertext BLOB NOT NULL
             );",
            )
            .map_err(|_| SecretStoreError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
            master_key,
        })
    }

    /// Builds the AEAD from the master key using the high-level
    /// `KeyInit::new_from_slice`: it takes `&[u8]`, checks the length at run
    /// time, and returns a `Result`, so no `generic-array` construction (all of
    /// whose slice constructors are deprecated in 0.14) is needed. The length
    /// is fixed at 32 by the type of `master_key`, so the error path is
    /// unreachable, but it is mapped rather than unwrapped to honour the
    /// crate's no-panic policy.
    fn cipher(&self) -> Result<XChaCha20Poly1305, SecretStoreError> {
        XChaCha20Poly1305::new_from_slice(&self.master_key.0[..])
            .map_err(|_| SecretStoreError::Unavailable)
    }
}

impl SecretMaterialStore for EncryptedSqliteSecretStore {
    fn insert(
        &self,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        material: &XmrSecretMaterial,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(), SecretStoreError> {
        if settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err(SecretStoreError::InvalidMaterial);
        }
        let mut nonce = [0; 24];
        rng.fill_bytes(&mut nonce);
        let associated = aad(settlement_id, terms_hash);
        let plaintext = material.plaintext();
        let ciphertext = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext[..],
                    aad: &associated,
                },
            )
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecretStoreError::Unavailable)?;
        let existing: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction.query_row(
            "SELECT terms_hash,nonce,ciphertext FROM xmr_secret_material_v2 WHERE settlement_id=?1",
            params![settlement_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|_| SecretStoreError::Unavailable)?;
        if let Some((stored_terms, stored_nonce, stored_ciphertext)) = existing {
            let stored_terms: [u8; 32] = stored_terms
                .try_into()
                .map_err(|_| SecretStoreError::AuthenticationFailed)?;
            let stored_nonce: [u8; 24] = stored_nonce
                .try_into()
                .map_err(|_| SecretStoreError::AuthenticationFailed)?;
            let stored_plaintext = Zeroizing::new(
                self.cipher()?
                    .decrypt(
                        &XNonce::from(stored_nonce),
                        Payload {
                            msg: &stored_ciphertext,
                            aad: &aad(settlement_id, stored_terms),
                        },
                    )
                    .map_err(|_| SecretStoreError::AuthenticationFailed)?,
            );
            if stored_terms != terms_hash || stored_plaintext.as_slice() != &plaintext[..] {
                return Err(SecretStoreError::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| SecretStoreError::Unavailable)?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO xmr_secret_material_v2(settlement_id,terms_hash,nonce,ciphertext)
             VALUES(?1,?2,?3,?4)",
                params![
                    settlement_id.as_slice(),
                    terms_hash.as_slice(),
                    nonce.as_slice(),
                    ciphertext
                ],
            )
            .map_err(|_| SecretStoreError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| SecretStoreError::Unavailable)
    }

    fn load(
        &self,
        settlement_id: &[u8; 32],
        terms_hash: &[u8; 32],
    ) -> Result<XmrSecretMaterial, SecretStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection.query_row(
            "SELECT terms_hash,nonce,ciphertext FROM xmr_secret_material_v2 WHERE settlement_id=?1",
            params![settlement_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|_| SecretStoreError::Unavailable)?;
        let (stored_terms, nonce, ciphertext) = row.ok_or(SecretStoreError::NotFound)?;
        let stored_terms: [u8; 32] = stored_terms
            .try_into()
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        if &stored_terms != terms_hash {
            return Err(SecretStoreError::AuthenticationFailed);
        }
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        let plaintext = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad(*settlement_id, *terms_hash),
                    },
                )
                .map_err(|_| SecretStoreError::AuthenticationFailed)?,
        );
        let fixed: [u8; PLAINTEXT_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        XmrSecretMaterial::from_plaintext(fixed)
    }

    fn delete(&self, settlement_id: &[u8; 32]) -> Result<(), SecretStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        connection
            .execute(
                "DELETE FROM xmr_secret_material_v2 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
            )
            .map_err(|_| SecretStoreError::Unavailable)?;
        Ok(())
    }
}

fn aad(settlement_id: [u8; 32], terms_hash: [u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(AAD_DOMAIN.len() + 64);
    output.extend_from_slice(AAD_DOMAIN);
    output.extend_from_slice(&settlement_id);
    output.extend_from_slice(&terms_hash);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETTLEMENT: [u8; 32] = [9; 32];
    const TERMS: [u8; 32] = [7; 32];
    const LOCAL: [u8; 32] = [3; 32];
    const VIEW: [u8; 32] = [5; 32];

    fn store(directory: &tempfile::TempDir, key: [u8; 32]) -> EncryptedSqliteSecretStore {
        EncryptedSqliteSecretStore::open(
            directory.path().join("secrets.sqlite"),
            SecretStoreMasterKey::new(key).expect("non-zero key"),
        )
        .expect("open")
    }

    fn material() -> XmrSecretMaterial {
        XmrSecretMaterial::new(LOCAL, VIEW).expect("valid material")
    }

    #[test]
    fn material_round_trips_under_the_binding_it_was_stored_with() {
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = store(&directory, [0x44; 32]);
        secrets
            .insert(SETTLEMENT, TERMS, &material(), &mut rand::thread_rng())
            .expect("insert");
        secrets.load(&SETTLEMENT, &TERMS).expect("loads");
    }

    #[test]
    fn material_stored_under_other_terms_does_not_load() {
        // The terms hash is part of the AEAD binding: material frozen under one
        // settlement's terms must not decrypt under another's, or a re-quoted
        // route could reuse keys from a route the operator never agreed to.
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = store(&directory, [0x44; 32]);
        secrets
            .insert(SETTLEMENT, TERMS, &material(), &mut rand::thread_rng())
            .expect("insert");
        assert!(secrets.load(&SETTLEMENT, &[8; 32]).is_err());
    }

    #[test]
    fn another_master_key_cannot_read_the_database() {
        let directory = tempfile::tempdir().expect("tempdir");
        store(&directory, [0x44; 32])
            .insert(SETTLEMENT, TERMS, &material(), &mut rand::thread_rng())
            .expect("insert");
        // Reopening the same file with a different operator key must fail
        // authentication rather than return anything.
        assert!(store(&directory, [0x55; 32])
            .load(&SETTLEMENT, &TERMS)
            .is_err());
    }

    #[test]
    fn a_zero_master_key_is_refused() {
        assert_eq!(
            SecretStoreMasterKey::new([0; 32]).unwrap_err(),
            SecretStoreError::InvalidMaterial
        );
    }

    #[test]
    fn zero_key_material_is_refused() {
        assert_eq!(
            XmrSecretMaterial::new([0; 32], VIEW).unwrap_err(),
            SecretStoreError::InvalidMaterial
        );
        assert_eq!(
            XmrSecretMaterial::new(LOCAL, [0; 32]).unwrap_err(),
            SecretStoreError::InvalidMaterial
        );
    }

    #[test]
    fn deleting_removes_the_material() {
        let directory = tempfile::tempdir().expect("tempdir");
        let secrets = store(&directory, [0x44; 32]);
        secrets
            .insert(SETTLEMENT, TERMS, &material(), &mut rand::thread_rng())
            .expect("insert");
        secrets.delete(&SETTLEMENT).expect("delete");
        assert!(secrets.load(&SETTLEMENT, &TERMS).is_err());
    }

    #[test]
    fn material_survives_reopening_the_database() {
        // Restart safety: the key must still be there after a process restart,
        // otherwise a claim arriving after a crash could never be swept.
        let directory = tempfile::tempdir().expect("tempdir");
        store(&directory, [0x44; 32])
            .insert(SETTLEMENT, TERMS, &material(), &mut rand::thread_rng())
            .expect("insert");
        store(&directory, [0x44; 32])
            .load(&SETTLEMENT, &TERMS)
            .expect("survives restart");
    }
}

//! Encrypted restart-safe storage for the local Solana route witness.
//!
//! Without this store the witness lives only inside the in-memory session:
//! a process that dies between funding and claim loses it, and the funds are
//! then recoverable only by waiting out the escrow's timelock refund. The
//! store keeps the 32-byte cross-curve witness encrypted at rest, keyed by
//! settlement, so a restarted node resumes the settlements it had open. The
//! public half — the bound DLEQ proof — is already durable in the setup
//! store and is deliberately not duplicated here.

#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{CryptoRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex};
use zeroize::Zeroizing;

const AAD_DOMAIN: &[u8] = b"DOM-INTEROP/SOLANA-SECRET-STORE/V1\0";
const PLAINTEXT_LEN: usize = 32;

/// Secret-store failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretStoreError {
    /// Invalid zero/private material.
    #[error("invalid Solana witness material")]
    InvalidMaterial,
    /// Existing row differs.
    #[error("conflicting Solana witness material")]
    Conflict,
    /// Row absent.
    #[error("Solana witness material not found")]
    NotFound,
    /// Database/mutex unavailable.
    #[error("Solana secret store unavailable")]
    Unavailable,
    /// Ciphertext/schema authentication failed.
    #[error("Solana secret store authentication failed")]
    AuthenticationFailed,
}

/// The canonical little-endian 252-bit witness. Zeroizes on drop.
///
/// Canonicality (non-zero, inside the 252-bit domain) is validated where the
/// witness is used — `CrossCurveSecret252::from_little_endian` — not here;
/// this type only refuses the all-zero placeholder so a blank row can never
/// round-trip as material.
pub struct SolanaWitnessMaterial {
    little_endian: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for SolanaWitnessMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SolanaWitnessMaterial(<redacted>)")
    }
}

impl SolanaWitnessMaterial {
    /// Constructs non-zero material.
    pub fn new(little_endian: [u8; 32]) -> Result<Self, SecretStoreError> {
        if little_endian == [0; 32] {
            return Err(SecretStoreError::InvalidMaterial);
        }
        Ok(Self {
            little_endian: Zeroizing::new(little_endian),
        })
    }

    /// Closure-only access.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.little_endian)
    }
}

/// Restart-safe storage port.
pub trait WitnessMaterialStore: Send + Sync {
    /// Inserts exactly once; an identical replay is idempotent and a
    /// divergent one conflicts.
    fn insert(
        &self,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        material: &SolanaWitnessMaterial,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(), SecretStoreError>;
    /// Decrypts one row.
    fn load(
        &self,
        settlement_id: &[u8; 32],
        terms_hash: &[u8; 32],
    ) -> Result<SolanaWitnessMaterial, SecretStoreError>;
    /// Deletes after the settlement reaches a terminal observed state.
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
pub struct EncryptedSqliteWitnessStore {
    connection: Mutex<Connection>,
    master_key: SecretStoreMasterKey,
}

impl core::fmt::Debug for EncryptedSqliteWitnessStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedSqliteWitnessStore")
            .field("master_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EncryptedSqliteWitnessStore {
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
             CREATE TABLE IF NOT EXISTS solana_route_witness_v1(
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

    /// Builds the AEAD through `KeyInit::new_from_slice`; the length is fixed
    /// at 32 by the key type, so the error path is unreachable, but it is
    /// mapped rather than unwrapped to honour the crate's no-panic policy.
    fn cipher(&self) -> Result<XChaCha20Poly1305, SecretStoreError> {
        XChaCha20Poly1305::new_from_slice(&self.master_key.0[..])
            .map_err(|_| SecretStoreError::Unavailable)
    }
}

impl WitnessMaterialStore for EncryptedSqliteWitnessStore {
    fn insert(
        &self,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        material: &SolanaWitnessMaterial,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(), SecretStoreError> {
        if settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err(SecretStoreError::InvalidMaterial);
        }
        let mut nonce = [0; 24];
        rng.fill_bytes(&mut nonce);
        let associated = aad(settlement_id, terms_hash);
        let ciphertext = material.expose(|plaintext| {
            self.cipher()?
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &plaintext[..],
                        aad: &associated,
                    },
                )
                .map_err(|_| SecretStoreError::AuthenticationFailed)
        })?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecretStoreError::Unavailable)?;
        let existing: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT terms_hash,nonce,ciphertext FROM solana_route_witness_v1
                 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| SecretStoreError::Unavailable)?;
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
            let matches =
                material.expose(|plaintext| stored_plaintext.as_slice() == &plaintext[..]);
            if stored_terms != terms_hash || !matches {
                return Err(SecretStoreError::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| SecretStoreError::Unavailable)?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO solana_route_witness_v1(settlement_id,terms_hash,nonce,ciphertext)
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
    ) -> Result<SolanaWitnessMaterial, SecretStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT terms_hash,nonce,ciphertext FROM solana_route_witness_v1
                 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| SecretStoreError::Unavailable)?;
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
        SolanaWitnessMaterial::new(fixed)
    }

    fn delete(&self, settlement_id: &[u8; 32]) -> Result<(), SecretStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SecretStoreError::Unavailable)?;
        connection
            .execute(
                "DELETE FROM solana_route_witness_v1 WHERE settlement_id=?1",
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
    const WITNESS: [u8; 32] = [3; 32];

    fn store(directory: &tempfile::TempDir, key: [u8; 32]) -> EncryptedSqliteWitnessStore {
        EncryptedSqliteWitnessStore::open(
            directory.path().join("witness.sqlite"),
            SecretStoreMasterKey::new(key).expect("non-zero key"),
        )
        .expect("open")
    }

    fn material() -> SolanaWitnessMaterial {
        SolanaWitnessMaterial::new(WITNESS).expect("valid material")
    }

    #[test]
    fn round_trips_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        store(&dir, [1; 32])
            .insert(SETTLEMENT, TERMS, &material(), &mut rng)
            .expect("insert");
        let loaded = store(&dir, [1; 32])
            .load(&SETTLEMENT, &TERMS)
            .expect("load after reopen");
        loaded.expose(|witness| assert_eq!(witness, &WITNESS));
    }

    #[test]
    fn identical_replay_is_idempotent_and_divergent_replay_conflicts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        let s = store(&dir, [1; 32]);
        s.insert(SETTLEMENT, TERMS, &material(), &mut rng)
            .expect("insert");
        s.insert(SETTLEMENT, TERMS, &material(), &mut rng)
            .expect("identical replay");
        let divergent = SolanaWitnessMaterial::new([4; 32]).expect("valid");
        assert_eq!(
            s.insert(SETTLEMENT, TERMS, &divergent, &mut rng),
            Err(SecretStoreError::Conflict)
        );
        assert_eq!(
            s.insert(SETTLEMENT, [8; 32], &material(), &mut rng),
            Err(SecretStoreError::Conflict)
        );
    }

    #[test]
    fn wrong_key_and_wrong_terms_fail_authentication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        store(&dir, [1; 32])
            .insert(SETTLEMENT, TERMS, &material(), &mut rng)
            .expect("insert");
        assert_eq!(
            store(&dir, [2; 32]).load(&SETTLEMENT, &TERMS).unwrap_err(),
            SecretStoreError::AuthenticationFailed
        );
        assert_eq!(
            store(&dir, [1; 32])
                .load(&SETTLEMENT, &[8; 32])
                .unwrap_err(),
            SecretStoreError::AuthenticationFailed
        );
        assert_eq!(
            store(&dir, [1; 32]).load(&[10; 32], &TERMS).unwrap_err(),
            SecretStoreError::NotFound
        );
    }

    #[test]
    fn zero_material_and_zero_key_are_refused() {
        assert_eq!(
            SolanaWitnessMaterial::new([0; 32]).unwrap_err(),
            SecretStoreError::InvalidMaterial
        );
        assert_eq!(
            SecretStoreMasterKey::new([0; 32]).unwrap_err(),
            SecretStoreError::InvalidMaterial
        );
    }

    #[test]
    fn delete_makes_the_row_unrecoverable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        let s = store(&dir, [1; 32]);
        s.insert(SETTLEMENT, TERMS, &material(), &mut rng)
            .expect("insert");
        s.delete(&SETTLEMENT).expect("delete");
        assert_eq!(
            s.load(&SETTLEMENT, &TERMS).unwrap_err(),
            SecretStoreError::NotFound
        );
    }
}

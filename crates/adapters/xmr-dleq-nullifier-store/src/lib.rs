//! Durable one-shot registry for cross-curve public claims.
//!
//! A valid DLEQ proof can be copied byte-for-byte. Context wrappers alone do
//! not make the underlying public claim one-shot. This store prevents the same
//! `(T_secp, S_xmr)` claim from being admitted by two settlements and prevents
//! one settlement from being rebound to a different claim after restart.

#![forbid(unsafe_code)]

use std::{path::Path, sync::Mutex};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use xmr_dleq_sigma::CrossCurvePublicClaim;

const NULLIFIER_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-DLEQ-NULLIFIER/V1\0";

/// Result of registering one claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// A new one-shot claim was inserted.
    Inserted,
    /// The exact same settlement/binding/claim was replayed after restart.
    Idempotent,
}

/// Fail-closed registry errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NullifierError {
    /// A mandatory public binding is zero.
    #[error("invalid zero DLEQ binding")]
    InvalidBinding,
    /// This public claim is already assigned to another settlement.
    #[error("DLEQ public claim reused by another settlement")]
    ClaimReused,
    /// This settlement was already assigned another DLEQ public claim.
    #[error("settlement already bound to another DLEQ claim")]
    SettlementAlreadyBound,
    /// Same settlement/claim but divergent setup binding.
    #[error("DLEQ setup binding changed across replay")]
    BindingMismatch,
    /// Persisted bytes do not satisfy the frozen schema.
    #[error("corrupt DLEQ nullifier record")]
    Corrupt,
    /// SQLite or mutex was unavailable.
    #[error("DLEQ nullifier store unavailable")]
    Unavailable,
}

/// SQLite-backed one-shot claim registry.
pub struct DleqNullifierStore {
    connection: Mutex<Connection>,
}

impl core::fmt::Debug for DleqNullifierStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DleqNullifierStore")
            .finish_non_exhaustive()
    }
}

impl DleqNullifierStore {
    /// Opens/creates the registry with full-sync WAL durability.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NullifierError> {
        let connection = Connection::open(path).map_err(|_| NullifierError::Unavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS xmr_dleq_nullifier_v1(
                   claim_id BLOB PRIMARY KEY NOT NULL CHECK(length(claim_id)=32),
                   settlement_id BLOB NOT NULL UNIQUE CHECK(length(settlement_id)=32),
                   binding_hash BLOB NOT NULL CHECK(length(binding_hash)=32)
                 );",
            )
            .map_err(|_| NullifierError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Domain-separated identifier of a public claim.
    #[must_use]
    pub fn claim_id(claim: &CrossCurvePublicClaim) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NULLIFIER_DOMAIN);
        hasher.update(claim.secp_compressed);
        hasher.update(claim.ed_compressed);
        hasher.finalize().into()
    }

    /// Registers a claim exactly once while allowing exact restart replay.
    pub fn register(
        &self,
        settlement_id: [u8; 32],
        binding_hash: [u8; 32],
        claim: &CrossCurvePublicClaim,
    ) -> Result<RegistrationOutcome, NullifierError> {
        if settlement_id == [0; 32]
            || binding_hash == [0; 32]
            || claim.secp_compressed == [0; 33]
            || claim.ed_compressed == [0; 32]
        {
            return Err(NullifierError::InvalidBinding);
        }

        let claim_id = Self::claim_id(claim);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| NullifierError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| NullifierError::Unavailable)?;

        let by_claim: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT settlement_id,binding_hash FROM xmr_dleq_nullifier_v1 WHERE claim_id=?1",
                params![claim_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| NullifierError::Unavailable)?;

        if let Some((stored_settlement, stored_binding)) = by_claim {
            let stored_settlement = fixed32(stored_settlement)?;
            let stored_binding = fixed32(stored_binding)?;
            if stored_settlement != settlement_id {
                return Err(NullifierError::ClaimReused);
            }
            if stored_binding != binding_hash {
                return Err(NullifierError::BindingMismatch);
            }
            transaction
                .commit()
                .map_err(|_| NullifierError::Unavailable)?;
            return Ok(RegistrationOutcome::Idempotent);
        }

        let settlement_claim: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT claim_id FROM xmr_dleq_nullifier_v1 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| NullifierError::Unavailable)?;
        if settlement_claim.is_some() {
            return Err(NullifierError::SettlementAlreadyBound);
        }

        transaction
            .execute(
                "INSERT INTO xmr_dleq_nullifier_v1(claim_id,settlement_id,binding_hash)
                 VALUES(?1,?2,?3)",
                params![
                    claim_id.as_slice(),
                    settlement_id.as_slice(),
                    binding_hash.as_slice()
                ],
            )
            .map_err(|_| NullifierError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| NullifierError::Unavailable)?;
        Ok(RegistrationOutcome::Inserted)
    }
}

fn fixed32(bytes: Vec<u8>) -> Result<[u8; 32], NullifierError> {
    bytes.try_into().map_err(|_| NullifierError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(byte: u8) -> CrossCurvePublicClaim {
        let mut secp = [byte; 33];
        secp[0] = 2;
        CrossCurvePublicClaim {
            secp_compressed: secp,
            ed_compressed: [byte; 32],
        }
    }

    #[test]
    fn exact_replay_is_idempotent_but_cross_settlement_reuse_fails() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = DleqNullifierStore::open(directory.path().join("nullifiers.sqlite"))
            .expect("open store");
        assert_eq!(
            store
                .register([1; 32], [2; 32], &claim(3))
                .expect("first registration"),
            RegistrationOutcome::Inserted,
        );
        assert_eq!(
            store
                .register([1; 32], [2; 32], &claim(3))
                .expect("exact replay"),
            RegistrationOutcome::Idempotent,
        );
        assert_eq!(
            store.register([9; 32], [2; 32], &claim(3)),
            Err(NullifierError::ClaimReused),
        );
    }

    #[test]
    fn settlement_cannot_be_rebound_to_another_claim() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store = DleqNullifierStore::open(directory.path().join("nullifiers.sqlite"))
            .expect("open store");
        store
            .register([1; 32], [2; 32], &claim(3))
            .expect("first registration");
        assert_eq!(
            store.register([1; 32], [2; 32], &claim(4)),
            Err(NullifierError::SettlementAlreadyBound),
        );
    }
}

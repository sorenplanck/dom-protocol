//! Durable one-shot registry for Solana settlement setups.

#![forbid(unsafe_code)]

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use solana_profile::SolanaSetupBindingV1;
use std::{path::Path, sync::Mutex};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetupStoreError {
    #[error("setup store unavailable")]
    Unavailable,
    #[error("invalid setup")]
    Invalid,
    #[error("same settlement or DLEQ claim attempted a divergent setup")]
    Conflict,
    #[error("corrupt setup row")]
    Corrupt,
}

pub struct SolanaSetupStore {
    connection: Mutex<Connection>,
}

impl SolanaSetupStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SetupStoreError> {
        let connection = Connection::open(path).map_err(|_| SetupStoreError::Unavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS solana_setup_v1(
               settlement_id BLOB PRIMARY KEY NOT NULL CHECK(length(settlement_id)=32),
               setup_id BLOB UNIQUE NOT NULL CHECK(length(setup_id)=32),
               secp_claim BLOB UNIQUE NOT NULL CHECK(length(secp_claim)=33),
               ed_claim BLOB UNIQUE NOT NULL CHECK(length(ed_claim)=32),
               binding BLOB NOT NULL
             );",
            )
            .map_err(|_| SetupStoreError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn register(&self, binding: &SolanaSetupBindingV1) -> Result<(), SetupStoreError> {
        if binding.settlement_id == [0; 32]
            || binding.setup_id == [0; 32]
            || binding.dleq.bundle.claim.ed_compressed == [0; 32]
        {
            return Err(SetupStoreError::Invalid);
        }
        let encoded = bincode::serialize(binding).map_err(|_| SetupStoreError::Invalid)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SetupStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SetupStoreError::Unavailable)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT binding FROM solana_setup_v1 WHERE settlement_id=?1",
                params![binding.settlement_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SetupStoreError::Unavailable)?;
        if let Some(existing) = existing {
            if existing != encoded {
                return Err(SetupStoreError::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| SetupStoreError::Unavailable)?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO solana_setup_v1(settlement_id,setup_id,secp_claim,ed_claim,binding)
             VALUES(?1,?2,?3,?4,?5)",
                params![
                    binding.settlement_id.as_slice(),
                    binding.setup_id.as_slice(),
                    binding.dleq.bundle.claim.secp_compressed.as_slice(),
                    binding.dleq.bundle.claim.ed_compressed.as_slice(),
                    encoded,
                ],
            )
            .map_err(|error| {
                if error.sqlite_error_code().is_some() {
                    SetupStoreError::Conflict
                } else {
                    SetupStoreError::Unavailable
                }
            })?;
        transaction
            .commit()
            .map_err(|_| SetupStoreError::Unavailable)
    }

    pub fn load(
        &self,
        settlement_id: &[u8; 32],
    ) -> Result<Option<SolanaSetupBindingV1>, SetupStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SetupStoreError::Unavailable)?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT binding FROM solana_setup_v1 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SetupStoreError::Unavailable)?;
        bytes
            .map(|bytes| bincode::deserialize(&bytes).map_err(|_| SetupStoreError::Corrupt))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_profile::{SolanaAssetV1, SolanaSetupBindingV1};
    use solana_route_secret::SolanaRouteSecret;
    use solana_types::SolanaPubkey;

    fn binding(settlement: u8, secret: &SolanaRouteSecret) -> SolanaSetupBindingV1 {
        SolanaSetupBindingV1 {
            settlement_id: [settlement; 32],
            terms_hash: [2; 32],
            dleq: secret.proof().clone(),
            program_id: SolanaPubkey([3; 32]),
            state_pda: SolanaPubkey([4; 32]),
            vault_pda: SolanaPubkey([5; 32]),
            vault_authority: SolanaPubkey([6; 32]),
            state_bump: 254,
            vault_bump: 253,
            authority_bump: 252,
            asset: SolanaAssetV1::NativeSol,
            funder: SolanaPubkey([7; 32]),
            recipient: SolanaPubkey([8; 32]),
            refund_recipient: SolanaPubkey([9; 32]),
            amount: 1_000,
            refund_after_unix: 2_000_000_000,
            program_data_hash: [10; 32],
            setup_id: [11; 32],
        }
    }

    fn store(directory: &tempfile::TempDir) -> SolanaSetupStore {
        SolanaSetupStore::open(directory.path().join("setup.sqlite")).expect("open")
    }

    #[test]
    fn register_load_round_trips_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        let secret = SolanaRouteSecret::generate([1; 32], [2; 32], &mut rng).expect("secret");
        let value = binding(1, &secret);
        store(&dir).register(&value).expect("register");
        assert_eq!(
            store(&dir).load(&value.settlement_id).expect("load"),
            Some(value)
        );
    }

    #[test]
    fn identical_replay_is_idempotent_and_divergent_replay_conflicts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        let secret = SolanaRouteSecret::generate([1; 32], [2; 32], &mut rng).expect("secret");
        let value = binding(1, &secret);
        let s = store(&dir);
        s.register(&value).expect("register");
        s.register(&value).expect("identical replay");
        let mut divergent = value.clone();
        divergent.amount = 2_000;
        assert_eq!(s.register(&divergent), Err(SetupStoreError::Conflict));
    }

    #[test]
    fn a_public_claim_is_one_shot_across_settlements() {
        // The nullifier property: the same DLEQ claim cannot register a
        // second settlement, so a witness cannot be re-locked elsewhere.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        let secret = SolanaRouteSecret::generate([1; 32], [2; 32], &mut rng).expect("secret");
        let s = store(&dir);
        s.register(&binding(1, &secret)).expect("register");
        assert_eq!(
            s.register(&binding(2, &secret)),
            Err(SetupStoreError::Conflict)
        );
    }

    #[test]
    fn zero_fields_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut rng = rand::thread_rng();
        let secret = SolanaRouteSecret::generate([1; 32], [2; 32], &mut rng).expect("secret");
        let mut value = binding(1, &secret);
        value.settlement_id = [0; 32];
        assert_eq!(store(&dir).register(&value), Err(SetupStoreError::Invalid));
        let mut value = binding(1, &secret);
        value.setup_id = [0; 32];
        assert_eq!(store(&dir).register(&value), Err(SetupStoreError::Invalid));
    }
}

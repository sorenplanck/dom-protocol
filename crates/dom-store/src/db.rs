#![allow(missing_docs)]
//! LMDB environment and database handles.

use dom_core::DomError;
use lmdb::{Database, DatabaseFlags, Environment, EnvironmentFlags, Transaction, WriteFlags};
use std::path::Path;

const MAP_SIZE: usize = 1 << 34; // 16 GiB — expandable
const MAX_DBS: u32 = 16;

/// Named LMDB databases.
pub const DB_BLOCKS: &str = "blocks";
pub const DB_BLOCK_HEIGHT: &str = "block_height";
pub const DB_CHAIN_TIP: &str = "chain_tip";
pub const DB_UTXOS: &str = "utxos";
pub const DB_KERNEL_INDEX: &str = "kernel_index";
pub const DB_PEER_ADDRS: &str = "peer_addrs";

/// The DOM storage engine.
pub struct DomStore {
    /// LMDB environment.
    pub env: Environment,
    /// blocks: hash → header bytes
    pub db_blocks: Database,
    /// block_height: height_le8 → hash
    pub db_height: Database,
    /// chain_tip: "tip" → hash
    pub db_tip: Database,
    /// utxos: commitment_33 → UtxoEntry
    pub db_utxos: Database,
    /// kernel_index: excess_33 → block_hash
    pub db_kernels: Database,
    /// peer_addrs: addr_str → last_seen_u64
    pub db_peers: Database,
}

impl DomStore {
    /// Open (or create) the store at the given directory.
    pub fn open(data_dir: &Path) -> Result<Self, DomError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| DomError::Internal(format!("create data dir: {e}")))?;

        let env = Environment::new()
            .set_flags(EnvironmentFlags::NO_TLS | EnvironmentFlags::NO_SYNC)
            .set_max_dbs(MAX_DBS)
            .set_map_size(MAP_SIZE)
            .open(data_dir)
            .map_err(|e| DomError::Internal(format!("lmdb open: {e}")))?;

        let open_db = |name: &str| -> Result<Database, DomError> {
            let txn = env
                .begin_rw_txn()
                .map_err(|e| DomError::Internal(format!("begin txn: {e}")))?;
            let db = unsafe {
                txn.open_db(Some(name))
                    .or_else(|_| txn.create_db(Some(name), DatabaseFlags::empty()))
            }
            .map_err(|e| DomError::Internal(format!("open db {name}: {e}")))?;
            txn.commit()
                .map_err(|e| DomError::Internal(format!("commit db open: {e}")))?;
            Ok(db)
        };

        Ok(Self {
            db_blocks: open_db(DB_BLOCKS)?,
            db_height: open_db(DB_BLOCK_HEIGHT)?,
            db_tip: open_db(DB_CHAIN_TIP)?,
            db_utxos: open_db(DB_UTXOS)?,
            db_kernels: open_db(DB_KERNEL_INDEX)?,
            db_peers: open_db(DB_PEER_ADDRS)?,
            env,
        })
    }

    /// Get the current chain tip hash. Returns None if chain is empty.
    pub fn get_chain_tip(&self) -> Result<Option<[u8; 32]>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_tip, b"tip") {
            Ok(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                Ok(Some(h))
            }
            Ok(_) => Err(DomError::Internal("corrupt chain tip".into())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get tip: {e}"))),
        }
    }

    /// Get a block header by hash. Returns None if not found.
    pub fn get_block_header(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_blocks, hash) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get block: {e}"))),
        }
    }

    /// Get block hash at a given height.
    pub fn get_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, DomError> {
        let key = height.to_le_bytes();
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_height, &key) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                Ok(Some(h))
            }
            Ok(_) => Err(DomError::Internal("corrupt height index".into())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get height: {e}"))),
        }
    }

    /// Get a UTXO entry by commitment (33-byte compressed point).
    /// Returns None if the UTXO does not exist (spent or never created).
    pub fn get_utxo(&self, commitment: &[u8; 33]) -> Result<Option<crate::utxo::UtxoEntry>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_utxos, commitment) {
            Ok(bytes) => Ok(Some(crate::utxo::UtxoEntry::from_bytes(bytes)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get utxo: {e}"))),
        }
    }

    /// Atomically commit a validated block to storage.
    ///
    /// RFC-0007 step 14: ALL writes in ONE transaction.
    /// On any error the transaction is aborted — no partial state.
    pub fn commit_block(
        &self,
        block_hash: &[u8; 32],
        block_height: u64,
        header_bytes: &[u8],
        new_utxos: &[([u8; 33], Vec<u8>)], // (commitment, utxo_entry)
        spent_utxos: &[[u8; 33]],          // commitments to remove
        kernel_excesses: &[([u8; 33], [u8; 32])], // (excess, block_hash)
    ) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;

        // Store block header
        txn.put(
            self.db_blocks,
            block_hash,
            &header_bytes.to_vec(),
            WriteFlags::empty(),
        )
        .map_err(|e| DomError::Internal(format!("put block: {e}")))?;

        // Store height → hash index
        let height_key = block_height.to_le_bytes();
        txn.put(self.db_height, &height_key, block_hash, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put height: {e}")))?;

        // Update chain tip
        txn.put(self.db_tip, b"tip", block_hash, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put tip: {e}")))?;

        // Add new UTXOs
        for (commitment, entry) in new_utxos {
            txn.put(self.db_utxos, commitment, entry, WriteFlags::empty())
                .map_err(|e| DomError::Internal(format!("put utxo: {e}")))?;
        }

        // Remove spent UTXOs
        for commitment in spent_utxos {
            match txn.del(self.db_utxos, commitment, None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => return Err(DomError::Internal(format!("del utxo: {e}"))),
            }
        }

        // Index kernels
        for (excess, hash) in kernel_excesses {
            txn.put(self.db_kernels, excess, hash, WriteFlags::empty())
                .map_err(|e| DomError::Internal(format!("put kernel: {e}")))?;
        }

        // Single atomic commit — if this fails nothing was written
        txn.commit()
            .map_err(|e| DomError::Internal(format!("commit block: {e}")))?;

        Ok(())
    }
}

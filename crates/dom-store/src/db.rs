#![allow(missing_docs)]
//! LMDB environment and database handles.
//!
//! ## Durability stance (Roadmap v2 Phase 3.3)
//!
//! The environment is opened with the *default* sync mode. Concretely:
//!
//! - `MDB_NOSYNC` is NOT set. `mdb_txn_commit` therefore fsyncs the
//!   data file before returning. A successful `commit_block` MUST mean
//!   the block is durable across a power loss or kernel panic — that
//!   is the consensus-grade contract a blockchain store has to honour.
//! - `MDB_NOMETASYNC` is NOT set. The meta page (the LMDB superblock)
//!   is fsynced too; without it a power loss can leave the file
//!   structurally inconsistent.
//!
//! The pre-Phase-3.3 flag set (`NO_TLS | NO_SYNC`) traded durability
//! for a throughput win that does not exist at our commit cadence
//! (~one fsync per ≥120-second block) and that the LMDB docs
//! explicitly warn "can corrupt the database or lose the last
//! transactions". A blockchain cannot accept either outcome.
//!
//! `NO_TLS` is retained: it disables the per-thread reader-slot
//! reservation that prevents a single thread from opening multiple
//! read transactions concurrently. The DomStore caller pool is async
//! / multi-thread and the slot model would otherwise serialise reads.
//!
//! ## Map size (Roadmap v2 Phase 3.3)
//!
//! `MAP_SIZE` is the maximum mapped region size — LMDB will refuse
//! commits with `MDB_MAP_FULL` once the file grows past it. We
//! pre-allocate 16 GiB on every host; that buys >5 years at the
//! current 33-DOM block reward + typical 1 MB block budget before any
//! manual extension is needed. When a commit fails with `MapFull`,
//! `commit_block` returns a tagged `DomError::Internal` containing
//! `"LMDB_MAP_FULL"` so the chain-init layer can surface the
//! condition distinctly from a generic LMDB error.
//!
//! Dynamic map_size growth is intentionally deferred: it requires a
//! safe quiescent point with no in-flight read transactions, and the
//! current async multi-reader model can't guarantee that cheaply.
//! Once Phase 6 lands rebuild-from-genesis, the operator path
//! "raise the limit and restart" becomes equivalent to "wait,
//! redeliver" and the deferral is no longer a release blocker.
//! Tracked under RB-LMDB-MAPSIZE in RELEASE_BLOCKERS.
//!
//! ## Partial-persistence contract (Roadmap v2 Phase 3.2)
//!
//! Under normal use, every `commit_block` is one LMDB transaction, and
//! LMDB's per-txn atomicity guarantees that an interrupted process
//! either persists the whole transaction or nothing. The SIGKILL
//! harness in `tests/crash_consistency_sigkill.rs` exercises this.
//!
//! If something *outside* `commit_block` does manage to leave the
//! store in a partial state — a future refactor that splits a write
//! across txns, an external corruption tool, a manual recovery — the
//! contract is:
//!
//! 1. `DomStore::open` MUST succeed on the partial state. It must not
//!    panic, abort, or refuse to open. Callers need to be able to
//!    inspect the store in order to repair it; bailing out here would
//!    deny them that.
//! 2. Every read method (`get_block_header`, `get_block_body`,
//!    `get_hash_at_height`, `get_chain_tip`, `get_utxo`) MUST report
//!    the on-disk state honestly:
//!      - `Some(v)` if the value is present in its database;
//!      - `None` if it is not.
//!
//!    No silent reconstruction, no fabricated bytes.
//! 3. Pointer relations (`chain_tip → block`, `height → hash`,
//!    `kernel_index → block_hash`) MUST be returned verbatim. If the
//!    pointer survives but its target is missing, the caller observes
//!    `Some(ptr)` from the pointer read and then `None` from the
//!    dereference. Detecting that mismatch and reacting (log, abort,
//!    rebuild) is the chain-init layer's responsibility, not this
//!    crate's.
//!
//! These guarantees are pinned by `tests/partial_persistence.rs`.

use dom_core::DomError;
use lmdb::{Database, DatabaseFlags, Environment, EnvironmentFlags, Transaction, WriteFlags};
use std::path::Path;

const MAP_SIZE: usize = 1 << 34; // 16 GiB — see module doc § "Map size"
const MAX_DBS: u32 = 16;

/// Sentinel substring callers can grep for in `DomError::Internal`
/// messages to detect LMDB map-full conditions distinctly from other
/// internal errors. Exposed as a constant so the chain-init layer can
/// match exactly without typo risk.
pub const LMDB_MAP_FULL_SENTINEL: &str = "LMDB_MAP_FULL";

/// Named LMDB databases.
pub const DB_BLOCKS: &str = "blocks";
pub const DB_BLOCK_BODIES: &str = "block_bodies";
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
    /// block_bodies: hash → serialized Block body (full block bytes minus header)
    pub db_block_bodies: Database,
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

        // NO_TLS only — see module doc § "Durability stance". NO_SYNC and
        // NO_META_SYNC are intentionally absent: every commit_block must
        // fsync the data file + meta page before returning.
        let env = Environment::new()
            .set_flags(EnvironmentFlags::NO_TLS)
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
            db_block_bodies: open_db(DB_BLOCK_BODIES)?,
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
    pub fn get_utxo(
        &self,
        commitment: &[u8; 33],
    ) -> Result<Option<crate::utxo::UtxoEntry>, DomError> {
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

    /// Get the full serialized block body by hash.
    ///
    /// Returns None if the block is unknown (not yet committed or pruned).
    pub fn get_block_body(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, DomError> {
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| DomError::Internal(format!("ro txn: {e}")))?;
        match txn.get(self.db_block_bodies, hash) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(DomError::Internal(format!("get block body: {e}"))),
        }
    }

    /// Atomically commit a validated block to storage.
    ///
    /// RFC-0007 step 14: ALL writes in ONE transaction.
    /// On any error the transaction is aborted — no partial state.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_block(
        &self,
        block_hash: &[u8; 32],
        block_height: u64,
        header_bytes: &[u8],
        block_body_bytes: &[u8],
        new_utxos: &[([u8; 33], Vec<u8>)], // (commitment, utxo_entry)
        spent_utxos: &[[u8; 33]],          // commitments to remove
        kernel_excesses: &[([u8; 33], [u8; 32])], // (excess, block_hash)
    ) -> Result<(), DomError> {
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| DomError::Internal(format!("rw txn: {e}")))?;

        // Store block header.
        // DOM-LMDB-001: NO_OVERWRITE detects duplicates. connect_block's
        // ab82f89 early-return should prevent this from ever firing; if it
        // does, upstream dedup was bypassed (security-relevant).
        txn.put(
            self.db_blocks,
            block_hash,
            &header_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "block header already exists — connect_block dedup bypassed? hash={}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put block: {other}")),
        })?;

        // Store block body (full serialized block) for IBD responses.
        // DOM-LMDB-001: NO_OVERWRITE — block body is immutable by hash.
        txn.put(
            self.db_block_bodies,
            block_hash,
            &block_body_bytes.to_vec(),
            WriteFlags::NO_OVERWRITE,
        )
        .map_err(|e| match e {
            lmdb::Error::KeyExist => DomError::Internal(format!(
                "block body already exists — connect_block dedup bypassed? hash={}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("put block body: {other}")),
        })?;

        // Store height → hash index
        let height_key = block_height.to_le_bytes();
        txn.put(self.db_height, &height_key, block_hash, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put height: {e}")))?;

        // Update chain tip
        txn.put(self.db_tip, b"tip", block_hash, WriteFlags::empty())
            .map_err(|e| DomError::Internal(format!("put tip: {e}")))?;

        // Add new UTXOs.
        // DOM-LMDB-001: NO_OVERWRITE — commitments must be unique. Duplicate
        // commitment means the same (value, blinding) pair was produced twice,
        // which would be a critical consensus bug (double output).
        for (commitment, entry) in new_utxos {
            txn.put(self.db_utxos, commitment, entry, WriteFlags::NO_OVERWRITE)
                .map_err(|e| match e {
                    lmdb::Error::KeyExist => DomError::Internal(format!(
                        "UTXO commitment already exists — consensus bug? commitment={}",
                        hex::encode(commitment)
                    )),
                    other => DomError::Internal(format!("put utxo: {other}")),
                })?;
        }

        // Remove spent UTXOs
        for commitment in spent_utxos {
            match txn.del(self.db_utxos, commitment, None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(e) => return Err(DomError::Internal(format!("del utxo: {e}"))),
            }
        }

        // Index kernels.
        // DOM-LMDB-001 — MOST CRITICAL of the NO_OVERWRITE conversions.
        // A duplicate kernel excess is the signature of a kernel-replay
        // attack: the consensus layer should already reject blocks containing
        // previously-seen kernels (kernel uniqueness check), so if we ever
        // get here with KeyExist, either:
        //   - the consensus check has a bypass (security-critical bug)
        //   - the same block is being committed twice (caught by db_blocks
        //     check above first, so this is defense-in-depth)
        // Either way, loud-fail with explicit error.
        for (excess, hash) in kernel_excesses {
            txn.put(self.db_kernels, excess, hash, WriteFlags::NO_OVERWRITE)
                .map_err(|e| match e {
                    lmdb::Error::KeyExist => DomError::Internal(format!(
                        "KERNEL REPLAY DETECTED — excess already indexed (DOM-SEC critical): excess={}, block={}",
                        hex::encode(excess),
                        hex::encode(hash)
                    )),
                    other => DomError::Internal(format!("put kernel: {other}")),
                })?;
        }

        // Single atomic commit — if this fails nothing was written.
        // MDB_MAP_FULL is tagged with LMDB_MAP_FULL_SENTINEL so the
        // chain-init layer can recognise it without parsing free-form
        // error text.
        txn.commit().map_err(|e| match e {
            lmdb::Error::MapFull => DomError::Internal(format!(
                "{LMDB_MAP_FULL_SENTINEL}: map_size={MAP_SIZE} exhausted while committing block {} at height {block_height}",
                hex::encode(block_hash)
            )),
            other => DomError::Internal(format!("commit block: {other}")),
        })?;

        Ok(())
    }
}

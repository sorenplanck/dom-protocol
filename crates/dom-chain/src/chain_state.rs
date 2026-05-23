#![allow(missing_docs)]
//! Chain state — current tip, validation, block commitment.

use dom_consensus::block::{
    validate_future_timestamp, validate_header_syntax, validate_median_time_past, validate_pow,
    BlockHeader,
};
use dom_consensus::{derive_chain_id, validate_block, Block, ValidationContext};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp};
use dom_pow::{randomx_seed_height, target_to_difficulty, AsertAnchor, CompactTarget};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_store::DomStore;
use primitive_types::U256;
use tracing::{debug, info};

pub struct ChainState {
    pub store: DomStore,
    pub tip_hash: Hash256,
    pub tip_height: BlockHeight,
    pub tip_difficulty: U256,
    pub genesis_hash: Hash256,
    pub asert_anchor: AsertAnchor,
    pub network_magic: u32,
}

impl ChainState {
    pub fn open(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
    ) -> Result<Self, DomError> {
        let genesis_target = CompactTarget(dom_core::GENESIS_TARGET_COMPACT)
            .to_target()
            .map_err(|e| DomError::Internal(format!("GENESIS_TARGET_COMPACT: {e}")))?;
        let asert_anchor = AsertAnchor {
            timestamp: Timestamp(dom_core::GENESIS_TIMESTAMP_PLACEHOLDER),
            height: BlockHeight::GENESIS,
            target: genesis_target,
        };

        let (tip_hash, tip_height, tip_difficulty) = match store.get_chain_tip()? {
            Some(hash) => {
                let header_bytes = store
                    .get_block_header(&hash)?
                    .ok_or_else(|| DomError::Internal("tip header not found".into()))?;
                let header = BlockHeader::from_bytes(&header_bytes)?;
                (
                    Hash256::from_bytes(hash),
                    header.height,
                    header.total_difficulty,
                )
            }
            None => (Hash256::ZERO, BlockHeight::GENESIS, U256::zero()),
        };

        Ok(Self {
            store,
            tip_hash,
            tip_height,
            tip_difficulty,
            genesis_hash,
            asert_anchor,
            network_magic,
        })
    }

    pub fn connect_block(
        &mut self,
        block: &Block,
        now: Timestamp,
    ) -> Result<ConnectResult, DomError> {
        let header = &block.header;
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_hash(&header_bytes);

        // DOM-SEC-RELAY-LOOP fix: early-return for already-known blocks.
        // Without this check, duplicate blocks (e.g. from relay loops between
        // peers) would re-execute full validation, re-write the store with
        // identical data, and trigger another rebroadcast — creating an
        // infinite amplification loop. Discovered via Doc 8 two_node test
        // on 2026-05-23.
        if self.store.get_block_header(block_hash.as_bytes())?.is_some() {
            return Ok(ConnectResult::AlreadyHave);
        }

        validate_header_syntax(header)?;

        if header.height != BlockHeight::GENESIS {
            let parent_bytes = self
                .store
                .get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Orphan(format!("parent {} not found", header.prev_hash))
                })?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;
            let expected_height = parent
                .height
                .checked_next()
                .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
            if header.height != expected_height {
                return Err(DomError::Invalid(format!(
                    "height mismatch: expected {expected_height}, got {}",
                    header.height
                )));
            }
            let ancestors = self.get_recent_timestamps(header.height.0, 11)?;
            validate_median_time_past(header, &ancestors)?;
        }

        validate_future_timestamp(header, now)?;
        let seed = self.compute_randomx_seed(header.height.0)?;
        validate_pow(header, &seed)?;

        let parent_difficulty = if header.height == BlockHeight::GENESIS {
            U256::zero()
        } else {
            let parent_bytes = self
                .store
                .get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| DomError::Internal("parent missing".into()))?;
            BlockHeader::from_bytes(&parent_bytes)?.total_difficulty
        };

        let block_diff = target_to_difficulty(
            &header
                .target
                .to_target()
                .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
        );
        let expected_total = parent_difficulty.saturating_add(U256::from(block_diff));
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }

        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        let ctx = ValidationContext {
            current_height: header.height,
            chain_id: *chain_id.as_bytes(),
            now,
        };

        validate_block(block, &ctx).map_err(|e| {
            DomError::Invalid(format!(
                "block validation failed: hash={block_hash}, error={e}"
            ))
        })?;

        // Validate every input exists in UTXO set and coinbase outputs are mature.
        // This protects against double-spend and immature coinbase spend (reorg risk).
        for tx in &block.transactions {
            for input in &tx.inputs {
                let commitment_bytes = input.commitment.as_bytes();
                let entry = self.store.get_utxo(commitment_bytes)?.ok_or_else(|| {
                    DomError::Invalid(format!(
                        "input commitment not found in UTXO set: {}",
                        hex::encode(commitment_bytes)
                    ))
                })?;
                if entry.is_coinbase && !entry.is_mature(header.height.0) {
                    return Err(DomError::Invalid(format!(
                        "immature coinbase spend at height {} (created at {})",
                        header.height.0, entry.block_height
                    )));
                }
            }
        }

        // Build UTXO changeset from block contents.
        // Coinbase output is marked is_coinbase=true (subject to maturity rule).
        let mut new_utxos: Vec<([u8; 33], Vec<u8>)> = Vec::new();
        let coinbase_entry = dom_store::utxo::UtxoEntry {
            block_height: header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        };
        new_utxos.push((
            *block.coinbase.output.commitment.as_bytes(),
            coinbase_entry.to_bytes(),
        ));

        let mut spent_utxos: Vec<[u8; 33]> = Vec::new();
        for tx in &block.transactions {
            for input in &tx.inputs {
                spent_utxos.push(*input.commitment.as_bytes());
            }
            for output in &tx.outputs {
                let entry = dom_store::utxo::UtxoEntry {
                    block_height: header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                };
                new_utxos.push((*output.commitment.as_bytes(), entry.to_bytes()));
            }
        }

        // Serialize full block body for IBD responses (peers ask for bodies by hash).
        let block_body_bytes = block.to_bytes()?;

        self.store.commit_block(
            block_hash.as_bytes(),
            header.height.0,
            &header_bytes,
            &block_body_bytes,
            &new_utxos,
            &spent_utxos,
            &[],
        )?;

        if header.total_difficulty > self.tip_difficulty {
            self.tip_hash = block_hash;
            self.tip_height = header.height;
            self.tip_difficulty = header.total_difficulty;
            info!(
                "New chain tip: height={}, hash={}",
                header.height, block_hash
            );
            Ok(ConnectResult::BestChain)
        } else {
            debug!(
                "Side chain block: height={}, hash={}",
                header.height, block_hash
            );
            Ok(ConnectResult::SideChain)
        }
    }

    pub fn validate_header_only(
        &self,
        header: &BlockHeader,
        now: Timestamp,
    ) -> Result<(), DomError> {
        validate_header_syntax(header)?;
        validate_future_timestamp(header, now)?;
        let seed = self.compute_randomx_seed(header.height.0)?;
        validate_pow(header, &seed)?;
        Ok(())
    }

    /// Compute the RandomX seed for a block at `height`.
    ///
    /// Seed = hash of block at `randomx_seed_height(height)`.
    /// For early blocks where the seed_height has no block yet (chain bootstrap),
    /// returns [0u8; 32] by convention.
    fn compute_randomx_seed(&self, height: u64) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);
        match self.store.get_hash_at_height(seed_height)? {
            Some(hash) => Ok(hash),
            None => Ok([0u8; 32]),
        }
    }

    fn get_recent_timestamps(
        &self,
        current_height: u64,
        count: usize,
    ) -> Result<Vec<Timestamp>, DomError> {
        let mut timestamps = Vec::with_capacity(count);
        let start = current_height.saturating_sub(count as u64);
        for h in (start..current_height).rev() {
            if let Some(hash) = self.store.get_hash_at_height(h)? {
                if let Some(header_bytes) = self.store.get_block_header(&hash)? {
                    if let Ok(header) = BlockHeader::from_bytes(&header_bytes) {
                        timestamps.push(header.timestamp);
                    }
                }
            }
        }
        Ok(timestamps)
    }

    pub fn is_synced(&self, best_peer_height: u64) -> bool {
        self.tip_height.0 + 10 >= best_peer_height
    }
}

/// Outcome of attempting to connect a block to the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectResult {
    /// Block extended the best chain — new tip. Caller should rebroadcast.
    BestChain,
    /// Block is valid but on a side chain (lower or equal total difficulty).
    /// Caller should NOT rebroadcast — would cause network amplification.
    SideChain,
    /// Block was already known (hash already in store). No-op.
    /// Caller MUST NOT rebroadcast or re-validate. Critical for preventing
    /// relay loops (DOM-SEC-RELAY-LOOP, 2026-05-23).
    AlreadyHave,
}

fn compute_block_hash(header_bytes: &[u8]) -> Hash256 {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(header_bytes);
    let result = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Hash256::from_bytes(arr)
}

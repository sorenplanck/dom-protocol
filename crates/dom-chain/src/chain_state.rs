//! Chain state — current tip, validation, block commitment.

use dom_core::{BlockHeight, DomError, Hash256, Timestamp};
use dom_consensus::block::{BlockHeader, validate_header_syntax, validate_future_timestamp, validate_median_time_past, validate_pow};
use dom_pow::{AsertAnchor, CompactTarget, target_to_difficulty};
use primitive_types::U256;
use dom_store::DomStore;
use dom_serialization::{DomDeserialize, DomSerialize};
use tracing::{info, debug};

/// The current chain state.
pub struct ChainState {
    /// Persistent storage.
    pub store: DomStore,
    /// Current best block hash.
    pub tip_hash: Hash256,
    /// Current best block height.
    pub tip_height: BlockHeight,
    /// Current best block total difficulty (U256 for full precision).
    pub tip_difficulty: U256,
    /// Genesis block hash (hardcoded, validated on startup).
    pub genesis_hash: Hash256,
    /// ASERT anchor (genesis block).
    pub asert_anchor: AsertAnchor,
}

impl ChainState {
    /// Initialize chain state from storage.
    pub fn open(store: DomStore, genesis_hash: Hash256) -> Result<Self, DomError> {
        // Genesis anchor — RFC-0006 finalizado.
        //
        // GENESIS_TARGET_COMPACT = 0x1e00ffff
        //   Calibrado para CPU solo RandomX com blocos de 2 minutos.
        //   O ASERT ajusta automaticamente a partir do bloco 1.
        //
        // GENESIS_TIMESTAMP_PLACEHOLDER
        //   Substituir no dia do lancamento com: date +%s
        //
        // [CONSENSUS CRITICAL] Qualquer alteracao aqui e um hard fork.
        let genesis_target = CompactTarget(dom_core::GENESIS_TARGET_COMPACT)
            .to_target()
            .map_err(|e| DomError::Internal(format!(
                "GENESIS_TARGET_COMPACT invalido — erro de consenso: {e}"
            )))?;

        let asert_anchor = AsertAnchor {
            timestamp: Timestamp(dom_core::GENESIS_TIMESTAMP_PLACEHOLDER),
            height: BlockHeight::GENESIS,
            target: genesis_target,
        };

        let (tip_hash, tip_height, tip_difficulty) = match store.get_chain_tip()? {
            Some(hash) => {
                // Load tip from storage
                let header_bytes = store.get_block_header(&hash)?
                    .ok_or_else(|| DomError::Internal("tip header not found".into()))?;
                let header = BlockHeader::from_bytes(&header_bytes)?;
                let height = header.height;
                let diff = header.total_difficulty; // U256
                info!("Loaded chain tip: height={}, hash={}", height, hex::encode(hash));
                (Hash256::from_bytes(hash), height, diff)
            }
            None => {
                info!("Empty chain — starting from genesis");
                (Hash256::ZERO, BlockHeight::GENESIS, U256::zero())
            }
        };

        Ok(Self { store, tip_hash, tip_height, tip_difficulty, genesis_hash, asert_anchor })
    }

    /// Validate and connect a new block to the chain tip.
    ///
    /// Implements RFC-0007 block validation steps 1-7 (structural).
    /// Steps 8-14 (transaction validation, PMMR) are marked as pending
    /// full Bulletproofs integration.
    pub fn connect_block(
        &mut self,
        header: &BlockHeader,
        now: Timestamp,
    ) -> Result<ConnectResult, DomError> {
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_hash(&header_bytes);

        // ── Step 1: Canonical decode (already done by caller) ────────────────

        // ── Step 2: Header syntax ────────────────────────────────────────────
        validate_header_syntax(header)?;

        // ── Step 3: Parent lookup ────────────────────────────────────────────
        if header.height != BlockHeight::GENESIS {
            let parent_bytes = self.store.get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| DomError::Orphan(
                    format!("parent {} not found", header.prev_hash)
                ))?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;

            // Height must be parent + 1
            let expected_height = parent.height.checked_next()
                .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
            if header.height != expected_height {
                return Err(DomError::Invalid(format!(
                    "height mismatch: expected {expected_height}, got {}",
                    header.height
                )));
            }

            // ── Step 4: Median-time-past ─────────────────────────────────────
            let ancestors = self.get_recent_timestamps(header.height.0, 11)?;
            validate_median_time_past(header, &ancestors)?;
        }

        // ── Step 5: Future timestamp ─────────────────────────────────────────
        validate_future_timestamp(header, now)?;

        // ── Step 6: PoW validation ───────────────────────────────────────────
        validate_pow(header, &block_hash)?;

        // ── Step 7: Total difficulty ─────────────────────────────────────────
        let parent_difficulty = if header.height == BlockHeight::GENESIS {
            primitive_types::U256::zero()
        } else {
            let parent_bytes = self.store.get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| DomError::Internal("parent missing after step 3".into()))?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;
            parent.total_difficulty
        };

        let block_diff = target_to_difficulty(
            &header.target.to_target()
                .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?
        );
        let expected_total = parent_difficulty.saturating_add(primitive_types::U256::from(block_diff));
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }

        // ── Steps 8-14: Transaction validation (pending Bulletproofs) ────────
        // TODO: validate transactions when secp256k1-zkp is integrated.
        // For now, we validate structural rules only and commit the header.

        // ── Commit ───────────────────────────────────────────────────────────
        self.store.commit_block(
            block_hash.as_bytes(),
            header.height.0,
            &header_bytes,
            &[],   // new UTXOs: filled after full tx validation
            &[],   // spent UTXOs: filled after full tx validation
            &[],   // kernel index: filled after full tx validation
        )?;

        // Update in-memory tip if this extends the best chain
        if header.total_difficulty > self.tip_difficulty {
            self.tip_hash = block_hash;
            self.tip_height = header.height;
            self.tip_difficulty = header.total_difficulty;
            info!("New chain tip: height={}, hash={}", header.height, block_hash);
            Ok(ConnectResult::BestChain)
        } else {
            debug!("Side chain block: height={}, hash={}", header.height, block_hash);
            Ok(ConnectResult::SideChain)
        }
    }

    /// Validate a block header without committing (used during IBD).
    pub fn validate_header_only(
        &self,
        header: &BlockHeader,
        now: Timestamp,
    ) -> Result<(), DomError> {
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_hash(&header_bytes);
        validate_header_syntax(header)?;
        validate_future_timestamp(header, now)?;
        validate_pow(header, &block_hash)?;
        Ok(())
    }

    /// Get recent block timestamps for median-time-past check.
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

    /// Whether this node has finished IBD and is near the chain tip.
    pub fn is_synced(&self, best_peer_height: u64) -> bool {
        self.tip_height.0 + 10 >= best_peer_height
    }
}

/// Result of connecting a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectResult {
    /// Block extended the best chain.
    BestChain,
    /// Block is on a side chain.
    SideChain,
}

/// Compute block hash from serialized header bytes.
fn compute_block_hash(header_bytes: &[u8]) -> Hash256 {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(header_bytes);
    let result = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Hash256::from_bytes(arr)
}

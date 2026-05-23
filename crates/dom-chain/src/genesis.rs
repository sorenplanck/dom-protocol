//! Genesis block generator for DOM Protocol.
//!
//! Produces the deterministic genesis block for mainnet and testnet.
//! The genesis block is the foundation of the chain — every node must
//! agree on it exactly.
//!
//! Genesis message (immutable): "Not a store of value. A means of exchange."
//!
//! RFC-0000 §4: Genesis block specification.

use dom_consensus::{block::ProofOfWork, derive_chain_id, BlockHeader};
use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, GENESIS_MESSAGE, GENESIS_TARGET_COMPACT,
    GENESIS_TIMESTAMP_PLACEHOLDER, INITIAL_BLOCK_REWARD, NETWORK_MAGIC_MAINNET,
    NETWORK_MAGIC_TESTNET,
};
use dom_pow::CompactTarget;
use primitive_types::U256;
use sha2::{Digest, Sha256};

/// Result of genesis block generation.
#[derive(Debug, Clone)]
pub struct GenesisResult {
    /// The genesis block header.
    pub header: BlockHeader,
    /// The genesis block hash (SHA-256 per whitepaper).
    pub block_hash: Hash256,
    /// Network magic for this genesis.
    pub network_magic: u32,
    /// Coinbase reward in noms.
    pub reward: u64,
    /// Genesis message inscribed in coinbase.
    pub message: String,
}

impl GenesisResult {
    /// Returns the chain_id derived from this genesis.
    ///
    /// chain_id = Blake2b-256(network_magic || genesis_hash)
    pub fn chain_id(&self) -> Hash256 {
        derive_chain_id(self.network_magic, &self.block_hash)
    }
}

/// Build the genesis block header for a given network.
///
/// # Parameters
/// - `network_magic`: NETWORK_MAGIC_MAINNET or NETWORK_MAGIC_TESTNET
/// - `timestamp`: Unix timestamp for genesis.
pub fn build_genesis(network_magic: u32, timestamp: u64) -> Result<GenesisResult, DomError> {
    let header = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        height: BlockHeight::GENESIS,
        timestamp: Timestamp(timestamp),
        prev_hash: Hash256::ZERO,
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(GENESIS_TARGET_COMPACT),
        total_difficulty: U256::from(1u64),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };

    let block_hash = hash_genesis_header(&header, network_magic)?;

    Ok(GenesisResult {
        header,
        block_hash,
        network_magic,
        reward: INITIAL_BLOCK_REWARD,
        message: GENESIS_MESSAGE.to_string(),
    })
}

/// Build mainnet genesis block.
pub fn build_mainnet_genesis() -> Result<GenesisResult, DomError> {
    build_genesis(NETWORK_MAGIC_MAINNET, GENESIS_TIMESTAMP_PLACEHOLDER)
}

/// Build testnet genesis block.
pub fn build_testnet_genesis() -> Result<GenesisResult, DomError> {
    build_genesis(NETWORK_MAGIC_TESTNET, GENESIS_TIMESTAMP_PLACEHOLDER)
}

/// Compute the genesis block hash using SHA-256 (per whitepaper).
///
/// genesis_hash = SHA-256(network_magic || timestamp || height || message)
fn hash_genesis_header(header: &BlockHeader, network_magic: u32) -> Result<Hash256, DomError> {
    let mut hasher = Sha256::new();
    hasher.update(network_magic.to_le_bytes());
    hasher.update(header.timestamp.0.to_le_bytes());
    hasher.update(header.height.0.to_le_bytes());
    hasher.update(GENESIS_MESSAGE.as_bytes());
    hasher.update(INITIAL_BLOCK_REWARD.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(Hash256::from_bytes(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_genesis_is_deterministic() {
        let g1 = build_testnet_genesis().unwrap();
        let g2 = build_testnet_genesis().unwrap();
        assert_eq!(g1.block_hash, g2.block_hash);
    }

    #[test]
    fn mainnet_testnet_genesis_differ() {
        let mainnet = build_mainnet_genesis().unwrap();
        let testnet = build_testnet_genesis().unwrap();
        assert_ne!(mainnet.block_hash, testnet.block_hash);
    }

    #[test]
    fn genesis_height_is_zero() {
        let g = build_testnet_genesis().unwrap();
        assert_eq!(g.header.height.0, 0);
    }

    #[test]
    fn genesis_prev_hash_is_zero() {
        let g = build_testnet_genesis().unwrap();
        assert_eq!(g.header.prev_hash, Hash256::ZERO);
    }

    #[test]
    fn genesis_message_matches_constant() {
        let g = build_testnet_genesis().unwrap();
        assert_eq!(g.message, GENESIS_MESSAGE);
    }

    #[test]
    fn genesis_reward_matches_constant() {
        let g = build_testnet_genesis().unwrap();
        assert_eq!(g.reward, INITIAL_BLOCK_REWARD);
    }

    #[test]
    fn chain_id_differs_by_network() {
        let mainnet = build_mainnet_genesis().unwrap();
        let testnet = build_testnet_genesis().unwrap();
        assert_ne!(mainnet.chain_id(), testnet.chain_id());
    }
}

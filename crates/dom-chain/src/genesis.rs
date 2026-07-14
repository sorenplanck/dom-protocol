//! Canonical fully rooted genesis construction for DOM Protocol.
//!
//! This module is the sole genesis authority used by node startup and vectors.
//! It serializes the same complete block that is committed to chain storage.

use dom_consensus::block::ProofOfWork;
use dom_consensus::{
    compute_block_pmmr_roots, Block, BlockHeader, CoinbaseKernel, CoinbaseTransaction,
    TransactionOutput,
};
use dom_core::{
    BlockHeight, DomError, Hash256, KERNEL_FEAT_COINBASE, PROTOCOL_VERSION, TAG_GENESIS_BLINDING,
    TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::{blake2b_256, blake2b_256_tagged};
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::{genesis_anchor, target_to_compact, target_to_difficulty, CompactTarget};
use dom_serialization::DomSerialize;
use primitive_types::U256;

/// Complete deterministic genesis construction result.
#[derive(Debug, Clone)]
pub struct CanonicalGenesis {
    /// Canonical fully rooted genesis block.
    pub block: Block,
    /// Canonical serialized header bytes.
    pub header_bytes: Vec<u8>,
    /// Canonical serialized complete block bytes.
    pub block_bytes: Vec<u8>,
    /// Blake2b-256 hash of `header_bytes`.
    pub hash: Hash256,
}

/// Build the canonical fully rooted genesis block for a recognized network.
///
/// `chain_id` is the configured chain identity used by the genesis kernel
/// signature. Mainnet and Regtest configured hashes remain intentionally
/// unfinalized; this constructor does not activate or replace them.
pub fn build_canonical_genesis(
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<CanonicalGenesis, DomError> {
    let anchor = genesis_anchor(network_magic)?;
    let coinbase = build_genesis_coinbase(chain_id)?;
    let (output_root, kernel_root, rangeproof_root) = compute_block_pmmr_roots(&coinbase, &[])?;
    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_hash: Hash256::ZERO,
        height: BlockHeight::GENESIS,
        timestamp: anchor.timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(target_to_compact(&anchor.target)),
        total_difficulty: U256::from(target_to_difficulty(&anchor.target)),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };
    let block = Block {
        header,
        coinbase,
        transactions: Vec::new(),
    };
    let header_bytes = block
        .header
        .to_bytes()
        .map_err(|error| DomError::Internal(format!("genesis header serialization: {error}")))?;
    let block_bytes = block
        .to_bytes()
        .map_err(|error| DomError::Internal(format!("genesis block serialization: {error}")))?;
    let hash = blake2b_256(&header_bytes);
    Ok(CanonicalGenesis {
        block,
        header_bytes,
        block_bytes,
        hash,
    })
}

fn build_genesis_coinbase(chain_id: &[u8; 32]) -> Result<CoinbaseTransaction, DomError> {
    let blinding_hash = blake2b_256_tagged(TAG_GENESIS_BLINDING, b"");
    let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes())
        .map_err(|error| DomError::Internal(format!("genesis blinding: {error}")))?;
    let nonce = *blake2b_256_tagged(TAG_GENESIS_BLINDING, b"bulletproof-nonce").as_bytes();
    let explicit_value = dom_core::block_reward(BlockHeight::GENESIS).noms();
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, proof_commitment) =
        dom_crypto::range_proof_prove_bytes_with_nonce(explicit_value, &blinding, &nonce)
            .map_err(|error| DomError::Internal(format!("genesis range proof failed: {error}")))?;
    if proof_commitment != *commitment.as_bytes() {
        return Err(DomError::Internal(
            "genesis range proof commitment mismatch".into(),
        ));
    }
    let excess = Commitment::commit(0, &blinding);
    let mut message_data = Vec::with_capacity(9);
    message_data.push(KERNEL_FEAT_COINBASE);
    message_data.extend_from_slice(&explicit_value.to_le_bytes());
    let message = blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &message_data);
    let key = SecretKey::from_bytes(blinding.as_bytes())
        .map_err(|error| DomError::Internal(format!("genesis blinding as key: {error}")))?;
    let signature = schnorr_sign(&key, message.as_bytes(), chain_id)
        .map_err(|error| DomError::Internal(format!("genesis signing failed: {error}")))?;

    Ok(CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: signature.to_bytes(),
        },
        offset: [0u8; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_consensus::derive_chain_id;
    use dom_core::{
        configured_genesis_hash_for_network_magic, GENESIS_HASH_TESTNET, NETWORK_MAGIC_MAINNET,
        NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
    };

    fn configured_chain_id(network_magic: u32) -> [u8; 32] {
        let genesis_hash = configured_genesis_hash_for_network_magic(network_magic).unwrap();
        *derive_chain_id(network_magic, &genesis_hash).as_bytes()
    }

    #[test]
    fn canonical_testnet_genesis_matches_frozen_identity() {
        let genesis = build_canonical_genesis(
            NETWORK_MAGIC_TESTNET,
            &configured_chain_id(NETWORK_MAGIC_TESTNET),
        )
        .unwrap();
        assert_eq!(genesis.hash.as_bytes(), &GENESIS_HASH_TESTNET);
        assert_eq!(genesis.block.coinbase.output.proof.len(), 739);
        assert_eq!(
            hex::encode(genesis.block.header.output_root.as_bytes()),
            "7dcd67abf72846eadd94cee37060ecd58ac26df2a6c1f6e74a43fe9e6aab9f1d"
        );
        assert_eq!(
            hex::encode(genesis.block.header.kernel_root.as_bytes()),
            "69a1283a2fd4a90f0df6110caf2f74150365e31ca96cc2485cb022ceae15834b"
        );
        assert_eq!(
            hex::encode(genesis.block.header.rangeproof_root.as_bytes()),
            "ac00fb8ccb323f0cfdc2f4da553ad818e289cb2614400cb6d6af4b51d18a872c"
        );
    }

    #[test]
    fn canonical_genesis_is_deterministic_for_every_configured_network() {
        for magic in [
            NETWORK_MAGIC_MAINNET,
            NETWORK_MAGIC_TESTNET,
            NETWORK_MAGIC_REGTEST,
        ] {
            let chain_id = configured_chain_id(magic);
            let expected = build_canonical_genesis(magic, &chain_id).unwrap();
            for _ in 0..10 {
                let actual = build_canonical_genesis(magic, &chain_id).unwrap();
                assert_eq!(actual.header_bytes, expected.header_bytes);
                assert_eq!(actual.block_bytes, expected.block_bytes);
                assert_eq!(actual.hash, expected.hash);
            }
        }
    }

    #[test]
    fn unknown_network_has_no_genesis_authority() {
        let error = build_canonical_genesis(0, &[0u8; 32]).unwrap_err();
        assert!(error.to_string().contains("unknown network magic"));
    }
}

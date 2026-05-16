//! Minerador DOM — loop de mineração com RandomX.

use crate::node::DomNode;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE};
use dom_crypto::pedersen::Commitment;
use dom_pow::{
    asert_next_target, genesis_anchor, hash_meets_target, randomx_seed_height,
    target_to_difficulty, CompactTarget,
};
use primitive_types::U256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn block_reward(height: u64) -> u64 {
    let epoch = height / dom_core::HALVING_INTERVAL;
    if epoch >= dom_core::HALVING_EPOCHS as u64 {
        return 0;
    }
    match usize::try_from(epoch) {
        Ok(idx) => dom_core::BLOCK_REWARD_TABLE[idx],
        Err(_) => 0,
    }
}

const SECP256K1_GENERATOR_COMPRESSED: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

fn generator_commitment() -> Result<Commitment, DomError> {
    Commitment::from_compressed_bytes(&SECP256K1_GENERATOR_COMPRESSED)
        .map_err(|e| DomError::Internal(format!("placeholder generator commitment: {e}")))
}

// TODO(mainnet-blocker): build_placeholder_coinbase uses dummy commitment (G point),
// dummy range proof (vec![0u8; 100]), and zero excess signature ([0u8; 65]).
// MUST be replaced with real CoinbaseBuilder using secp256k1-zkp + Bulletproof
// before mainnet. This placeholder is consensus-invalid on a real network.
fn build_placeholder_coinbase(
    height: BlockHeight,
    total_tx_fees: u64,
) -> Result<CoinbaseTransaction, DomError> {
    let reward = dom_core::block_reward(height).noms();
    let explicit_value = reward
        .checked_add(total_tx_fees)
        .ok_or_else(|| DomError::Invalid("coinbase value overflow".into()))?;
    let generator = generator_commitment()?;

    // This placeholder coinbase is intentionally not cryptographically valid.
    // Full validation currently logs a warning until the miner owns a real
    // signing key and can produce a real range proof and kernel signature.
    Ok(CoinbaseTransaction {
        output: TransactionOutput {
            commitment: generator.clone(),
            proof: vec![0u8; 100],
        },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess: generator,
            excess_signature: [0u8; 65],
        },
        offset: [0u8; 32],
    })
}

pub async fn mining_loop(node: Arc<DomNode>) {
    info!("Minerador iniciado");
    {
        let chain = node.chain.lock().await;
        if chain.tip_height.0 == 0 && chain.tip_hash == dom_core::Hash256::ZERO {
            drop(chain);
            if let Err(e) = create_genesis_block(node.clone()).await {
                warn!("Genesis falhou: {e}");
                return;
            }
        }
    }
    loop {
        match mine_one_block(node.clone()).await {
            Ok(h) => info!("✅ Bloco {} minerado!", h),
            Err(e) => {
                warn!("Mineracao falhou: {e}");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

async fn create_genesis_block(node: Arc<DomNode>) -> Result<(), DomError> {
    use dom_core::GENESIS_MESSAGE;
    info!("Criando bloco genesis...");
    info!("Mensagem: {}", GENESIS_MESSAGE);
    let anchor = genesis_anchor();
    let genesis_header = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        prev_hash: Hash256::ZERO,
        height: dom_core::BlockHeight::GENESIS,
        timestamp: anchor.timestamp,
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(target_to_compact(&anchor.target)),
        total_difficulty: U256::one(),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };

    let genesis_block = Block {
        header: genesis_header,
        coinbase: build_placeholder_coinbase(BlockHeight::GENESIS, 0)?,
        transactions: Vec::new(),
    };

    let mut chain = node.chain.lock().await;
    let header_bytes = {
        use dom_serialization::DomSerialize;
        genesis_block
            .header
            .to_bytes()
            .map_err(|e| DomError::Internal(format!("genesis serialize: {e}")))?
    };
    let genesis_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    chain
        .store
        .commit_block(&genesis_hash, 0, &header_bytes, &[], &[], &[])?;
    chain.tip_hash = Hash256::from_bytes(genesis_hash);
    chain.tip_height = dom_core::BlockHeight::GENESIS;
    chain.genesis_hash = Hash256::from_bytes(genesis_hash);
    info!("✅ Genesis criado! hash={}", hex::encode(genesis_hash));
    Ok(())
}

async fn mine_one_block(node: Arc<DomNode>) -> Result<u64, DomError> {
    let (tip_hash, tip_height, tip_difficulty) = {
        let chain = node.chain.lock().await;
        (chain.tip_hash, chain.tip_height, chain.tip_difficulty)
    };

    let new_height = tip_height.0 + 1;
    let anchor = genesis_anchor();
    let target = if new_height == 1 {
        anchor.target
    } else {
        asert_next_target(&anchor, Timestamp(now_secs()), BlockHeight(new_height))?
    };
    let block_diff = target_to_difficulty(&target);
    let new_total_diff = tip_difficulty.saturating_add(U256::from(block_diff));

    info!(
        "Minerando bloco {} | target: {}...",
        new_height,
        hex::encode(&target[0..4])
    );

    let seed_h = randomx_seed_height(new_height);
    let seed_hash = {
        let chain = node.chain.lock().await;
        chain
            .store
            .get_hash_at_height(seed_h)
            .ok()
            .flatten()
            .unwrap_or([0u8; 32])
    };

    let (tx, rx) = tokio::sync::oneshot::channel::<Result<BlockHeader, String>>();

    std::thread::Builder::new()
        .name(format!("miner-{}", new_height))
        .spawn(move || {
            let result = mine_blocking(new_height, tip_hash, target, new_total_diff, seed_hash);
            let _ = tx.send(result.map_err(|e| e.to_string()));
        })
        .map_err(|e| DomError::Internal(format!("spawn thread: {e}")))?;

    let header = rx
        .await
        .map_err(|e| DomError::Internal(format!("channel: {e}")))?
        .map_err(DomError::Internal)?;

    let block = Block {
        header,
        coinbase: build_placeholder_coinbase(BlockHeight(new_height), 0)?,
        transactions: Vec::new(),
    };

    {
        let mut chain = node.chain.lock().await;
        chain
            .connect_block(&block, Timestamp(now_secs()))
            .map_err(|e| DomError::Internal(format!("connect_block: {e}")))?;
    }

    Ok(new_height)
}

fn mine_blocking(
    new_height: u64,
    tip_hash: Hash256,
    target: [u8; 32],
    new_total_diff: U256,
    seed_hash: [u8; 32],
) -> Result<BlockHeader, DomError> {
    use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
    let flags = RandomXFlag::FLAG_DEFAULT;
    let cache = RandomXCache::new(flags, &seed_hash)
        .map_err(|e| DomError::Internal(format!("cache: {e}")))?;
    let vm = RandomXVM::new(flags, Some(cache), None)
        .map_err(|e| DomError::Internal(format!("vm: {e}")))?;

    let mut nonce = 0u64;
    loop {
        let header = BlockHeader {
            version: dom_core::PROTOCOL_VERSION,
            prev_hash: tip_hash,
            height: BlockHeight(new_height),
            timestamp: Timestamp(now_secs()),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(dom_core::GENESIS_TARGET_COMPACT),
            total_difficulty: new_total_diff,
            pow: ProofOfWork {
                nonce,
                randomx_hash: Hash256::ZERO,
            },
        };
        let preimage = header.pow_preimage();
        let hash = randomx_hash(&vm, &preimage)?;
        if hash_meets_target(&hash, &target) {
            let mut final_header = header;
            final_header.pow.randomx_hash = Hash256::from_bytes(hash);
            return Ok(final_header);
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn randomx_hash(vm: &randomx_rs::RandomXVM, preimage: &[u8]) -> Result<[u8; 32], DomError> {
    let v = vm
        .calculate_hash(preimage)
        .map_err(|e| DomError::Internal(format!("rx hash: {e}")))?;
    if v.len() != 32 {
        return Err(DomError::Internal("hash len != 32".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

fn target_to_compact(t: &[u8; 32]) -> u32 {
    let mut first = 0usize;
    for (i, &b) in t.iter().enumerate() {
        if b != 0 {
            first = i;
            break;
        }
    }
    let exp = (32 - first) as u32;
    let m = if first + 2 < 32 {
        ((t[first] as u32) << 16) | ((t[first + 1] as u32) << 8) | (t[first + 2] as u32)
    } else {
        (t[first] as u32) << 16
    };
    (exp << 24) | (m & 0x007f_ffff)
}

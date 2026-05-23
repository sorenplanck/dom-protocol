//! Minerador DOM — loop de mineração com RandomX.

use crate::node::DomNode;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::derive_chain_id;
use dom_consensus::{Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE};
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

/// Compute the canonical chain_id from the node's network configuration.
fn chain_id_for(config: &dom_config::NodeConfig) -> [u8; 32] {
    let genesis_hash = match config.network {
        dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
    };
    *derive_chain_id(config.network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes()
}

/// Build a cryptographically valid coinbase transaction.
///
/// Generates a fresh random blinding factor for every block. The blinding
/// factor is used as both the output blinding and the kernel signing key
/// (Mimblewimble: excess = r*G, signature proves knowledge of r).
///
/// The blinding is discarded after signing — the coinbase is consensus-valid
/// but unspendable. A wallet-integrated miner would persist the blinding.
fn build_real_coinbase(
    height: BlockHeight,
    total_tx_fees: u64,
    chain_id: &[u8; 32],
) -> Result<CoinbaseTransaction, DomError> {
    build_coinbase_with_blinding(height, total_tx_fees, chain_id, None, None)
}

/// Build the canonical genesis coinbase using a deterministic blinding factor.
///
/// The blinding is derived from `TAG_GENESIS_BLINDING` so every node produces
/// the same commitment and signature for the genesis block. This is required
/// for genesis_hash to be identical across all nodes — otherwise nodes can't
/// agree on the chain they're on.
fn build_genesis_coinbase(chain_id: &[u8; 32]) -> Result<CoinbaseTransaction, DomError> {
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::pedersen::BlindingFactor;

    // Derive deterministic blinding from a public tag — public knowledge,
    // since the genesis coinbase recipient is "everyone".
    let blinding_hash = blake2b_256_tagged(dom_core::TAG_GENESIS_BLINDING, b"");
    let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes())
        .map_err(|e| DomError::Internal(format!("genesis blinding: {e}")))?;

    // Derive a deterministic bulletproof nonce too, so the range proof is reproducible.
    let nonce_hash = blake2b_256_tagged(dom_core::TAG_GENESIS_BLINDING, b"bulletproof-nonce");
    let nonce = *nonce_hash.as_bytes();

    build_coinbase_with_blinding(
        BlockHeight::GENESIS,
        0,
        chain_id,
        Some(blinding),
        Some(nonce),
    )
}

fn build_coinbase_with_blinding(
    height: BlockHeight,
    total_tx_fees: u64,
    chain_id: &[u8; 32],
    blinding_override: Option<dom_crypto::pedersen::BlindingFactor>,
    bulletproof_nonce: Option<[u8; 32]>,
) -> Result<CoinbaseTransaction, DomError> {
    use dom_crypto::bulletproof;
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::keys::SecretKey;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::schnorr_sign;

    let reward = dom_core::block_reward(height).noms();
    let explicit_value = reward
        .checked_add(total_tx_fees)
        .ok_or_else(|| DomError::Invalid("coinbase value overflow".into()))?;

    // Either use the provided blinding (genesis) or generate fresh (normal blocks).
    let blinding = match blinding_override {
        Some(b) => b,
        None => BlindingFactor::random(),
    };

    // Output commitment: C = value*H + r*G
    let output_commitment = Commitment::commit(explicit_value, &blinding);

    // Range proof: proves value in [0, 2^52)
    let (range_proof, _) = match bulletproof_nonce {
        Some(nonce) => bulletproof::prove_with_nonce(explicit_value, &blinding, &nonce)
            .map_err(|e| DomError::Internal(format!("coinbase range proof failed: {e}")))?,
        None => bulletproof::prove(explicit_value, &blinding)
            .map_err(|e| DomError::Internal(format!("coinbase range proof failed: {e}")))?,
    };

    // Kernel excess = r*G (Mimblewimble: coinbase creates value, excess is blinding only)
    let excess = Commitment::commit(0, &blinding);

    // Kernel message: TAG_KERNEL_MSG_COINBASE || features || explicit_value_le8
    let kernel_message = {
        let mut data = Vec::with_capacity(9);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&explicit_value.to_le_bytes());
        blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &data)
    };

    // Sign with blinding as secret key — proves ownership of the excess point
    let sk = SecretKey::from_bytes(blinding.as_bytes())
        .map_err(|e| DomError::Internal(format!("coinbase blinding as key: {e}")))?;
    let signature = schnorr_sign(&sk, kernel_message.as_bytes(), chain_id)
        .map_err(|e| DomError::Internal(format!("coinbase sign failed: {e}")))?;

    Ok(CoinbaseTransaction {
        output: TransactionOutput {
            commitment: output_commitment,
            proof: range_proof.bytes,
        },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: signature.to_bytes(),
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

pub async fn create_genesis_block(node: Arc<DomNode>) -> Result<(), DomError> {
    use dom_core::GENESIS_MESSAGE;
    use dom_pmmr::Pmmr;
    info!("Criando bloco genesis...");
    info!("Mensagem: {}", GENESIS_MESSAGE);
    let anchor = genesis_anchor();

    // Deterministic genesis coinbase — identical on every node.
    let genesis_coinbase = build_genesis_coinbase(&chain_id_for(&node.config))?;

    // Compute PMMR roots from the coinbase so the header is self-consistent.
    let output_root = {
        let mut mmr = Pmmr::new();
        mmr.push(genesis_coinbase.output.commitment.as_bytes())?;
        mmr.root()
    };
    let kernel_root = {
        let mut mmr = Pmmr::new();
        mmr.push(genesis_coinbase.kernel.excess.as_bytes())?;
        mmr.root()
    };
    let rangeproof_root = {
        let mut mmr = Pmmr::new();
        mmr.push(&genesis_coinbase.output.proof)?;
        mmr.root()
    };

    let genesis_header = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        prev_hash: Hash256::ZERO,
        height: dom_core::BlockHeight::GENESIS,
        timestamp: anchor.timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
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
        coinbase: genesis_coinbase,
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
    let genesis_body = {
        use dom_serialization::DomSerialize;
        genesis_block
            .to_bytes()
            .map_err(|e| DomError::Internal(format!("genesis body serialize: {e}")))?
    };
    chain.store.commit_block(
        &genesis_hash,
        0,
        &header_bytes,
        &genesis_body,
        &[],
        &[],
        &[],
    )?;
    chain.tip_hash = Hash256::from_bytes(genesis_hash);
    chain.tip_height = dom_core::BlockHeight::GENESIS;
    chain.tip_difficulty = primitive_types::U256::one();
    chain.genesis_hash = Hash256::from_bytes(genesis_hash);
    info!("✅ Genesis criado! hash={}", hex::encode(genesis_hash));
    Ok(())
}

pub async fn mine_one_block(node: Arc<DomNode>) -> Result<u64, DomError> {
    let (tip_hash, tip_height, tip_difficulty) = {
        let chain = node.chain.lock().await;
        (chain.tip_hash, chain.tip_height, chain.tip_difficulty)
    };

    let new_height = tip_height.0 + 1;
    let anchor = genesis_anchor();
    // Testnet: use easy target so blocks are findable in seconds on a CPU.
    // Mainnet: full ASERT difficulty from anchor.
    let target = if node.config.network == dom_config::Network::Testnet {
        dom_core::MAX_TARGET_BYTES
    } else if new_height == 1 {
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

    // Build coinbase before mining so we can include PMMR roots in the header.
    // Build coinbase: use wallet if available, fallback to random blinding
    let coinbase = if let Some(ref wallet_arc) = node.wallet {
        // Wallet-integrated mining: deterministic blinding, output recorded
        let mut wallet = wallet_arc.lock().await;
        wallet.build_coinbase(BlockHeight(new_height), 0)
            .map_err(|e| DomError::Internal(format!("wallet coinbase: {e}")))?
    } else {
        // Fallback: random blinding, output NOT recorded (DOM-SEC-004 unresolved)
        warn!("Mining without wallet — rewards will NOT be spendable (DOM-SEC-004)");
        build_real_coinbase(BlockHeight(new_height), 0, &chain_id_for(&node.config))?
    };

    let output_root = {
        let mut mmr = dom_pmmr::Pmmr::new();
        mmr.push(coinbase.output.commitment.as_bytes())?;
        mmr.root()
    };
    let kernel_root = {
        let mut mmr = dom_pmmr::Pmmr::new();
        mmr.push(coinbase.kernel.excess.as_bytes())?;
        mmr.root()
    };
    let rangeproof_root = {
        let mut mmr = dom_pmmr::Pmmr::new();
        mmr.push(&coinbase.output.proof)?;
        mmr.root()
    };

    let (tx, rx) = tokio::sync::oneshot::channel::<Result<BlockHeader, String>>();
    std::thread::Builder::new()
        .name(format!("miner-{}", new_height))
        .spawn(move || {
            let result = mine_blocking(
                new_height,
                tip_hash,
                target,
                new_total_diff,
                seed_hash,
                output_root,
                kernel_root,
                rangeproof_root,
            );
            let _ = tx.send(result.map_err(|e| e.to_string()));
        })
        .map_err(|e| DomError::Internal(format!("spawn thread: {e}")))?;
    let header = rx
        .await
        .map_err(|e| DomError::Internal(format!("channel: {e}")))?
        .map_err(DomError::Internal)?;
    let block = Block {
        header,
        coinbase,
        transactions: Vec::new(),
    };

    let connect_outcome = {
        let mut chain = node.chain.lock().await;
        chain
            .connect_block(&block, Timestamp(now_secs()))
            .map_err(|e| DomError::Internal(format!("connect_block: {e}")))?
    };

    // Miner just produced a fresh block — anything other than BestChain is a bug
    // (someone else mined the same hash? race? duplicate state?). Log loudly
    // but don't crash, since the block validation already passed.
    match connect_outcome {
        dom_chain::ConnectResult::BestChain => { /* normal path */ }
        dom_chain::ConnectResult::SideChain => {
            tracing::warn!(
                "Miner block at height {} accepted as SideChain — race with another miner?",
                new_height
            );
        }
        dom_chain::ConnectResult::AlreadyHave => {
            tracing::warn!(
                "Miner block at height {} was AlreadyHave — duplicate hash, very unusual",
                new_height
            );
            // Don't relay — peers already have it (somehow).
            return Ok(new_height);
        }
    }

    // Scan block for wallet outputs (coinbase reward recovery).
    if let Some(ref wallet_arc) = node.wallet {
        let mut wallet = wallet_arc.lock().await;
        wallet.scan_block(&block.transactions, new_height);
    }

    // Relay newly-mined block to all connected peers via broadcast channel.
    // Only reached for BestChain or SideChain (AlreadyHave returns early above).
    let block_bytes = {
        use dom_serialization::DomSerialize;
        block
            .to_bytes()
            .map_err(|e| DomError::Internal(format!("serialize block for relay: {e}")))?
    };
    let _ = node.block_relay_tx.send(block_bytes);

    Ok(new_height)
}

#[allow(clippy::too_many_arguments)]
fn mine_blocking(
    new_height: u64,
    tip_hash: Hash256,
    target: [u8; 32],
    new_total_diff: U256,
    seed_hash: [u8; 32],
    output_root: Hash256,
    kernel_root: Hash256,
    rangeproof_root: Hash256,
) -> Result<BlockHeader, DomError> {
    use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
    let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
    let cache = RandomXCache::new(flags, &seed_hash)
        .map_err(|e| DomError::Internal(format!("cache: {e}")))?;
    let dataset = RandomXDataset::new(flags, cache.clone(), 0)
        .map_err(|e| DomError::Internal(format!("dataset: {e}")))?;
    let vm = RandomXVM::new(flags, Some(cache), Some(dataset))
        .map_err(|e| DomError::Internal(format!("vm: {e}")))?;

    let mut nonce = 0u64;
    loop {
        let header = BlockHeader {
            version: dom_core::PROTOCOL_VERSION,
            prev_hash: tip_hash,
            height: BlockHeight(new_height),
            timestamp: Timestamp(now_secs()),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(target_to_compact(&target)),
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

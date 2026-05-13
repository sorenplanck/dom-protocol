//! Minerador DOM — loop de mineração com RandomX.

use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp, INITIAL_BLOCK_REWARD};
use dom_pow::{
    asert_next_target, genesis_anchor, hash_meets_target,
    randomx_seed_height, CompactTarget, target_to_difficulty,
};
use primitive_types::U256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use crate::node::DomNode;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn block_reward(height: u64) -> u64 {
    let epoch = height / dom_core::HALVING_INTERVAL;
    if epoch >= 64 { return 0; }
    INITIAL_BLOCK_REWARD >> epoch
}

pub async fn mining_loop(node: Arc<DomNode>) {
    info!("Minerador iniciado");

    // Cria bloco genesis se chain estiver vazia
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

    let mut chain = node.chain.lock().await;
    // Commita genesis diretamente no store sem validar PoW
    let header_bytes = {
        use dom_serialization::DomSerialize;
        genesis_header.to_bytes()
            .map_err(|e| DomError::Internal(format!("genesis serialize: {e}")))?
    };

    // Calcula hash do genesis usando Blake2b-256 (consenso DOM).
    // RFC-0001: todo Hash256 do protocolo é Blake2b. Usar SHA256 aqui
    // produziria genesis hash incompatível com outras implementações.
    let genesis_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();

    chain.store.commit_block(
        &genesis_hash,
        0,
        &header_bytes,
        &[], &[], &[],
    )?;

    // Atualiza tip
    chain.tip_hash = Hash256::from_bytes(genesis_hash);
    chain.tip_height = dom_core::BlockHeight::GENESIS;
    chain.genesis_hash = Hash256::from_bytes(genesis_hash);

    info!("✅ Genesis criado! hash={}", hex::encode(genesis_hash));
    info!("   Mensagem: {}", GENESIS_MESSAGE);
    Ok(())
}

async fn mine_one_block(node: Arc<DomNode>) -> Result<u64, DomError> {
    let (tip_hash, tip_height, tip_difficulty) = {
        let chain = node.chain.lock().await;
        (chain.tip_hash, chain.tip_height, chain.tip_difficulty)
    };

    let new_height = tip_height.0 + 1;
    let anchor = genesis_anchor();
    // Bloco 1: usar target do anchor diretamente (ASERT ainda não tem histórico)
    // A partir do bloco 2, ASERT ajusta normalmente
    let target = if new_height == 1 {
        anchor.target
    } else {
        asert_next_target(&anchor, Timestamp(now_secs()), BlockHeight(new_height))?
    };
    let block_diff = target_to_difficulty(&target);
    let new_total_diff = tip_difficulty.saturating_add(U256::from(block_diff));

    info!("Minerando bloco {} | target: {}...", new_height, hex::encode(&target[0..4]));

    let seed_h = randomx_seed_height(new_height);
    let seed_hash = {
        let chain = node.chain.lock().await;
        chain.store.get_hash_at_height(seed_h).ok().flatten().unwrap_or([0u8; 32])
    };

    // Canal oneshot — thread envia resultado, async aguarda
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<BlockHeader, String>>();

    std::thread::Builder::new()
        .name(format!("miner-{}", new_height))
        .spawn(move || {
            eprintln!("[miner] Thread iniciada para bloco {}", new_height);
            
            let result = mine_blocking(
                new_height, tip_hash, target, new_total_diff, seed_hash
            );
            
            let _ = tx.send(result.map_err(|e| e.to_string()));
        })
        .map_err(|e| DomError::Internal(format!("spawn thread: {e}")))?;

    // Aguarda resultado sem bloquear o runtime
    let header = rx.await
        .map_err(|e| DomError::Internal(format!("channel: {e}")))?
        .map_err(|e| DomError::Internal(e))?;

    // Submete à chain
    {
        let mut chain = node.chain.lock().await;
        chain.connect_block(&header, Timestamp(now_secs()))
            .map_err(|e| DomError::Internal(format!("connect_block: {e}")))?;
    }

    Ok(new_height)
}

/// Mineração bloqueante — roda em thread OS dedicada.
fn mine_blocking(
    new_height: u64,
    tip_hash: Hash256,
    target: [u8; 32],
    new_total_diff: U256,
    seed_hash: [u8; 32],
) -> Result<BlockHeader, DomError> {
    use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

    eprintln!("[miner] Criando RandomX VM...");
    let flags = RandomXFlag::FLAG_DEFAULT;
    let cache = RandomXCache::new(flags, &seed_hash)
        .map_err(|e| DomError::Internal(format!("cache: {e}")))?;
    let vm = RandomXVM::new(flags, Some(cache), None)
        .map_err(|e| DomError::Internal(format!("vm: {e}")))?;
    eprintln!("[miner] VM pronta! Buscando nonce...");

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
            pow: ProofOfWork { nonce, randomx_hash: Hash256::ZERO },
        };

        let preimage = serialize_preimage(&header)?;
        let hash = randomx_hash(&vm, &preimage)?;

        if hash_meets_target(&hash, &target) {
            let mut final_header = header;
            final_header.pow.randomx_hash = Hash256::from_bytes(hash);
            eprintln!("[miner] BLOCO! nonce={} hash={}", nonce, hex::encode(&hash[0..8]));
            return Ok(final_header);
        }

        nonce = nonce.wrapping_add(1);
        if nonce % 5 == 0 {
            eprintln!("[miner] nonce={}", nonce);
        }
    }
}

fn randomx_hash(vm: &randomx_rs::RandomXVM, preimage: &[u8]) -> Result<[u8; 32], DomError> {
    let v = vm.calculate_hash(preimage)
        .map_err(|e| DomError::Internal(format!("rx hash: {e}")))?;
    if v.len() != 32 {
        return Err(DomError::Internal("hash len != 32".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

fn serialize_preimage(h: &BlockHeader) -> Result<Vec<u8>, DomError> {
    let mut out = Vec::with_capacity(200);
    out.extend_from_slice(&h.version.to_le_bytes());
    out.extend_from_slice(h.prev_hash.as_bytes());
    out.extend_from_slice(&h.height.0.to_le_bytes());
    out.extend_from_slice(&h.timestamp.0.to_le_bytes());
    out.extend_from_slice(h.output_root.as_bytes());
    out.extend_from_slice(h.kernel_root.as_bytes());
    out.extend_from_slice(h.rangeproof_root.as_bytes());
    out.extend_from_slice(&h.total_kernel_offset);
    out.extend_from_slice(&h.target.0.to_le_bytes());
    let mut td = [0u8; 32];
    h.total_difficulty.to_big_endian(&mut td);
    out.extend_from_slice(&td);
    out.extend_from_slice(&h.pow.nonce.to_le_bytes());
    Ok(out)
}

fn target_to_compact(t: &[u8; 32]) -> u32 {
    let mut first = 0usize;
    for (i, &b) in t.iter().enumerate() {
        if b != 0 { first = i; break; }
    }
    let exp = (32 - first) as u32;
    let m = if first + 2 < 32 {
        ((t[first] as u32) << 16) | ((t[first+1] as u32) << 8) | (t[first+2] as u32)
    } else {
        (t[first] as u32) << 16
    };
    (exp << 24) | (m & 0x007f_ffff)
}

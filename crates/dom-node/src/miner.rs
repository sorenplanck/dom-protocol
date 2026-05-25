//! Minerador DOM — loop de mineração com RandomX.

use crate::node::DomNode;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{compute_block_pmmr_roots, derive_chain_id};
use dom_consensus::{
    Block, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionOutput,
};
use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, MAX_BLOCK_WEIGHT,
    WEIGHT_COINBASE_KERNEL, WEIGHT_OUTPUT,
};
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
        dom_config::Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
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

/// Create the deterministic genesis block on a fresh chain.
///
/// **TEST-INFRASTRUCTURE API. Not part of the stable public surface.**
///
/// Exposed as `pub` so integration test helpers can bootstrap genesis
/// without spawning the full `mining_loop`. Production code paths reach
/// genesis creation only via `mining_loop` (which calls this internally
/// under a tip-height guard) — never call this from production code.
///
/// Idempotency: callers MUST guard with a check that `chain.tip_height == 0`
/// and `chain.tip_hash == Hash256::ZERO`. Calling on an initialized chain
/// will fail under the LMDB NO_OVERWRITE protection added in DOM-LMDB-001
/// (commit 1b26b13).
///
/// Audit (2026-05-23, second auditor ACHADO 6): marked `#[doc(hidden)]`
/// to keep this out of generated rustdoc despite needing `pub` visibility.
#[doc(hidden)]
pub async fn create_genesis_block(node: Arc<DomNode>) -> Result<(), DomError> {
    use dom_core::GENESIS_MESSAGE;
    info!("Criando bloco genesis...");
    info!("Mensagem: {}", GENESIS_MESSAGE);
    let anchor = genesis_anchor();

    // Deterministic genesis coinbase — identical on every node.
    let genesis_coinbase = build_genesis_coinbase(&chain_id_for(&node.config))?;

    // Compute PMMR roots from the coinbase via the shared helper so the
    // genesis header is byte-identical to what every validator will
    // recompute on disk during connect_block.
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&genesis_coinbase, &[])?;

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
    // NOTE: do NOT overwrite chain.genesis_hash with the computed hash here.
    // The chain_id used for kernel signatures is derived from the *constant*
    // GENESIS_HASH_{MAINNET,TESTNET,REGTEST} (see chain_id_for() and
    // Wallet::create). Overwriting chain.genesis_hash with the live
    // computed hash makes ValidationContext.chain_id diverge from what the
    // miner/wallet signed with, and every block fails kernel-signature
    // verification. Pre-launch, set the constants to the real precomputed
    // genesis hash; until then, all sites consistently use the placeholder.
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
    // Network-specific target selection:
    //   - Regtest: the defensively-named REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION
    //     (every RandomX hash satisfies it; mining wins on the first nonce).
    //   - Testnet: MAX_TARGET_BYTES (every CPU finds blocks in seconds).
    //   - Mainnet: full ASERT difficulty from the genesis anchor.
    let target = match node.config.network {
        dom_config::Network::Regtest => dom_core::REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION,
        dom_config::Network::Testnet => dom_core::MAX_TARGET_BYTES,
        dom_config::Network::Mainnet => {
            if new_height == 1 {
                anchor.target
            } else {
                asert_next_target(&anchor, Timestamp(now_secs()), BlockHeight(new_height))?
            }
        }
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

    // ── Mempool inclusion (DOM-PMMR-002 Phase C) ──────────────────────────────
    //
    // Snapshot the highest-fee mempool entries that fit under the
    // block-weight budget once, before mining starts. The mempool lock
    // is dropped before the wallet or chain locks are acquired, so the
    // ordering is monotonic and dead-lock free.
    //
    // The coinbase always claims 1 output (WEIGHT_OUTPUT) and 1 coinbase
    // kernel (WEIGHT_COINBASE_KERNEL); reserve those before passing the
    // tx-weight budget to `select_for_block`. A future block-template
    // refactor would add per-tx weight tightening (e.g. dropping
    // marginal-fee txs that no longer fit after the coinbase grows) —
    // for now the coinbase weight is constant and the conservative
    // budget below mirrors what validate_block enforces.
    let tx_weight_budget = MAX_BLOCK_WEIGHT
        .saturating_sub(WEIGHT_OUTPUT)
        .saturating_sub(WEIGHT_COINBASE_KERNEL);
    let selected_txs: Vec<Transaction> = {
        let mempool = node.mempool.lock().await;
        mempool
            .select_for_block(tx_weight_budget)
            .into_iter()
            .map(|e| e.tx.clone())
            .collect()
    };
    let total_tx_fees: u64 = selected_txs.iter().try_fold(0u64, |acc, tx| {
        let fee = tx.total_fee()?;
        acc.checked_add(fee)
            .ok_or_else(|| DomError::Invalid("mempool fee sum overflow".into()))
    })?;
    if !selected_txs.is_empty() {
        info!(
            "Bloco {}: incluindo {} tx(s) da mempool, fees totais = {} noms",
            new_height,
            selected_txs.len(),
            total_tx_fees
        );
    }

    // Build coinbase reflecting tx fees so explicit_value == reward + fees.
    let coinbase = if let Some(ref wallet_arc) = node.wallet {
        // Wallet-integrated mining: deterministic blinding, output recorded
        let mut wallet = wallet_arc.lock().await;
        wallet
            .build_coinbase(BlockHeight(new_height), total_tx_fees)
            .map_err(|e| DomError::Internal(format!("wallet coinbase: {e}")))?
    } else {
        // Fallback: random blinding, output NOT recorded (DOM-SEC-004 unresolved)
        warn!("Mining without wallet — rewards will NOT be spendable (DOM-SEC-004)");
        build_real_coinbase(
            BlockHeight(new_height),
            total_tx_fees,
            &chain_id_for(&node.config),
        )?
    };

    // PMMR roots over coinbase + selected mempool txs. Single source
    // of truth: `compute_block_pmmr_roots` is the same helper that
    // `validate_pmmr_roots` runs during block acceptance, so the miner
    // cannot drift on iteration order.
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &selected_txs)?;

    // All networks mine with FLAG_FULL_MEM (~2 GB dataset + ~256 MB cache
    // per active miner thread) for ~10× hash-rate vs the cache-only VM.
    // RandomX hash output is identical between modes — only the prover
    // speed differs — so consensus validation does not care which mode
    // the miner used. Validators (dom-pow::randomx_pool) intentionally
    // stay on the cache-only path: validation is occasional and shouldn't
    // pay the dataset cost.
    //
    // Memory budget: ~2.3 GB per active miner thread. Two-node Regtest
    // integration runs (~4.6 GB miners + node baseline) fit on 8 GB hosts.
    // On lower-RAM laptops, set light_vm = true here if you hit OOM —
    // mining will be ~10× slower but functionally identical.
    let light_vm = false;
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
                light_vm,
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
        transactions: selected_txs,
    };

    let connect_outcome = {
        let mut chain = node.chain.lock().await;
        chain
            .connect_block(&block, Timestamp(now_secs()))
            .map_err(|e| DomError::Internal(format!("connect_block: {e}")))?
    };

    // Miner just produced a fresh block. BestChain is the normal path.
    // SideChain is a natural race in PoW (another peer relayed faster, or
    // two miners found blocks simultaneously) — debug-level, not anomalous.
    // AlreadyHave on a freshly-mined block is very unusual (nonce collision?
    // duplicate state?) but not crash-worthy — log and skip relay.
    //
    // Audit (2026-05-23, first auditor): SideChain should not be warn-level
    // because it pollutes logs under normal pool/solo miner concurrency.
    match connect_outcome {
        dom_chain::ConnectResult::BestChain => { /* normal path */ }
        dom_chain::ConnectResult::SideChain => {
            tracing::debug!(
                "Miner block at height {} accepted as SideChain (race with relayed block)",
                new_height
            );
        }
        dom_chain::ConnectResult::AlreadyHave => {
            tracing::debug!(
                "Miner block at height {} was AlreadyHave (unusual but benign)",
                new_height
            );
            // Don't relay — peers already have it (somehow).
            return Ok(new_height);
        }
    }

    // Drain the mempool of every transaction whose inputs were just
    // confirmed. `remove_confirmed` evicts by input commitment, so any
    // descendant that would now double-spend a freshly-consumed UTXO
    // is also cleaned up, not just the txs we packed into the block.
    {
        let mut all_inputs: Vec<[u8; 33]> =
            Vec::with_capacity(block.transactions.iter().map(|tx| tx.inputs.len()).sum());
        for tx in &block.transactions {
            for input in &tx.inputs {
                all_inputs.push(*input.commitment.as_bytes());
            }
        }
        if !all_inputs.is_empty() {
            let mut mempool = node.mempool.lock().await;
            mempool.remove_confirmed(&all_inputs);
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
    light_vm: bool,
) -> Result<BlockHeader, DomError> {
    use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
    // Mainnet / Testnet mining sets `FLAG_FULL_MEM` for throughput
    // (allocates the ~2 GB RandomX dataset). Regtest opts out via
    // `light_vm = true` and uses the cache-only VM (~256 MB) — slow per
    // hash but trivial target means we still find a block on the first
    // attempt, and two miners fit in a developer laptop's RAM.
    let flags = if light_vm {
        RandomXFlag::get_recommended_flags()
    } else {
        RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM
    };
    let cache = RandomXCache::new(flags, &seed_hash)
        .map_err(|e| DomError::Internal(format!("cache: {e}")))?;
    let vm = if light_vm {
        // Cache-only VM. No dataset is allocated.
        RandomXVM::new(flags, Some(cache), None)
            .map_err(|e| DomError::Internal(format!("vm: {e}")))?
    } else {
        let dataset = RandomXDataset::new(flags, cache.clone(), 0)
            .map_err(|e| DomError::Internal(format!("dataset: {e}")))?;
        RandomXVM::new(flags, Some(cache), Some(dataset))
            .map_err(|e| DomError::Internal(format!("vm: {e}")))?
    };

    // Heartbeat: blocks can take minutes to hours under low-effort targets +
    // light VM. Without a periodic log, "stuck" miners are indistinguishable
    // from "still hashing" — log every HEARTBEAT_NONCES iterations with the
    // current hash-rate so operators (and tests) see continuous progress.
    const HEARTBEAT_NONCES: u64 = 5_000;
    let mining_start = std::time::Instant::now();
    let mut last_heartbeat = mining_start;
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
        if nonce.is_multiple_of(HEARTBEAT_NONCES) {
            let now = std::time::Instant::now();
            let window = now.duration_since(last_heartbeat).as_secs_f64();
            let hps = if window > 0.0 {
                HEARTBEAT_NONCES as f64 / window
            } else {
                0.0
            };
            info!(
                "⛏ minerando h={} | nonces={} | {:.1} H/s | total={:.1}s",
                new_height,
                nonce,
                hps,
                mining_start.elapsed().as_secs_f64()
            );
            last_heartbeat = now;
        }
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

#[cfg(test)]
mod genesis_determinism_tests {
    //! Roadmap v2 Phase 6.3 — Bootstrap recoverability proofs.
    //!
    //! The protocol's "wipe the data_dir and rebuild from genesis"
    //! recovery story is only useful if the rebuilt genesis is
    //! byte-identical to the one that any other node would build from
    //! the same constants. These tests pin that property at the
    //! coinbase + PMMR-root layer, without going through RandomX
    //! (which is what makes the full chain_persistence integration
    //! test slow — see RB-PMMR-001 deferred validation gaps).
    //!
    //! Coverage:
    //!   1. `build_genesis_coinbase` is deterministic across N calls.
    //!   2. The three PMMR roots over the genesis coinbase are
    //!      deterministic across N calls.
    //!   3. Different chain_ids produce different coinbases (sanity:
    //!      Mainnet vs Testnet vs Regtest genesis must NOT collide).

    use super::build_genesis_coinbase;
    use dom_consensus::compute_block_pmmr_roots;
    use dom_serialization::DomSerialize;

    fn chain_id_mainnet() -> [u8; 32] {
        use dom_consensus::derive_chain_id;
        use dom_core::Hash256;
        *derive_chain_id(
            dom_core::NETWORK_MAGIC_MAINNET,
            &Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET),
        )
        .as_bytes()
    }

    fn chain_id_testnet() -> [u8; 32] {
        use dom_consensus::derive_chain_id;
        use dom_core::Hash256;
        *derive_chain_id(
            dom_core::NETWORK_MAGIC_TESTNET,
            &Hash256::from_bytes(dom_core::GENESIS_HASH_TESTNET),
        )
        .as_bytes()
    }

    fn chain_id_regtest() -> [u8; 32] {
        use dom_consensus::derive_chain_id;
        use dom_core::Hash256;
        *derive_chain_id(
            dom_core::NETWORK_MAGIC_REGTEST,
            &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        )
        .as_bytes()
    }

    /// Building the genesis coinbase N times for the same chain_id
    /// MUST produce byte-identical commitment, excess, and signature.
    /// A divergence here means a node restarted with the data_dir
    /// wiped would compute a different genesis hash than its peers —
    /// silent fork at height 0.
    #[test]
    fn genesis_coinbase_is_deterministic_across_runs() {
        for cid_fn in [
            chain_id_mainnet as fn() -> [u8; 32],
            chain_id_testnet,
            chain_id_regtest,
        ] {
            let cid = cid_fn();
            let a = build_genesis_coinbase(&cid).expect("build genesis coinbase #1");
            for trial in 0..8 {
                let b = build_genesis_coinbase(&cid).expect("build genesis coinbase #N");
                let a_bytes = a.to_bytes().expect("serialize a");
                let b_bytes = b.to_bytes().expect("serialize b");
                assert_eq!(
                    a_bytes, b_bytes,
                    "trial {trial}: genesis coinbase is non-deterministic on this network"
                );
                assert_eq!(
                    a.output.commitment.as_bytes(),
                    b.output.commitment.as_bytes()
                );
                assert_eq!(a.kernel.excess.as_bytes(), b.kernel.excess.as_bytes());
                assert_eq!(a.kernel.excess_signature, b.kernel.excess_signature);
            }
        }
    }

    /// The three PMMR roots over the genesis coinbase MUST be
    /// deterministic across N rebuilds. This is the bootstrap
    /// invariant a "wipe and re-sync from genesis" workflow depends
    /// on: every fresh node must produce the same output_root /
    /// kernel_root / rangeproof_root for the genesis block.
    #[test]
    fn genesis_pmmr_roots_are_deterministic_across_runs() {
        let cid = chain_id_regtest();
        let a = build_genesis_coinbase(&cid).expect("build genesis coinbase");
        let (a_or, a_kr, a_rr) =
            compute_block_pmmr_roots(&a, &[]).expect("compute genesis roots");

        for trial in 0..8 {
            let b = build_genesis_coinbase(&cid).expect("build genesis coinbase #N");
            let (b_or, b_kr, b_rr) =
                compute_block_pmmr_roots(&b, &[]).expect("compute genesis roots #N");
            assert_eq!(a_or, b_or, "trial {trial}: output_root drift");
            assert_eq!(a_kr, b_kr, "trial {trial}: kernel_root drift");
            assert_eq!(a_rr, b_rr, "trial {trial}: rangeproof_root drift");
        }
    }

    /// Sanity: distinct chain_ids must produce distinct genesis
    /// coinbases. This is the cross-network safety property — a
    /// mainnet genesis MUST NOT replay onto testnet.
    #[test]
    fn genesis_coinbase_differs_across_networks() {
        let m = build_genesis_coinbase(&chain_id_mainnet()).expect("mainnet");
        let t = build_genesis_coinbase(&chain_id_testnet()).expect("testnet");
        let r = build_genesis_coinbase(&chain_id_regtest()).expect("regtest");
        assert_ne!(
            m.kernel.excess_signature, t.kernel.excess_signature,
            "mainnet and testnet genesis signatures must differ"
        );
        assert_ne!(
            m.kernel.excess_signature, r.kernel.excess_signature,
            "mainnet and regtest genesis signatures must differ"
        );
        assert_ne!(
            t.kernel.excess_signature, r.kernel.excess_signature,
            "testnet and regtest genesis signatures must differ"
        );
    }
}

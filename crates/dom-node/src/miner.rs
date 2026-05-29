//! Minerador DOM — loop de mineração com RandomX.

use crate::node::{reconcile_mempool_after_connect, DomNode};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{compute_block_pmmr_roots, derive_chain_id};
use dom_consensus::{Block, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionOutput};
use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, MAX_BLOCK_WEIGHT,
    WEIGHT_COINBASE_KERNEL, WEIGHT_OUTPUT,
};
use dom_pow::{
    compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target,
    pow_validation_mode_for_network, randomx_seed_height, target_to_compact, target_to_difficulty,
    CompactTarget, PowValidationMode,
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
fn chain_id_for(config: &dom_config::NodeConfig) -> Result<[u8; 32], DomError> {
    let genesis_hash = dom_core::startup_genesis_hash_for_network_magic(config.network.magic())?;
    Ok(*derive_chain_id(config.network.magic(), &genesis_hash).as_bytes())
}

fn use_light_vm(network: dom_config::Network) -> bool {
    matches!(network, dom_config::Network::Regtest)
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

async fn finalize_mined_block(node: &Arc<DomNode>, block: Block) -> Result<u64, DomError> {
    let new_height = block.header.height.0;
    let coinbase_commitment = *block.coinbase.output.commitment.as_bytes();

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
        dom_chain::ConnectResult::Reorg(_) => {
            tracing::debug!(
                "Miner block at height {} triggered a heavier known-tip reorg",
                new_height
            );
        }
        dom_chain::ConnectResult::SideChain => {
            tracing::debug!(
                "Miner block at height {} accepted as SideChain (race with relayed block)",
                new_height
            );
            if let Some(ref wallet_arc) = node.wallet {
                let mut wallet = wallet_arc.lock().await;
                wallet.forget_output(&coinbase_commitment);
            }
        }
        dom_chain::ConnectResult::AlreadyHave => {
            tracing::debug!(
                "Miner block at height {} was AlreadyHave (unusual but benign)",
                new_height
            );
            if let Some(ref wallet_arc) = node.wallet {
                let mut wallet = wallet_arc.lock().await;
                wallet.forget_output(&coinbase_commitment);
            }
            // Don't relay — peers already have it (somehow).
            return Ok(new_height);
        }
    }

    reconcile_mempool_after_connect(
        &node.chain,
        &node.mempool,
        &connect_outcome,
        &block.transactions,
    )
    .await
    .map_err(|e| DomError::Internal(format!("mempool reconciliation: {e}")))?;

    // Scan block for wallet outputs (coinbase reward recovery).
    if matches!(connect_outcome, dom_chain::ConnectResult::BestChain) {
        if let Some(ref wallet_arc) = node.wallet {
            let mut wallet = wallet_arc.lock().await;
            wallet
                .apply_canonical_block(&block.transactions, new_height)
                .map_err(|e| DomError::Internal(format!("wallet canonical block apply: {e}")))?;
        }
    } else if matches!(connect_outcome, dom_chain::ConnectResult::Reorg(_)) {
        tracing::debug!(
            "Skipping wallet canonical apply for mined reorg block at height {}; rollback hooks remain explicit follow-up work",
            new_height
        );
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
    let anchor = genesis_anchor(node.config.network.magic())?;

    // Deterministic genesis coinbase — identical on every node.
    let genesis_chain_id = chain_id_for(&node.config)?;
    let genesis_coinbase = build_genesis_coinbase(&genesis_chain_id)?;

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
        total_difficulty: U256::from(target_to_difficulty(&anchor.target)),
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
    chain.tip_difficulty = primitive_types::U256::from(target_to_difficulty(&anchor.target));
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
    let block_timestamp = Timestamp(now_secs());
    let target = compute_expected_target(
        node.config.network.magic(),
        block_timestamp,
        BlockHeight(new_height),
    )?;
    let block_diff = target_to_difficulty(&target);
    let new_total_diff = tip_difficulty.saturating_add(U256::from(block_diff));
    let pow_mode = pow_validation_mode_for_network(node.config.network.magic())?;

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
            &chain_id_for(&node.config)?,
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
    // Memory budget: ~2.3 GB per active miner thread in full-mem mode.
    // Regtest always uses the cache-only VM: its dev-only target remains
    // low effort (~2^-16 acceptance against MAX_TARGET_BYTES) and does not
    // justify allocating a multi-gigabyte dataset just to mine test blocks.
    let light_vm = use_light_vm(node.config.network);
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<BlockHeader, String>>();
    std::thread::Builder::new()
        .name(format!("miner-{}", new_height))
        .spawn(move || {
            let result = mine_blocking(
                new_height,
                tip_hash,
                block_timestamp,
                target,
                new_total_diff,
                seed_hash,
                output_root,
                kernel_root,
                rangeproof_root,
                light_vm,
                pow_mode,
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
    finalize_mined_block(&node, block).await
}

#[allow(clippy::too_many_arguments)]
fn mine_blocking(
    new_height: u64,
    tip_hash: Hash256,
    block_timestamp: Timestamp,
    target: [u8; 32],
    new_total_diff: U256,
    seed_hash: [u8; 32],
    output_root: Hash256,
    kernel_root: Hash256,
    rangeproof_root: Hash256,
    light_vm: bool,
    pow_mode: PowValidationMode,
) -> Result<BlockHeader, DomError> {
    use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
    // Mainnet / Testnet mining sets `FLAG_FULL_MEM` for throughput
    // (allocates the ~2 GB RandomX dataset). Regtest opts out via
    // `light_vm = true` and uses the cache-only VM (~256 MB). Regtest still
    // performs real PoW against `REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION`
    // (~2^-16 acceptance), but that is a much better tradeoff than paying
    // multi-gigabyte dataset cost in dev/test environments.
    let fast_mode = matches!(pow_mode, PowValidationMode::FastDevOnly);
    let flags = if light_vm {
        RandomXFlag::get_recommended_flags()
    } else {
        RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM
    };
    let cache = if fast_mode {
        None
    } else {
        Some(
            RandomXCache::new(flags, &seed_hash)
                .map_err(|e| DomError::Internal(format!("cache: {e}")))?,
        )
    };
    let vm = if fast_mode {
        None
    } else if light_vm {
        // Cache-only VM. No dataset is allocated.
        Some(
            RandomXVM::new(flags, Some(cache.clone().expect("cache")), None)
                .map_err(|e| DomError::Internal(format!("vm: {e}")))?,
        )
    } else {
        let cache = cache.clone().expect("cache");
        let dataset = RandomXDataset::new(flags, cache.clone(), 0)
            .map_err(|e| DomError::Internal(format!("dataset: {e}")))?;
        Some(
            RandomXVM::new(flags, Some(cache), Some(dataset))
                .map_err(|e| DomError::Internal(format!("vm: {e}")))?,
        )
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
            timestamp: block_timestamp,
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
        let hash = if fast_mode {
            fast_pow_hash(&seed_hash, &preimage)
        } else {
            randomx_hash(vm.as_ref().expect("vm"), &preimage)?
        };
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

    use super::{build_genesis_coinbase, build_real_coinbase, finalize_mined_block, mine_blocking};
    use crate::node::DomNode;
    use dom_config::NodeConfig;
    use dom_consensus::block::validate_pow_for_network;
    use dom_consensus::block::{BlockHeader, ProofOfWork};
    use dom_consensus::compute_block_pmmr_roots;
    use dom_consensus::Block;
    use dom_core::{BlockHeight, Hash256, Timestamp, NETWORK_MAGIC_REGTEST, PROTOCOL_VERSION};
    use dom_pow::{
        compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target,
        target_to_compact, target_to_difficulty,
    };
    use dom_serialization::DomSerialize;
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

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

    fn fresh_test_dir(label: &str) -> PathBuf {
        let unique = format!(
            "dom-miner-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn regtest_config(data_dir: &std::path::Path) -> NodeConfig {
        let mut config = NodeConfig::regtest();
        config.data_dir = data_dir.to_string_lossy().into_owned();
        config.wallet_path = None;
        config.wallet_password = None;
        config.mine = false;
        config
    }

    #[allow(clippy::too_many_arguments)]
    fn mine_fast_test_header(
        seed_hash: [u8; 32],
        prev_hash: Hash256,
        height: BlockHeight,
        timestamp: Timestamp,
        output_root: Hash256,
        kernel_root: Hash256,
        rangeproof_root: Hash256,
        total_kernel_offset: [u8; 32],
        total_difficulty: U256,
    ) -> BlockHeader {
        let target =
            compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
        let mut nonce = 0u64;
        loop {
            let mut header = BlockHeader {
                version: PROTOCOL_VERSION,
                prev_hash,
                height,
                timestamp,
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset,
                target: dom_pow::CompactTarget(target_to_compact(&target)),
                total_difficulty,
                pow: ProofOfWork {
                    nonce,
                    randomx_hash: Hash256::ZERO,
                },
            };
            let hash = fast_pow_hash(&seed_hash, &header.pow_preimage());
            if hash_meets_target(&hash, &target) {
                header.pow.randomx_hash = Hash256::from_bytes(hash);
                return header;
            }
            nonce = nonce.wrapping_add(1);
        }
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
        let (a_or, a_kr, a_rr) = compute_block_pmmr_roots(&a, &[]).expect("compute genesis roots");

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

    #[test]
    fn regtest_mining_uses_light_vm_only_on_regtest() {
        assert!(super::use_light_vm(dom_config::Network::Regtest));
        assert!(!super::use_light_vm(dom_config::Network::Mainnet));
        assert!(!super::use_light_vm(dom_config::Network::Testnet));
    }

    #[test]
    fn regtest_fast_mining_returns_a_valid_header_without_searching() {
        use dom_core::NETWORK_MAGIC_REGTEST;

        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let target = dom_core::MAX_TARGET_BYTES;

        let header = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            Timestamp(1_700_000_000),
            target,
            primitive_types::U256::one(),
            [0u8; 32],
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            true,
            dom_pow::PowValidationMode::FastDevOnly,
        )
        .expect("fast mining");

        assert_eq!(header.pow.nonce, 0, "fast mining should not search nonces");
        assert!(validate_pow_for_network(NETWORK_MAGIC_REGTEST, &header, &[0u8; 32]).is_ok());
    }

    #[test]
    fn miner_validator_still_share_compute_expected_target() {
        use dom_core::NETWORK_MAGIC_MAINNET;

        let timestamp = Timestamp(1_778_642_753);
        let target =
            compute_expected_target(NETWORK_MAGIC_MAINNET, timestamp, BlockHeight(1)).unwrap();
        let total_difficulty = U256::from(target_to_difficulty(&target));
        let header = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            timestamp,
            target,
            total_difficulty,
            [0u8; 32],
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            true,
            dom_pow::PowValidationMode::FastDevOnly,
        )
        .expect("mine mainnet-style header");

        assert_eq!(header.timestamp, timestamp);
        assert_eq!(
            header.target.to_target().unwrap(),
            compute_expected_target(NETWORK_MAGIC_MAINNET, header.timestamp, header.height)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn invariant_mined_block_is_rejected_before_broadcast_when_economic_balance_is_invalid() {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let dir = fresh_test_dir("pre-broadcast-invalid-balance");
        let node = Arc::new(DomNode::init(regtest_config(&dir)).expect("node init"));
        super::create_genesis_block(node.clone())
            .await
            .expect("create genesis");

        let mut relay_rx = node.block_relay_tx.subscribe();
        let coinbase =
            build_real_coinbase(BlockHeight(1), 0, &chain_id_regtest()).expect("coinbase");
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, &[]).expect("roots");
        let mut invalid_offset = [0u8; 32];
        invalid_offset[31] = 1;
        let (tip_hash, tip_difficulty) = {
            let chain = node.chain.lock().await;
            (chain.tip_hash, chain.tip_difficulty)
        };
        let timestamp = genesis_anchor(NETWORK_MAGIC_REGTEST)
            .expect("anchor")
            .timestamp
            .checked_add_secs(dom_core::TARGET_SPACING)
            .expect("timestamp");
        let target = compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, BlockHeight(1))
            .expect("target");
        let header = mine_fast_test_header(
            *tip_hash.as_bytes(),
            tip_hash,
            BlockHeight(1),
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            invalid_offset,
            tip_difficulty + U256::from(target_to_difficulty(&target)),
        );
        let block = Block {
            header,
            coinbase,
            transactions: vec![],
        };

        let err = finalize_mined_block(&node, block)
            .await
            .expect_err("economically invalid mined block must never reach relay");
        let msg = err.to_string();
        assert!(
            msg.contains("aggregate") || msg.contains("balance"),
            "expected economic-balance rejection, got: {msg}"
        );
        assert!(
            relay_rx.try_recv().is_err(),
            "invalid mined block must not be broadcast before local validation"
        );

        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }
}

#[cfg(test)]
mod cadence_probe_tests {
    use super::*;
    use dom_pow::{MAX_COMPACT_TARGET, TESTNET_TARGET_COMPACT};
    use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
    use std::io::Write;
    use std::time::Instant;

    #[test]
    #[ignore = "manual local cadence probe"]
    fn manual_testnet_cadence_probe() {
        let seed_hash = [0u8; 32];
        let flags = RandomXFlag::get_recommended_flags();
        let cache = RandomXCache::new(flags, &seed_hash).expect("cache");
        let vm = RandomXVM::new(flags, Some(cache), None).expect("vm");

        let mine_one = |compact: u32| -> (f64, u64) {
            let target = CompactTarget(compact).to_target().expect("target");
            let started = Instant::now();
            let mut nonce = 0u64;
            loop {
                let header = BlockHeader {
                    version: dom_core::PROTOCOL_VERSION,
                    prev_hash: Hash256::ZERO,
                    height: BlockHeight(1),
                    timestamp: Timestamp(now_secs()),
                    output_root: Hash256::ZERO,
                    kernel_root: Hash256::ZERO,
                    rangeproof_root: Hash256::ZERO,
                    total_kernel_offset: [0u8; 32],
                    target: CompactTarget(compact),
                    total_difficulty: U256::one(),
                    pow: ProofOfWork {
                        nonce,
                        randomx_hash: Hash256::ZERO,
                    },
                };
                let hash = randomx_hash(&vm, &header.pow_preimage()).expect("hash");
                if hash_meets_target(&hash, &target) {
                    return (started.elapsed().as_secs_f64(), nonce);
                }
                nonce = nonce.wrapping_add(1);
            }
        };

        for (label, compact) in [
            ("before", MAX_COMPACT_TARGET),
            ("after", TESTNET_TARGET_COMPACT),
        ] {
            let (elapsed, nonce) = mine_one(compact);
            println!(
                "{} compact=0x{:08x} elapsed_secs={:.3} nonce={}",
                label, compact, elapsed, nonce
            );
            std::io::stdout().flush().expect("flush");
        }
    }
}

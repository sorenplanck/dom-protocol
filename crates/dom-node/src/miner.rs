//! Minerador DOM — loop de mineração com RandomX.

use crate::node::{reconcile_mempool_after_connect, DomNode};
use crate::task_supervisor::ShutdownToken;
use dom_config::MinerThrottleConfig;
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

struct MiningActiveGuard {
    metrics: Arc<crate::metrics::Metrics>,
}

impl MiningActiveGuard {
    fn new(metrics: Arc<crate::metrics::Metrics>) -> Self {
        metrics
            .mining_active
            .store(1, std::sync::atomic::Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for MiningActiveGuard {
    fn drop(&mut self) {
        self.metrics
            .mining_active
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MiningMode {
    MainnetLikeRandomX,
    TestnetConfiguredRandomX,
    RegtestRandomXLight,
    RegtestFastDevOnly,
}

impl MiningMode {
    fn from_network_and_pow_mode(
        network: dom_config::Network,
        pow_mode: PowValidationMode,
    ) -> Result<Self, DomError> {
        match (network, pow_mode) {
            (dom_config::Network::Mainnet, PowValidationMode::RandomX) => {
                Ok(Self::MainnetLikeRandomX)
            }
            (dom_config::Network::Testnet, PowValidationMode::RandomX) => {
                Ok(Self::TestnetConfiguredRandomX)
            }
            (dom_config::Network::Regtest, PowValidationMode::RandomX) => {
                Ok(Self::RegtestRandomXLight)
            }
            (dom_config::Network::Regtest, PowValidationMode::FastDevOnly) => {
                Ok(Self::RegtestFastDevOnly)
            }
            (network, PowValidationMode::FastDevOnly) => Err(DomError::Invalid(format!(
                "FastDevOnly mining mode is only allowed on regtest, got {network:?}"
            ))),
        }
    }

    fn for_network(network: dom_config::Network) -> Result<Self, DomError> {
        Self::from_network_and_pow_mode(network, pow_validation_mode_for_network(network.magic())?)
    }

    fn pow_mode(self) -> PowValidationMode {
        match self {
            Self::MainnetLikeRandomX
            | Self::TestnetConfiguredRandomX
            | Self::RegtestRandomXLight => PowValidationMode::RandomX,
            Self::RegtestFastDevOnly => PowValidationMode::FastDevOnly,
        }
    }

    fn light_vm(self) -> bool {
        matches!(self, Self::RegtestRandomXLight | Self::RegtestFastDevOnly)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MinerThrottle {
    enabled: bool,
    yield_every_nonces: u64,
    sleep_micros: u64,
}

impl MinerThrottle {
    fn from_config(config: &MinerThrottleConfig) -> Self {
        Self {
            enabled: config.enabled && config.yield_every_nonces > 0,
            yield_every_nonces: config.yield_every_nonces,
            sleep_micros: config.sleep_micros,
        }
    }

    fn after_nonce(self, nonce: u64) {
        if !self.enabled || !nonce.is_multiple_of(self.yield_every_nonces) {
            return;
        }
        if self.sleep_micros == 0 {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_micros(self.sleep_micros));
        }
    }

    fn describe(self) -> String {
        if !self.enabled {
            return "disabled".into();
        }
        if self.sleep_micros == 0 {
            format!("yield every {} nonces", self.yield_every_nonces)
        } else {
            format!(
                "sleep {}us every {} nonces",
                self.sleep_micros, self.yield_every_nonces
            )
        }
    }
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

/// Build a byte-reproducible coinbase at an arbitrary height.
///
/// **TEST-INFRASTRUCTURE API. Not part of the stable public surface.**
///
/// Exposed as `pub` so the deterministic-replay regression test (in the
/// `dom-integration-tests` crate, which compiles `dom-node` as a normal
/// dependency and so cannot reach a `#[cfg(test)]` item) can build byte-identical
/// chains past genesis and pin a frozen canonical-state digest. Never call this
/// from production code: real blocks are mined via `mine_one_block`, whose
/// coinbase comes from the wallet or from [`build_real_coinbase`] (a fresh random
/// blinding per block).
///
/// This is a thin deterministic wrapper, not a new coinbase path: it only
/// derives a deterministic `(blinding, nonce)` pair — from `TAG_GENESIS_BLINDING`
/// keyed by height, exactly as [`build_genesis_coinbase`] derives the genesis
/// pair — and hands them to the same `build_coinbase_with_blinding` constructor
/// the genesis and normal paths use. It adds no coinbase-construction logic,
/// changes no consensus rule, and every block it produces is fully
/// consensus-valid (and rejected by `connect_block` if it were not).
///
/// Marked `#[doc(hidden)]` to keep this out of generated rustdoc despite needing
/// `pub` visibility.
#[doc(hidden)]
pub fn build_deterministic_coinbase(
    height: BlockHeight,
    total_tx_fees: u64,
    chain_id: &[u8; 32],
) -> Result<CoinbaseTransaction, DomError> {
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::pedersen::BlindingFactor;

    let mut blind_seed = b"dom:replay-coinbase:blinding:".to_vec();
    blind_seed.extend_from_slice(&height.0.to_le_bytes());
    let blinding_hash = blake2b_256_tagged(dom_core::TAG_GENESIS_BLINDING, &blind_seed);
    let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes())
        .map_err(|e| DomError::Internal(format!("deterministic coinbase blinding: {e}")))?;

    let mut nonce_seed = b"dom:replay-coinbase:bp-nonce:".to_vec();
    nonce_seed.extend_from_slice(&height.0.to_le_bytes());
    let nonce = *blake2b_256_tagged(dom_core::TAG_GENESIS_BLINDING, &nonce_seed).as_bytes();

    build_coinbase_with_blinding(height, total_tx_fees, chain_id, Some(blinding), Some(nonce))
}

fn build_coinbase_with_blinding(
    height: BlockHeight,
    total_tx_fees: u64,
    chain_id: &[u8; 32],
    blinding_override: Option<dom_crypto::pedersen::BlindingFactor>,
    bulletproof_nonce: Option<[u8; 32]>,
) -> Result<CoinbaseTransaction, DomError> {
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

    // Range proof: proves value in [0, 2^52). Yields the proof bytes (Vec<u8>).
    // Both paths now produce a 739-byte bounded aggregate Bulletproof (bp2):
    //   - GENESIS uses a DETERMINISTIC nonce (`Some(nonce)`) so the genesis block
    //     is byte-reproducible across nodes (bp2_prove_with_nonce).
    //   - normal blocks use fresh random nonces (bp2_prove).
    let range_proof_bytes: Vec<u8> = match bulletproof_nonce {
        Some(nonce) => {
            dom_crypto::bp2_prove_with_nonce(explicit_value, &blinding, &nonce)
                .map_err(|e| DomError::Internal(format!("coinbase range proof failed: {e}")))?
                .0
        }
        None => {
            dom_crypto::bp2_prove(explicit_value, &blinding)
                .map_err(|e| DomError::Internal(format!("coinbase range proof failed: {e}")))?
                .0
        }
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
            proof: range_proof_bytes,
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

pub async fn mining_loop(node: Arc<DomNode>, shutdown: ShutdownToken) -> Result<(), DomError> {
    info!("Minerador iniciado");
    let _mining_active = MiningActiveGuard::new(node.metrics.clone());
    {
        if shutdown.is_shutdown() {
            return Ok(());
        }
        let chain = node.chain.lock().await;
        if chain.tip_height.0 == 0 && chain.tip_hash == dom_core::Hash256::ZERO {
            drop(chain);
            if let Err(e) = create_genesis_block(node.clone()).await {
                warn!("Genesis falhou: {e}");
                return Err(e);
            }
        }
    }
    loop {
        if shutdown.is_shutdown() {
            return Ok(());
        }
        match mine_one_block(node.clone()).await {
            Ok(h) => info!("✅ Bloco {} minerado!", h),
            Err(e) => {
                warn!("Mineracao falhou: {e}");
                tokio::select! {
                    _ = shutdown.wait() => return Ok(()),
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {}
                }
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
    match &connect_outcome {
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
                let mut wallet_dir = wallet_arc.lock().await;
                wallet_dir.wallet_mut().forget_output(&coinbase_commitment);
            }
        }
        dom_chain::ConnectResult::AlreadyHave => {
            tracing::debug!(
                "Miner block at height {} was AlreadyHave (unusual but benign)",
                new_height
            );
            if let Some(ref wallet_arc) = node.wallet {
                let mut wallet_dir = wallet_arc.lock().await;
                wallet_dir.wallet_mut().forget_output(&coinbase_commitment);
            }
            // Don't relay — peers already have it (somehow).
            return Ok(new_height);
        }
    }
    node.metrics
        .blocks_mined
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    reconcile_mempool_after_connect(
        &node.chain,
        &node.mempool,
        &connect_outcome,
        &block.transactions,
    )
    .await
    .map_err(|e| DomError::Internal(format!("mempool reconciliation: {e}")))?;
    DomNode::refresh_runtime_metrics(
        &node.chain,
        &node.mempool,
        &node.future_block_queue,
        &node.metrics,
    )
    .await;

    // Scan block for wallet outputs (coinbase reward recovery).
    if matches!(
        &connect_outcome,
        dom_chain::ConnectResult::BestChain | dom_chain::ConnectResult::Reorg(_)
    ) {
        if let Some(ref wallet_arc) = node.wallet {
            let mut wallet_dir = wallet_arc.lock().await;
            apply_wallet_after_mined_connect(
                wallet_dir.wallet_mut(),
                &connect_outcome,
                &block.transactions,
                new_height,
            )?;
        }
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
    node.notify_state_changed();

    Ok(new_height)
}

fn apply_wallet_after_mined_connect(
    wallet: &mut dom_wallet::Wallet,
    connect_outcome: &dom_chain::ConnectResult,
    block_transactions: &[Transaction],
    new_height: u64,
) -> Result<(), DomError> {
    match connect_outcome {
        dom_chain::ConnectResult::BestChain => wallet
            .apply_canonical_block(block_transactions, new_height)
            .map_err(|e| DomError::Internal(format!("wallet canonical block apply: {e}"))),
        dom_chain::ConnectResult::Reorg(delta) => {
            wallet
                .rollback_to(delta.common_ancestor_height)
                .map_err(|e| DomError::Internal(format!("wallet mined reorg rollback: {e}")))?;
            for block in &delta.connected_blocks {
                wallet
                    .apply_canonical_block_with_hash(
                        &block.transactions,
                        block.block_height,
                        Some(block.block_hash),
                    )
                    .map_err(|e| {
                        DomError::Internal(format!("wallet mined reorg block apply: {e}"))
                    })?;
            }
            Ok(())
        }
        dom_chain::ConnectResult::SideChain | dom_chain::ConnectResult::AlreadyHave => Ok(()),
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
    // DOM-AUDIT-001: persist the genesis coinbase into the UTXO/kernel index
    // here, identically to what the reopen path reconstructs. The genesis
    // coinbase is spendable by design, so a create that leaves these empty
    // diverges from a reopened node (which rebuilds them) → chain-split risk.
    // Reuse the canonical changeset builder so create == reopen by construction.
    let (new_utxos, spent_utxos, kernel_excesses) =
        dom_chain::genesis_canonical_changeset(&genesis_block, Hash256::from_bytes(genesis_hash));
    chain.store.commit_block(
        &genesis_hash,
        0,
        &header_bytes,
        &genesis_body,
        &new_utxos,
        &spent_utxos,
        &kernel_excesses,
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

/// Aggregate the kernel offsets of a block's transactions into the
/// header's `total_kernel_offset`.
///
/// The block-level balance equation (`verify_block_balance_equation`)
/// expects `total_kernel_offset` to be the sum of every transaction's
/// `offset` as a secp256k1 scalar mod n. The coinbase contributes no
/// offset (its excess is `r·G` only), so it is excluded.
///
/// This MUST use the same scalar arithmetic the consensus validator
/// uses — it mirrors the reference `aggregate_tx_offsets` exactly:
/// start at `Scalar::ZERO`, add each canonical `tx.offset`, skip any
/// non-canonical bytes. The result is a `Scalar` reduced mod n, so it
/// is always `< n` and satisfies `validate_kernel_offset_canonical` by
/// construction. An empty tx set (coinbase-only block) yields `[0u8; 32]`.
fn aggregate_block_kernel_offset(transactions: &[Transaction]) -> [u8; 32] {
    use k256::{elliptic_curve::PrimeField, Scalar};
    let mut total = Scalar::ZERO;
    for tx in transactions {
        let fb = k256::FieldBytes::from(tx.offset);
        let s_ct = Scalar::from_repr(fb);
        if s_ct.is_some().into() {
            total += s_ct.unwrap();
        }
    }
    total.to_repr().into()
}

pub async fn mine_one_block(node: Arc<DomNode>) -> Result<u64, DomError> {
    let (tip_hash, tip_height, tip_difficulty, parent_ts) = {
        use dom_serialization::DomDeserialize;
        let chain = node.chain.lock().await;
        // Parent timestamp for the strict-progression invariant: consensus
        // (validate_parent_timestamp_progression in dom-consensus/src/block.rs)
        // requires child.timestamp > parent.timestamp STRICTLY, on every
        // network. now_secs() has second resolution, so two blocks mined within
        // the same wall-clock second would receive equal timestamps and the
        // second would be rejected by connect_block. Read the parent timestamp
        // here so the mined block can be forced strictly past it (see
        // block_timestamp below).
        //
        // Genesis / empty chain edge case: when the tip is the genesis sentinel
        // (height 0 && Hash256::ZERO) or the parent header is absent from the
        // store, there is no real parent — fall back to 0 and preserve the
        // existing now_secs() behaviour for the first block.
        let parent_ts = if chain.tip_height.0 == 0 && chain.tip_hash == Hash256::ZERO {
            0
        } else {
            chain
                .store
                .get_block_header(chain.tip_hash.as_bytes())
                .ok()
                .flatten()
                .and_then(|bytes| BlockHeader::from_bytes(&bytes).ok())
                .map(|header| header.timestamp.0)
                .unwrap_or(0)
        };
        (
            chain.tip_hash,
            chain.tip_height,
            chain.tip_difficulty,
            parent_ts,
        )
    };

    let new_height = tip_height.0 + 1;
    // Force the timestamp strictly past the parent's so the consensus
    // invariant child.timestamp > parent.timestamp always holds, even when
    // several blocks are mined within the same wall-clock second (regtest fast
    // mining). For genesis / empty chain parent_ts == 0, so this collapses back
    // to now_secs(). Computed BEFORE compute_expected_target so the target is
    // derived from the exact timestamp that ends up in the block — every later
    // use (mine_blocking, the BlockHeader below) reuses this one value rather
    // than re-reading now_secs().
    let block_timestamp = Timestamp(now_secs().max(parent_ts + 1));
    let target = compute_expected_target(
        node.config.network.magic(),
        block_timestamp,
        BlockHeight(new_height),
    )?;
    let block_diff = target_to_difficulty(&target);
    let new_total_diff = tip_difficulty.saturating_add(U256::from(block_diff));
    let mining_mode = MiningMode::for_network(node.config.network)?;
    let throttle = MinerThrottle::from_config(&node.config.miner_throttle);

    info!(
        "Minerando bloco {} | target: {}... | mode: {:?} | throttle: {}",
        new_height,
        hex::encode(&target[0..4]),
        mining_mode,
        throttle.describe()
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
        let mut wallet_dir = wallet_arc.lock().await;
        wallet_dir
            .wallet_mut()
            .build_coinbase(BlockHeight(new_height), total_tx_fees)
            .map_err(|e| DomError::Internal(format!("wallet coinbase: {e}")))?
    } else if node.config.network == dom_config::Network::Regtest {
        // Regtest only: dev/test mining without a wallet. The blinding is
        // discarded so the reward is NOT spendable — acceptable for the
        // ephemeral, throwaway chains regtest is used for (DOM-SEC-004).
        warn!(
            "Regtest mining without wallet — rewards will NOT be spendable (dev only, DOM-SEC-004)"
        );
        build_real_coinbase(
            BlockHeight(new_height),
            total_tx_fees,
            &chain_id_for(&node.config)?,
        )?
    } else {
        // Public networks (testnet/mainnet): fail closed before mining. Mining
        // here without a wallet would burn the reward into a permanently
        // unspendable coinbase (the blinding factor is discarded), so refuse
        // rather than silently destroy an honest operator's rewards.
        return Err(DomError::Invalid(
            "mining on a public network (testnet/mainnet) requires a configured wallet; \
             refusing to mine and burn unspendable coinbase rewards (DOM-SEC-004)"
                .into(),
        ));
    };

    // PMMR roots over coinbase + selected mempool txs. Single source
    // of truth: `compute_block_pmmr_roots` is the same helper that
    // `validate_pmmr_roots` runs during block acceptance, so the miner
    // cannot drift on iteration order.
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &selected_txs)?;

    // Aggregate kernel offset over the included transactions (coinbase
    // contributes none). The consensus balance equation requires the
    // header's total_kernel_offset to equal this sum; a coinbase-only
    // block yields [0u8; 32], preserving prior behaviour.
    let total_kernel_offset = aggregate_block_kernel_offset(&selected_txs);

    // Production-like networks mine with FLAG_FULL_MEM (~2 GB dataset +
    // ~256 MB cache per active miner thread) for ~10× hash-rate vs the
    // cache-only VM.
    // RandomX hash output is identical between modes — only the prover
    // speed differs — so consensus validation does not care which mode
    // the miner used. Validators (dom-pow::randomx_pool) intentionally
    // stay on the cache-only path: validation is occasional and shouldn't
    // pay the dataset cost.
    //
    // Memory budget: ~2.3 GB per active miner thread in full-mem mode.
    // Regtest uses either cache-only RandomX or explicit FastDevOnly hashing.
    // Both paths still mine against `compute_expected_target`; the fast mode
    // changes only the hash function and is rejected for production-like
    // networks before mining starts.
    let light_vm = mining_mode.light_vm();
    let pow_mode = mining_mode.pow_mode();
    let threads = node.config.miner_threads.max(1);
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<(BlockHeader, MiningStats), String>>();
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
                total_kernel_offset,
                light_vm,
                pow_mode,
                threads,
                throttle,
            );
            let _ = tx.send(result.map_err(|e| e.to_string()));
        })
        .map_err(|e| DomError::Internal(format!("spawn thread: {e}")))?;
    let (header, stats) = rx
        .await
        .map_err(|e| DomError::Internal(format!("channel: {e}")))?
        .map_err(DomError::Internal)?;
    tracing::debug!(
        "Bloco {new_height}: nonce encontrado com {} worker(s)",
        stats.workers
    );
    let block = Block {
        header,
        coinbase,
        transactions: selected_txs,
    };
    finalize_mined_block(&node, block).await
}

/// Outcome statistics of a mining run — for operator logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MiningStats {
    /// Nonce-search workers actually spawned. The deterministic FastDevOnly
    /// path searches nothing and always reports 1.
    workers: usize,
}

/// RandomX cache/dataset handles that may cross thread boundaries.
///
/// `randomx-rs` wraps the C pointers in `Arc` but the raw pointers strip the
/// `Send` auto-trait. The RandomX C API documents `randomx_cache` and
/// `randomx_dataset` as immutable after initialization and safe for
/// concurrent use by any number of VMs on any threads (one VM per thread);
/// release happens exactly once via the inner `Arc`'s last drop, and
/// `randomx_release_*` has no thread affinity. We therefore assert `Send` to
/// move CLONES of the fully-initialized handles into worker threads. `Sync`
/// is deliberately NOT asserted — each worker receives an owned clone, never
/// a shared reference.
#[allow(unsafe_code)]
mod shared_rx {
    pub(super) struct SharedCache(pub(super) randomx_rs::RandomXCache);
    // SAFETY: see module docs — immutable after init, Arc-managed single release.
    unsafe impl Send for SharedCache {}

    pub(super) struct SharedDataset(pub(super) randomx_rs::RandomXDataset);
    // SAFETY: see module docs.
    unsafe impl Send for SharedDataset {}
}

/// Immutable inputs of one worker's strided nonce search.
struct NonceSearch {
    /// Header with everything but the nonce/randomx_hash filled in.
    template: BlockHeader,
    target: [u8; 32],
    seed_hash: [u8; 32],
    /// `true` = deterministic dev hashing (no RandomX VM).
    fast_mode: bool,
    worker_id: usize,
    /// Total worker count; also the nonce stride.
    workers: usize,
    throttle: MinerThrottle,
}

/// Build the per-worker RandomX VM (None in fast mode). Light mode links the
/// shared cache only; full-mem mode links the shared cache AND dataset, so N
/// workers cost one ~2 GB dataset total, not N of them.
fn build_worker_vm(
    light_vm: bool,
    flags: randomx_rs::RandomXFlag,
    cache: Option<shared_rx::SharedCache>,
    dataset: Option<shared_rx::SharedDataset>,
) -> Result<Option<randomx_rs::RandomXVM>, DomError> {
    use randomx_rs::RandomXVM;
    let Some(shared_rx::SharedCache(cache)) = cache else {
        return Ok(None); // fast mode: no VM
    };
    let vm = if light_vm {
        // Cache-only VM. No dataset is allocated.
        RandomXVM::new(flags, Some(cache), None)
    } else {
        let shared_rx::SharedDataset(dataset) =
            dataset.ok_or_else(|| DomError::Internal("dataset missing for full-mem vm".into()))?;
        RandomXVM::new(flags, Some(cache), Some(dataset))
    }
    .map_err(|e| DomError::Internal(format!("vm: {e}")))?;
    Ok(Some(vm))
}

/// One worker's nonce search: starts at `worker_id` and strides by `workers`
/// so the workers partition the nonce space without coordination. Returns
/// `Ok(None)` when another worker won (stop flag set).
fn search_nonces(
    params: NonceSearch,
    vm: Option<&randomx_rs::RandomXVM>,
    stop: &std::sync::atomic::AtomicBool,
    total_hashes: &std::sync::atomic::AtomicU64,
) -> Result<Option<BlockHeader>, DomError> {
    use std::sync::atomic::Ordering;

    // Heartbeat: blocks can take minutes to hours under low-effort targets +
    // light VM. Without a periodic log, "stuck" miners are indistinguishable
    // from "still hashing" — worker 0 logs every HEARTBEAT_NONCES of its own
    // iterations with the aggregate hash-rate so operators (and tests) see
    // continuous progress.
    const HEARTBEAT_NONCES: u64 = 5_000;
    let mining_start = std::time::Instant::now();
    let mut last_heartbeat = mining_start;
    let mut last_total = 0u64;

    let mut header = params.template.clone();
    let new_height = header.height.0;
    let mut nonce = params.worker_id as u64;
    let stride = params.workers as u64;
    let mut iterations = 0u64;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        header.pow.nonce = nonce;
        let preimage = header.pow_preimage();
        let hash = if params.fast_mode {
            fast_pow_hash(&params.seed_hash, &preimage)
        } else {
            randomx_hash(vm.expect("vm"), &preimage)?
        };
        total_hashes.fetch_add(1, Ordering::Relaxed);
        if hash_meets_target(&hash, &params.target) {
            header.pow.randomx_hash = Hash256::from_bytes(hash);
            return Ok(Some(header));
        }
        nonce = nonce.wrapping_add(stride);
        iterations = iterations.wrapping_add(1);
        // Throttle on the worker-local iteration count, not the global nonce:
        // strided nonces of worker i>0 may never be multiples of the
        // configured yield interval.
        params.throttle.after_nonce(iterations);
        if params.worker_id == 0 && iterations.is_multiple_of(HEARTBEAT_NONCES) {
            let now = std::time::Instant::now();
            let window = now.duration_since(last_heartbeat).as_secs_f64();
            let total = total_hashes.load(Ordering::Relaxed);
            let hps = if window > 0.0 {
                total.saturating_sub(last_total) as f64 / window
            } else {
                0.0
            };
            info!(
                "⛏ minerando h={} | nonces={} | {:.1} H/s | workers={} | total={:.1}s | throttle={}",
                new_height,
                total,
                hps,
                params.workers,
                mining_start.elapsed().as_secs_f64(),
                params.throttle.describe()
            );
            last_heartbeat = now;
            last_total = total;
        }
    }
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
    total_kernel_offset: [u8; 32],
    light_vm: bool,
    pow_mode: PowValidationMode,
    threads: usize,
    throttle: MinerThrottle,
) -> Result<(BlockHeader, MiningStats), DomError> {
    use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    // Mainnet / Testnet mining sets `FLAG_FULL_MEM` for throughput
    // (allocates the ~2 GB RandomX dataset, shared by all workers). Regtest
    // opts out via `light_vm = true` and uses cache-only VMs (~256 MB shared).
    // Regtest still performs real PoW against `REGTEST_TARGET_COMPACT` unless
    // explicit FastDevOnly hashing is enabled for tests. All paths check the
    // same consensus target supplied by `compute_expected_target`.
    let fast_mode = matches!(pow_mode, PowValidationMode::FastDevOnly);
    // FastDevOnly finds its nonce deterministically without searching, so
    // extra workers add nothing and would only make the winning nonce racy
    // for tests — force the single inline worker.
    let workers = if fast_mode { 1 } else { threads.max(1) };
    info!(
        "Starting miner h={new_height}: configured_threads={threads} workers={workers} throttle={}",
        throttle.describe()
    );
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
    let dataset = if fast_mode || light_vm {
        None
    } else {
        Some(
            RandomXDataset::new(flags, cache.clone().expect("cache"), 0)
                .map_err(|e| DomError::Internal(format!("dataset: {e}")))?,
        )
    };
    let template = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        prev_hash: tip_hash,
        height: BlockHeight(new_height),
        timestamp: block_timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
        total_kernel_offset,
        target: CompactTarget(target_to_compact(&target)),
        total_difficulty: new_total_diff,
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };

    if workers == 1 {
        // Single worker: search inline on this thread, exactly the historical
        // behavior — no extra spawn, no cross-thread RandomX handles.
        let stop = AtomicBool::new(false);
        let total_hashes = AtomicU64::new(0);
        let vm = build_worker_vm(
            light_vm,
            flags,
            cache.map(shared_rx::SharedCache),
            dataset.map(shared_rx::SharedDataset),
        )?;
        let header = search_nonces(
            NonceSearch {
                template,
                target,
                seed_hash,
                fast_mode,
                worker_id: 0,
                workers: 1,
                throttle,
            },
            vm.as_ref(),
            &stop,
            &total_hashes,
        )?
        .ok_or_else(|| DomError::Internal("nonce search stopped without a result".into()))?;
        return Ok((header, MiningStats { workers: 1 }));
    }

    // Multi-worker: N strided searchers over one shared cache/dataset, first
    // valid header wins and stops the rest.
    let stop = Arc::new(AtomicBool::new(false));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let (result_tx, result_rx) = std::sync::mpsc::channel::<Result<BlockHeader, DomError>>();
    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        let cache_w = cache.clone().map(shared_rx::SharedCache);
        let dataset_w = dataset.clone().map(shared_rx::SharedDataset);
        let stop_w = Arc::clone(&stop);
        let hashes_w = Arc::clone(&total_hashes);
        let tx_w = result_tx.clone();
        let params = NonceSearch {
            template: template.clone(),
            target,
            seed_hash,
            fast_mode,
            worker_id,
            workers,
            throttle,
        };
        let spawned = std::thread::Builder::new()
            .name(format!("miner-{new_height}-w{worker_id}"))
            .spawn(move || {
                info!("⛏ h={new_height} worker #{worker_id}/{workers} iniciado");
                let outcome = build_worker_vm(light_vm, flags, cache_w, dataset_w)
                    .and_then(|vm| search_nonces(params, vm.as_ref(), &stop_w, &hashes_w));
                match outcome {
                    Ok(Some(header)) => {
                        stop_w.store(true, Ordering::Relaxed);
                        let _ = tx_w.send(Ok(header));
                    }
                    Ok(None) => {} // another worker won
                    Err(e) => {
                        let _ = tx_w.send(Err(e));
                    }
                }
            });
        match spawned {
            Ok(handle) => handles.push(handle),
            Err(e) => {
                // Don't leak already-running workers on spawn failure.
                stop.store(true, Ordering::Relaxed);
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(DomError::Internal(format!(
                    "spawn miner worker {worker_id}: {e}"
                )));
            }
        }
    }
    // Drop our sender so recv() unblocks with an error if every worker exits
    // without producing a result (e.g. all VMs failed to build).
    drop(result_tx);

    let mut winner: Option<BlockHeader> = None;
    let mut last_err: Option<DomError> = None;
    while let Ok(msg) = result_rx.recv() {
        match msg {
            Ok(header) => {
                winner = Some(header);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.join();
    }
    match winner {
        Some(header) => Ok((header, MiningStats { workers })),
        None => Err(last_err.unwrap_or_else(|| {
            DomError::Internal("all miner workers exited without a result".into())
        })),
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
mod kernel_offset_tests {
    //! Block-level kernel-offset aggregation (DOM block-assembly).
    //!
    //! `aggregate_block_kernel_offset` must reproduce the consensus
    //! validator's scalar arithmetic exactly: sum of each tx offset as a
    //! secp256k1 scalar mod n, coinbase excluded.

    use super::aggregate_block_kernel_offset;
    use dom_consensus::Transaction;

    /// A bare transaction carrying only an offset — the aggregator reads
    /// nothing else.
    fn tx_with_offset(offset: [u8; 32]) -> Transaction {
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: Vec::new(),
            offset,
        }
    }

    /// A big-endian 32-byte scalar repr of a small integer `v`.
    fn scalar_repr(v: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = v;
        b
    }

    #[test]
    fn empty_block_offset_is_zero() {
        assert_eq!(aggregate_block_kernel_offset(&[]), [0u8; 32]);
    }

    #[test]
    fn sum_of_two_known_offsets_matches_expected() {
        // scalar(2) + scalar(3) == scalar(5), in big-endian repr.
        let txs = vec![
            tx_with_offset(scalar_repr(2)),
            tx_with_offset(scalar_repr(3)),
        ];
        assert_eq!(aggregate_block_kernel_offset(&txs), scalar_repr(5));
    }
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

    use super::{
        apply_wallet_after_mined_connect, build_genesis_coinbase, build_real_coinbase,
        finalize_mined_block, mine_blocking, MinerThrottle,
    };
    use crate::node::DomNode;
    use dom_chain::{ConnectResult, ReorgBlockDelta, ReorgDelta};
    use dom_config::{MinerThrottleConfig, NodeConfig};
    use dom_consensus::block::validate_pow_for_network;
    use dom_consensus::block::{BlockHeader, ProofOfWork};
    use dom_consensus::compute_block_pmmr_roots;
    use dom_consensus::{Block, Transaction};
    use dom_core::{
        BlockHeight, Hash256, Timestamp, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST,
        NETWORK_MAGIC_TESTNET, PROTOCOL_VERSION,
    };
    use dom_crypto::pedersen::Commitment;
    use dom_crypto::BlindingFactor;
    use dom_pow::{
        compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target,
        target_to_compact, target_to_difficulty, PowValidationMode, REGTEST_TARGET_COMPACT,
    };
    use dom_serialization::DomSerialize;
    use dom_wallet::{Network, OwnedOutput, WalletDir};
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

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

    fn init_test_node(config: NodeConfig) -> DomNode {
        // Windows CI reserves LMDB map size more strictly than Linux/macOS.
        // These miner fixtures are tiny, so tests use a small explicit map
        // size while production `DomNode::init` keeps the 16 GiB default.
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE).expect("node init")
    }

    fn disabled_throttle() -> MinerThrottle {
        MinerThrottle::from_config(&MinerThrottleConfig::default())
    }

    #[test]
    fn mined_reorg_wallet_apply_rolls_back_and_applies_connected_blocks() {
        let dir = fresh_test_dir("wallet-mined-reorg-apply");
        let mut wd = WalletDir::create(
            &dir,
            "pw",
            Network::Regtest,
            &Hash256::from_bytes([0x42; 32]),
        )
        .expect("wallet dir");

        let stale_blinding = BlindingFactor::random();
        let stale_commitment = Commitment::commit(123, &stale_blinding);
        let stale_commitment_bytes = *stale_commitment.as_bytes();
        wd.wallet_mut().add_output(
            OwnedOutput::new(
                stale_commitment_bytes,
                123,
                *stale_blinding.as_bytes(),
                3,
                true,
            )
            .with_block_hash([0xA3; 32]),
        );

        let coinbase = wd
            .wallet_mut()
            .build_coinbase(BlockHeight(2), 0)
            .expect("coinbase");
        let canonical_commitment = *coinbase.output.commitment.as_bytes();
        assert!(wd.wallet_mut().forget_output(&canonical_commitment));

        let connected_tx = Transaction {
            inputs: vec![],
            outputs: vec![coinbase.output],
            kernels: vec![],
            offset: [0u8; 32],
        };
        let canonical_hash = [0xB2; 32];
        let delta = ReorgDelta {
            common_ancestor_height: 1,
            connected_blocks: vec![ReorgBlockDelta {
                block_hash: canonical_hash,
                block_height: 2,
                transactions: vec![connected_tx],
            }],
            ..Default::default()
        };

        apply_wallet_after_mined_connect(wd.wallet_mut(), &ConnectResult::Reorg(delta), &[], 2)
            .expect("wallet mined reorg apply");

        assert!(
            wd.wallet()
                .outputs()
                .all(|output| output.commitment != stale_commitment_bytes),
            "rollback must remove outputs above the common ancestor"
        );
        let recovered = wd
            .wallet()
            .outputs()
            .find(|output| output.commitment == canonical_commitment)
            .expect("connected reorg block must be applied to wallet");
        assert_eq!(recovered.block_height, 2);
        assert_eq!(recovered.block_hash, Some(canonical_hash));

        crate::test_dir::remove_test_dir(&dir);
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
    /// FROZEN GENESIS VECTORS (testnet, Bulletproof era). Regenerates the genesis
    /// end-to-end from the deterministic builder and pins every derived value, so
    /// any future drift (proof, derivation, roots, or header hash) is caught.
    ///
    /// The genesis coinbase now carries a 739-byte bounded aggregate Bulletproof
    /// (`bp2_prove_with_nonce`), so `rangeproof_root` and the genesis hash changed
    /// from the borromean era; `output_root`/`kernel_root` are unchanged (the
    /// Pedersen commitment and kernel excess are independent of the range-proof
    /// backend). Recomputed after the bounded aggregate bp2 migration.
    #[test]
    fn genesis_testnet_frozen_vectors() {
        // Pinned values (hex), authoritative from the deterministic builder.
        const OUTPUT_ROOT: &str =
            "7dcd67abf72846eadd94cee37060ecd58ac26df2a6c1f6e74a43fe9e6aab9f1d";
        const KERNEL_ROOT: &str =
            "69a1283a2fd4a90f0df6110caf2f74150365e31ca96cc2485cb022ceae15834b";
        const RANGEPROOF_ROOT: &str =
            "ac00fb8ccb323f0cfdc2f4da553ad818e289cb2614400cb6d6af4b51d18a872c";
        const GENESIS_HASH: &str =
            "2ab5e6c73607e8bfbbec2d4ce3ea1419cda29ae6892e7f1c24facc465cd65821";

        let cid = chain_id_testnet();
        let coinbase = build_genesis_coinbase(&cid).expect("genesis coinbase");

        // (1) bp2 range proof: exactly 739 bytes and self-verifies under bp2.
        assert_eq!(
            coinbase.output.proof.len(),
            739,
            "genesis coinbase proof must be a 739-byte Bulletproof"
        );
        assert!(
            dom_crypto::bp2_verify(
                coinbase.output.commitment.as_bytes(),
                &coinbase.output.proof
            )
            .expect("bp2_verify"),
            "genesis coinbase range proof must verify under bp2 (self-validation)"
        );

        // (2) PMMR roots match the pinned vectors.
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, &[]).expect("roots");
        assert_eq!(
            hex::encode(output_root.as_bytes()),
            OUTPUT_ROOT,
            "output_root drift"
        );
        assert_eq!(
            hex::encode(kernel_root.as_bytes()),
            KERNEL_ROOT,
            "kernel_root drift"
        );
        assert_eq!(
            hex::encode(rangeproof_root.as_bytes()),
            RANGEPROOF_ROOT,
            "rangeproof_root drift"
        );

        // (3) Genesis block hash matches the pinned vector AND the source-of-truth
        //     consensus constant GENESIS_HASH_TESTNET.
        let anchor = genesis_anchor(NETWORK_MAGIC_TESTNET).expect("anchor");
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_hash: Hash256::ZERO,
            height: BlockHeight::GENESIS,
            timestamp: anchor.timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: dom_pow::CompactTarget(target_to_compact(&anchor.target)),
            total_difficulty: U256::from(target_to_difficulty(&anchor.target)),
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        };
        let header_bytes = header.to_bytes().expect("ser");
        let genesis_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
        assert_eq!(
            hex::encode(genesis_hash),
            GENESIS_HASH,
            "genesis hash drift"
        );
        assert_eq!(
            genesis_hash,
            dom_core::GENESIS_HASH_TESTNET,
            "genesis hash must equal the pinned GENESIS_HASH_TESTNET constant"
        );

        // (4) Byte-reproducible: rebuild and confirm identical proof + roots.
        let cb2 = build_genesis_coinbase(&cid).expect("genesis coinbase rebuild");
        assert_eq!(
            cb2.output.proof, coinbase.output.proof,
            "genesis proof not reproducible"
        );
        let (o2, k2, r2) = compute_block_pmmr_roots(&cb2, &[]).expect("roots rebuild");
        assert_eq!((o2, k2, r2), (output_root, kernel_root, rangeproof_root));
    }

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
        assert!(super::MiningMode::from_network_and_pow_mode(
            dom_config::Network::Regtest,
            PowValidationMode::RandomX,
        )
        .unwrap()
        .light_vm());
        assert!(!super::MiningMode::from_network_and_pow_mode(
            dom_config::Network::Mainnet,
            PowValidationMode::RandomX,
        )
        .unwrap()
        .light_vm());
        assert!(!super::MiningMode::from_network_and_pow_mode(
            dom_config::Network::Testnet,
            PowValidationMode::RandomX,
        )
        .unwrap()
        .light_vm());
    }

    #[test]
    fn dev_mode_can_mine_fast_with_consensus_target() {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let mode = super::MiningMode::from_network_and_pow_mode(
            dom_config::Network::Regtest,
            PowValidationMode::FastDevOnly,
        )
        .expect("regtest fast mode");
        assert_eq!(mode, super::MiningMode::RegtestFastDevOnly);
        assert!(mode.light_vm());
        assert_eq!(mode.pow_mode(), PowValidationMode::FastDevOnly);

        let timestamp = Timestamp(1_700_000_000);
        let target =
            compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, BlockHeight(1)).unwrap();
        assert_eq!(target_to_compact(&target), REGTEST_TARGET_COMPACT);

        let (header, stats) = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            timestamp,
            target,
            primitive_types::U256::one(),
            [0u8; 32],
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            [0u8; 32],
            mode.light_vm(),
            mode.pow_mode(),
            1,
            disabled_throttle(),
        )
        .expect("fast mining with consensus target");
        assert_eq!(stats.workers, 1);

        assert_eq!(header.pow.nonce, 0, "fast mining should not search nonces");
        assert_eq!(
            header.target.to_target().unwrap(),
            compute_expected_target(NETWORK_MAGIC_REGTEST, header.timestamp, header.height)
                .unwrap()
        );
        assert!(validate_pow_for_network(NETWORK_MAGIC_REGTEST, &header, &[0u8; 32]).is_ok());
    }

    #[test]
    fn normal_mode_cannot_use_dev_target_accidentally() {
        assert_eq!(
            super::MiningMode::from_network_and_pow_mode(
                dom_config::Network::Mainnet,
                PowValidationMode::RandomX,
            )
            .unwrap(),
            super::MiningMode::MainnetLikeRandomX
        );
        assert_eq!(
            super::MiningMode::from_network_and_pow_mode(
                dom_config::Network::Testnet,
                PowValidationMode::RandomX,
            )
            .unwrap(),
            super::MiningMode::TestnetConfiguredRandomX
        );

        let timestamp = Timestamp(1_778_642_753);
        let mainnet_target =
            compute_expected_target(NETWORK_MAGIC_MAINNET, timestamp, BlockHeight(1)).unwrap();
        let testnet_target =
            compute_expected_target(NETWORK_MAGIC_TESTNET, timestamp, BlockHeight(1)).unwrap();

        assert_ne!(target_to_compact(&mainnet_target), REGTEST_TARGET_COMPACT);
        assert_ne!(target_to_compact(&testnet_target), REGTEST_TARGET_COMPACT);
    }

    #[test]
    fn fast_mining_fails_closed_on_production_like_networks() {
        for network in [dom_config::Network::Mainnet, dom_config::Network::Testnet] {
            let err = super::MiningMode::from_network_and_pow_mode(
                network,
                PowValidationMode::FastDevOnly,
            )
            .expect_err("production-like network must reject fast mining");
            assert!(
                err.to_string().contains("only allowed on regtest"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn config_parsing_does_not_silently_fall_back_to_easy_mining() {
        let json = r#"{
            "network": "Mainnet",
            "data_dir": "./dom-data",
            "p2p_listen_addr": "0.0.0.0:3333",
            "max_inbound": 125,
            "min_outbound": 8,
            "dns_seeds": [],
            "seed_peers": [],
            "mine": true,
            "miner_address": null,
            "wallet_path": null,
            "wallet_password": null,
            "log_level": "info",
            "rpc_listen_addr": null
        }"#;
        let config: NodeConfig = serde_json::from_str(json).expect("mainnet config parses");
        assert_eq!(config.network, dom_config::Network::Mainnet);
        assert_eq!(
            super::MiningMode::from_network_and_pow_mode(
                config.network,
                PowValidationMode::RandomX
            )
            .unwrap(),
            super::MiningMode::MainnetLikeRandomX
        );

        let invalid = json.replace("\"Mainnet\"", "\"Devtest\"");
        assert!(
            serde_json::from_str::<NodeConfig>(&invalid).is_err(),
            "unknown networks must not fall back to regtest/easy mining"
        );
    }

    #[test]
    fn throttle_config_defaults_to_disabled_when_missing() {
        let json = r#"{
            "network": "Regtest",
            "data_dir": "./dom-regtest-data",
            "p2p_listen_addr": "127.0.0.1:33371",
            "max_inbound": 8,
            "min_outbound": 0,
            "dns_seeds": [],
            "seed_peers": [],
            "mine": true,
            "miner_address": null,
            "wallet_path": null,
            "wallet_password": null,
            "log_level": "debug",
            "rpc_listen_addr": null
        }"#;
        let config: NodeConfig = serde_json::from_str(json).expect("regtest config parses");
        assert_eq!(config.miner_throttle, Default::default());
        assert_eq!(
            MinerThrottle::from_config(&config.miner_throttle),
            disabled_throttle()
        );
    }

    #[test]
    fn target_calculation_unchanged_by_throttle() {
        let timestamp = Timestamp(1_778_642_753);
        let mut off = NodeConfig::regtest();
        off.miner_throttle = Default::default();
        let mut on = NodeConfig::regtest();
        on.miner_throttle = MinerThrottleConfig {
            enabled: true,
            yield_every_nonces: 1,
            sleep_micros: 1,
        };

        assert_eq!(off.network, on.network);
        let off_target = compute_expected_target(off.network.magic(), timestamp, BlockHeight(1))
            .expect("target off");
        let on_target = compute_expected_target(on.network.magic(), timestamp, BlockHeight(1))
            .expect("target on");
        assert_eq!(off_target, on_target);
    }

    #[test]
    fn mined_block_validity_independent_of_throttle() {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let timestamp = Timestamp(1_700_000_000);
        let target =
            compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, BlockHeight(1)).unwrap();

        for throttle in [
            disabled_throttle(),
            MinerThrottle::from_config(&MinerThrottleConfig {
                enabled: true,
                yield_every_nonces: 1,
                sleep_micros: 0,
            }),
        ] {
            let (header, _stats) = mine_blocking(
                1,
                dom_core::Hash256::ZERO,
                timestamp,
                target,
                primitive_types::U256::one(),
                [0u8; 32],
                dom_core::Hash256::ZERO,
                dom_core::Hash256::ZERO,
                dom_core::Hash256::ZERO,
                [0u8; 32],
                true,
                PowValidationMode::FastDevOnly,
                1,
                throttle,
            )
            .expect("fast mining");

            assert_eq!(header.target.to_target().unwrap(), target);
            assert!(validate_pow_for_network(NETWORK_MAGIC_REGTEST, &header, &[0u8; 32]).is_ok());
        }
    }

    #[test]
    fn throttle_config_does_not_enter_consensus_serialization() {
        let timestamp = Timestamp(1_700_000_000);
        let mut off = NodeConfig::regtest();
        off.miner_throttle = Default::default();
        let mut on = NodeConfig::regtest();
        on.miner_throttle = MinerThrottleConfig {
            enabled: true,
            yield_every_nonces: 17,
            sleep_micros: 250,
        };

        let build_header = |config: &NodeConfig| {
            let target = compute_expected_target(config.network.magic(), timestamp, BlockHeight(1))
                .expect("target");
            BlockHeader {
                version: PROTOCOL_VERSION,
                prev_hash: Hash256::ZERO,
                height: BlockHeight(1),
                timestamp,
                output_root: Hash256::ZERO,
                kernel_root: Hash256::ZERO,
                rangeproof_root: Hash256::ZERO,
                total_kernel_offset: [0u8; 32],
                target: dom_pow::CompactTarget(target_to_compact(&target)),
                total_difficulty: primitive_types::U256::one(),
                pow: ProofOfWork {
                    nonce: 7,
                    randomx_hash: Hash256::from_bytes([0x42; 32]),
                },
            }
        };

        let off_header = build_header(&off);
        let on_header = build_header(&on);
        assert_eq!(off_header, on_header);
        assert_eq!(
            off_header.to_bytes().expect("off header bytes"),
            on_header.to_bytes().expect("on header bytes")
        );
        assert_eq!(off_header.pow_preimage(), on_header.pow_preimage());
    }

    #[test]
    fn miner_uses_consensus_target_not_fixed_dev_target() {
        let timestamp = Timestamp(1_778_642_753);
        for network_magic in [
            NETWORK_MAGIC_MAINNET,
            NETWORK_MAGIC_TESTNET,
            NETWORK_MAGIC_REGTEST,
        ] {
            let target = compute_expected_target(network_magic, timestamp, BlockHeight(1)).unwrap();
            let (header, _stats) = mine_blocking(
                1,
                dom_core::Hash256::ZERO,
                timestamp,
                target,
                primitive_types::U256::one(),
                [0u8; 32],
                dom_core::Hash256::ZERO,
                dom_core::Hash256::ZERO,
                dom_core::Hash256::ZERO,
                [0u8; 32],
                true,
                PowValidationMode::FastDevOnly,
                1,
                disabled_throttle(),
            )
            .expect("fast test mining");

            assert_eq!(
                header.target.to_target().unwrap(),
                compute_expected_target(network_magic, timestamp, BlockHeight(1)).unwrap()
            );
        }
    }

    #[test]
    fn regtest_fast_mining_returns_a_valid_header_without_searching() {
        use dom_core::NETWORK_MAGIC_REGTEST;

        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let target = dom_core::MAX_TARGET_BYTES;

        let (header, _stats) = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            Timestamp(1_700_000_000),
            target,
            primitive_types::U256::one(),
            [0u8; 32],
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            [0u8; 32],
            true,
            dom_pow::PowValidationMode::FastDevOnly,
            1,
            disabled_throttle(),
        )
        .expect("fast mining");

        assert_eq!(header.pow.nonce, 0, "fast mining should not search nonces");
        assert!(validate_pow_for_network(NETWORK_MAGIC_REGTEST, &header, &[0u8; 32]).is_ok());
    }

    #[test]
    fn multithreaded_randomx_mining_spawns_workers_and_produces_real_hash() {
        // Real RandomX (cache-only light VM, shared by 4 workers). The raw
        // all-0xFF search target makes EVERY hash a winner, so each worker
        // does exactly one RandomX hash and the test costs cache-init + 4
        // hashes instead of the ~2^16 expected for the smallest
        // consensus-encodable target (MAX_TARGET_BYTES) — minutes in debug
        // builds. Consequence: `validate_pow` (which re-derives the target
        // from the compact header field) is not applicable here; the property
        // this test pins is the multi-worker orchestration itself — N workers
        // spawn, partition the nonce space, share one RandomX cache across
        // threads, and the winner's hash is REAL RandomX (recomputed below on
        // an independent VM), not garbage from a torn/shared-state race.
        use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

        let seed = [0u8; 32];
        let trivial_target = [0xff_u8; 32];
        let (header, stats) = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            Timestamp(1_700_000_000),
            trivial_target,
            primitive_types::U256::one(),
            seed,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            [0u8; 32],
            true, // light VM: cache-only RandomX, no 2 GB dataset in tests
            PowValidationMode::RandomX,
            4,
            disabled_throttle(),
        )
        .expect("multithreaded RandomX mining");

        assert_eq!(
            stats.workers, 4,
            "configured 4 threads must spawn 4 workers"
        );
        // Strided partition: worker i searches nonces i, i+4, i+8, ... — with
        // the all-0xFF target every worker wins on its FIRST nonce, so the
        // winner is deterministically one of {0, 1, 2, 3}.
        assert!(
            header.pow.nonce < 4,
            "nonce {} outside the first stride of 4 workers",
            header.pow.nonce
        );
        // The winning hash must be genuine RandomX over the shared cache:
        // recompute it on a fresh, independent VM and require equality.
        let flags = RandomXFlag::get_recommended_flags();
        let cache = RandomXCache::new(flags, &seed).expect("verification cache");
        let vm = RandomXVM::new(flags, Some(cache), None).expect("verification vm");
        let recomputed = super::randomx_hash(&vm, &header.pow_preimage()).expect("recompute hash");
        assert_eq!(
            Hash256::from_bytes(recomputed),
            header.pow.randomx_hash,
            "worker hash must equal independently recomputed RandomX hash"
        );
    }

    #[test]
    fn fast_dev_mode_ignores_thread_count_and_stays_deterministic() {
        // FastDevOnly searches nothing; requesting many threads must not
        // make the found nonce racy (workers forced to 1).
        let (header, stats) = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            Timestamp(1_700_000_000),
            dom_core::MAX_TARGET_BYTES,
            primitive_types::U256::one(),
            [0u8; 32],
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            [0u8; 32],
            true,
            PowValidationMode::FastDevOnly,
            8,
            disabled_throttle(),
        )
        .expect("fast mining");

        assert_eq!(stats.workers, 1, "FastDevOnly must keep a single worker");
        assert_eq!(header.pow.nonce, 0, "fast mining should not search nonces");
    }

    #[test]
    fn zero_thread_config_clamps_to_one_worker() {
        // All-0xFF raw target: one RandomX hash ends the search (see the
        // multithread test above for why MAX_TARGET_BYTES is too slow here).
        let (_header, stats) = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            Timestamp(1_700_000_000),
            [0xff_u8; 32],
            primitive_types::U256::one(),
            [0u8; 32],
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            [0u8; 32],
            true,
            PowValidationMode::RandomX,
            0,
            disabled_throttle(),
        )
        .expect("zero-thread mining clamps to one worker");
        assert_eq!(stats.workers, 1);
    }

    #[test]
    fn miner_validator_still_share_compute_expected_target() {
        use dom_core::NETWORK_MAGIC_MAINNET;

        let timestamp = Timestamp(1_778_642_753);
        let target =
            compute_expected_target(NETWORK_MAGIC_MAINNET, timestamp, BlockHeight(1)).unwrap();
        let total_difficulty = U256::from(target_to_difficulty(&target));
        let (header, _stats) = mine_blocking(
            1,
            dom_core::Hash256::ZERO,
            timestamp,
            target,
            total_difficulty,
            [0u8; 32],
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            dom_core::Hash256::ZERO,
            [0u8; 32],
            true,
            dom_pow::PowValidationMode::FastDevOnly,
            1,
            disabled_throttle(),
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
        let node = Arc::new(init_test_node(regtest_config(&dir)));
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

        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn accepted_mined_block_updates_blocks_mined_and_runtime_gauges() {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let dir = fresh_test_dir("metrics-accepted-mined-block");
        let node = Arc::new(init_test_node(regtest_config(&dir)));
        super::create_genesis_block(node.clone())
            .await
            .expect("create genesis");

        let coinbase =
            build_real_coinbase(BlockHeight(1), 0, &chain_id_regtest()).expect("coinbase");
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, &[]).expect("roots");
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
            [0u8; 32],
            tip_difficulty + U256::from(target_to_difficulty(&target)),
        );
        let block = Block {
            header,
            coinbase,
            transactions: vec![],
        };

        let height = finalize_mined_block(&node, block)
            .await
            .expect("valid mined block accepted");

        assert_eq!(height, 1);
        assert_eq!(node.metrics.blocks_mined.load(Ordering::Relaxed), 1);
        assert_eq!(node.metrics.chain_height.load(Ordering::Relaxed), 1);
        assert_eq!(node.metrics.mempool_size.load(Ordering::Relaxed), 0);

        crate::test_dir::remove_test_dir(&dir);
    }

    /// DOM-AUDIT-001 regression: a freshly *created* genesis node and a node
    /// that *reopened* the same data_dir must hold byte-identical UTXO and
    /// kernel-index databases.
    ///
    /// The reopen path (`ChainState::open` → `ensure_canonical_utxo_set` +
    /// `rebuild_kernel_index_from_canonical_chain`) reconstructs the spendable
    /// genesis coinbase from the stored block body. If `create_genesis_block`
    /// persists a different changeset (e.g. an empty one), the created node and
    /// the reopened node diverge on the genesis coinbase — a latent chain split
    /// the instant that coinbase is spent. This test pins `create == reopen`.
    #[tokio::test]
    async fn genesis_create_persists_same_utxo_and_kernel_state_as_reopen_reconstruct() {
        use dom_serialization::DomDeserialize;

        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let dir = fresh_test_dir("genesis-create-equals-reopen");

        // --- Create path: build genesis via the miner into a temp data_dir. ---
        let node = Arc::new(init_test_node(regtest_config(&dir)));
        super::create_genesis_block(node.clone())
            .await
            .expect("create genesis");

        // Snapshot A: raw UTXO + kernel-index dumps right after create, plus the
        // genesis coinbase commitment read straight from the persisted body (the
        // unimpeachable source of truth for what the UTXO key must be).
        let (utxos_a, kernels_a, coinbase_commitment) = {
            let chain = node.chain.lock().await;
            let utxos_a = chain.store.read_all_utxos_raw().expect("utxo dump A");
            let kernels_a = chain
                .store
                .read_all_kernel_index_raw()
                .expect("kernel dump A");
            let body = chain
                .store
                .get_block_body(chain.tip_hash.as_bytes())
                .expect("genesis body lookup")
                .expect("genesis body present after create");
            let genesis_block = Block::from_bytes(&body).expect("decode persisted genesis block");
            let coinbase_commitment = genesis_block.coinbase.output.commitment.as_bytes().to_vec();
            (utxos_a, kernels_a, coinbase_commitment)
        };

        // Release the LMDB environment before reopening the same data_dir.
        drop(node);

        // --- Reopen path: ChainState::open re-runs the canonical reconstruct. ---
        let reopened = Arc::new(init_test_node(regtest_config(&dir)));
        let (utxos_b, kernels_b) = {
            let chain = reopened.chain.lock().await;
            let utxos_b = chain.store.read_all_utxos_raw().expect("utxo dump B");
            let kernels_b = chain
                .store
                .read_all_kernel_index_raw()
                .expect("kernel dump B");
            (utxos_b, kernels_b)
        };

        // Byte-for-byte equivalence across the full key/value space of both DBs.
        assert_eq!(
            utxos_a, utxos_b,
            "UTXO database diverged between create and reopen (create != reopen)"
        );
        assert_eq!(
            kernels_a, kernels_b,
            "kernel index diverged between create and reopen (create != reopen)"
        );

        // And specifically: the spendable genesis coinbase UTXO is present in BOTH.
        assert!(
            utxos_a.contains_key(&coinbase_commitment),
            "genesis coinbase UTXO missing from the freshly-created UTXO set"
        );
        assert!(
            utxos_b.contains_key(&coinbase_commitment),
            "genesis coinbase UTXO missing from the reopened/reconstructed UTXO set"
        );

        drop(reopened);
        crate::test_dir::remove_test_dir(&dir);
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

//! Embedded Wallet V3 API adapter for the production node.
//!
//! This module is the only node-side implementation of the wallet-facing
//! contract. Wallet code depends on `dom-wallet-core-api` types and receives
//! this adapter from the embedded node boundary; it must not reach through to
//! `ChainState`, LMDB, mempool internals, peer-manager internals, or task
//! channels.

use crate::node::{clear_persisted_mempool_snapshot, snapshot_tx_chain_view, DomNode};
use dom_config::Network;
use dom_consensus::{derive_chain_id, Block, Transaction};
use dom_core::{
    fee_policy, DomError, Hash256, MAX_TX_WEIGHT, MIN_RELAY_FEE_RATE, PROTOCOL_VERSION,
};
use dom_crypto::hash::blake2b_256;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoinbaseScanMetadata, CoreNetwork,
    CursorValidation, FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeeEstimateTarget,
    FeePolicySnapshot, FeeRate, FeeValidation, KernelQueryResult, MempoolPolicySnapshot, ScanBlock,
    ScanInput, ScanKernel, ScanOutput, ScanRequest, ScanResult, ScanStart, SubmissionDiagnostic,
    SubmissionResult, SubmissionResultKind, SubmitTransactionRequest, SyncStatus,
    TransactionIdentifier, TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult,
    WalletCoreApi, WalletCoreError, WalletScanCursor,
};
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Embedded-node implementation of the Wallet V3 core API.
#[derive(Clone)]
pub struct EmbeddedWalletCoreApi {
    node: Arc<DomNode>,
}

impl EmbeddedWalletCoreApi {
    /// Create a Wallet V3 API adapter for an in-process node.
    pub fn new(node: Arc<DomNode>) -> Self {
        Self { node }
    }

    fn network(&self) -> CoreNetwork {
        match self.node.config.network {
            Network::Mainnet => CoreNetwork::Mainnet,
            Network::Testnet => CoreNetwork::Testnet,
            Network::Regtest => CoreNetwork::Regtest,
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    fn classify_submission_error(error: &DomError) -> (SubmissionResultKind, SubmissionDiagnostic) {
        match error {
            DomError::PolicyRejected(message) if message.contains("already in mempool") => (
                SubmissionResultKind::AlreadyKnown,
                SubmissionDiagnostic::AlreadyKnown,
            ),
            DomError::PolicyRejected(message)
                if message.contains("fee rate") || message.contains("minimum relay fee") =>
            {
                (
                    SubmissionResultKind::RejectedFee,
                    SubmissionDiagnostic::FeeTooLow,
                )
            }
            DomError::PolicyRejected(message)
                if message.contains("input already reserved")
                    || message.contains("not found in canonical UTXO set") =>
            {
                (
                    SubmissionResultKind::RejectedDoubleSpend,
                    SubmissionDiagnostic::DoubleSpend,
                )
            }
            DomError::TemporarilyInvalid(message) if message.contains("coinbase") => (
                SubmissionResultKind::RejectedImmatureCoinbase,
                SubmissionDiagnostic::ImmatureCoinbase,
            ),
            DomError::TemporarilyInvalid(_) => (
                SubmissionResultKind::RejectedExpired,
                SubmissionDiagnostic::Locked,
            ),
            DomError::Invalid(_) | DomError::Malformed(_) | DomError::PeerMisbehavior { .. } => (
                SubmissionResultKind::RejectedInvalid,
                SubmissionDiagnostic::Invalid,
            ),
            DomError::PolicyRejected(_) => (
                SubmissionResultKind::RejectedPolicy,
                SubmissionDiagnostic::Policy,
            ),
            DomError::Orphan(_) => (
                SubmissionResultKind::TemporaryFailure,
                SubmissionDiagnostic::NodeBusy,
            ),
            DomError::Internal(_) => (
                SubmissionResultKind::InternalFailure,
                SubmissionDiagnostic::Internal,
            ),
        }
    }

    fn node_not_ready_result(
        tx_hash: [u8; 32],
        primary_kernel_excess: Option<[u8; 33]>,
    ) -> SubmissionResult {
        SubmissionResult {
            kind: SubmissionResultKind::NodeNotReady,
            tx_hash,
            primary_kernel_excess,
            accepted_to_mempool: false,
            broadcast_attempted: false,
            relayed: false,
            diagnostic: Some(SubmissionDiagnostic::NodeBusy),
        }
    }

    fn submission_error_result(
        tx_hash: [u8; 32],
        primary_kernel_excess: Option<[u8; 33]>,
        error: &DomError,
    ) -> SubmissionResult {
        let (kind, diagnostic) = Self::classify_submission_error(error);
        SubmissionResult {
            kind,
            tx_hash,
            primary_kernel_excess,
            accepted_to_mempool: false,
            broadcast_attempted: false,
            relayed: false,
            diagnostic: Some(diagnostic),
        }
    }

    fn primary_kernel_excess(tx: &Transaction) -> Option<[u8; 33]> {
        tx.kernels.first().map(|kernel| *kernel.excess.as_bytes())
    }

    fn tx_hash(tx: &Transaction) -> Result<([u8; 32], Vec<u8>), WalletCoreError> {
        let bytes = tx
            .to_bytes()
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
        Ok((*blake2b_256(&bytes).as_bytes(), bytes))
    }

    fn core_shape(shape: TransactionShape) -> fee_policy::TransactionShape {
        fee_policy::TransactionShape {
            input_count: shape.input_count,
            output_count: shape.output_count,
            kernel_count: shape.kernel_count,
        }
    }

    fn api_fee_rate(rate: fee_policy::FeeRate) -> FeeRate {
        FeeRate {
            noms_per_weight_unit: rate.noms_per_weight_unit,
        }
    }

    fn api_weight(weight: fee_policy::TransactionWeight) -> TransactionWeight {
        TransactionWeight {
            input_weight: weight.input_weight,
            output_weight: weight.output_weight,
            kernel_weight: weight.kernel_weight,
            total_weight: weight.total_weight,
        }
    }

    fn api_breakdown(&self, breakdown: fee_policy::FeeBreakdown) -> FeeBreakdown {
        FeeBreakdown {
            input_count: breakdown.shape.input_count,
            output_count: breakdown.shape.output_count,
            kernel_count: breakdown.shape.kernel_count,
            input_weight: breakdown.weight.input_weight,
            output_weight: breakdown.weight.output_weight,
            kernel_weight: breakdown.weight.kernel_weight,
            total_weight: breakdown.weight.total_weight,
            minimum_fee_noms: breakdown.minimum_fee_noms,
            recommended_fee_noms: breakdown.recommended_fee_noms,
            minimum_fee_rate: Self::api_fee_rate(breakdown.minimum_fee_rate),
            recommended_fee_rate: Self::api_fee_rate(breakdown.recommended_fee_rate),
            policy_version: breakdown.policy_version,
            network: self.network(),
            validity_horizon: None,
            dust_threshold_noms: breakdown.dust_threshold_noms,
        }
    }

    fn map_policy_error(error: DomError) -> WalletCoreError {
        match error {
            DomError::Invalid(message) | DomError::PolicyRejected(message) => {
                WalletCoreError::InvalidScanRequest(message)
            }
            DomError::Internal(message) => WalletCoreError::InternalFailure(message),
            other => WalletCoreError::InternalFailure(other.to_string()),
        }
    }

    fn current_identity_locked(
        &self,
        chain: &dom_chain::ChainState,
    ) -> Result<ChainIdentity, WalletCoreError> {
        let chain_id = derive_chain_id(chain.network_magic, &chain.genesis_hash);
        Ok(ChainIdentity {
            network: self.network(),
            network_magic: chain.network_magic,
            chain_id: *chain_id.as_bytes(),
            genesis_hash: *chain.genesis_hash.as_bytes(),
            protocol_version: PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
            coinbase_maturity: chain.coinbase_maturity,
            current_tip: BlockRef {
                height: chain.tip_height.0,
                hash: *chain.tip_hash.as_bytes(),
            },
        })
    }

    fn validate_request_identity(
        request: &ScanRequest,
        identity: &ChainIdentity,
    ) -> Result<(), WalletCoreError> {
        if request.network != identity.network || request.chain_id != identity.chain_id {
            return Err(WalletCoreError::CursorChainMismatch(
                "request identity does not match node identity".to_string(),
            ));
        }
        if request.max_blocks == 0 {
            return Err(WalletCoreError::InvalidScanRequest(
                "max_blocks must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_cursor_locked(
        &self,
        chain: &dom_chain::ChainState,
        cursor: &WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError> {
        cursor.validate_shape()?;
        let identity = self.current_identity_locked(chain)?;
        if cursor.network_magic != identity.network_magic || cursor.chain_id != identity.chain_id {
            return Err(WalletCoreError::CursorChainMismatch(
                "cursor identity does not match node identity".to_string(),
            ));
        }
        let Some(anchor_hash) = chain
            .store
            .get_hash_at_height(cursor.anchor_height)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
        else {
            return Err(WalletCoreError::CursorReorg(
                "cursor anchor height is no longer canonical".to_string(),
            ));
        };
        if anchor_hash != cursor.anchor_hash {
            return Err(WalletCoreError::CursorReorg(
                "cursor anchor hash differs from canonical hash".to_string(),
            ));
        }
        Ok(CursorValidation {
            valid: true,
            safe_rescan_anchor: BlockRef {
                height: cursor.anchor_height,
                hash: cursor.anchor_hash,
            },
        })
    }

    fn block_hash_at_locked(
        chain: &dom_chain::ChainState,
        height: u64,
    ) -> Result<Option<[u8; 32]>, WalletCoreError> {
        chain
            .store
            .get_hash_at_height(height)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))
    }

    fn load_canonical_block_locked(
        chain: &dom_chain::ChainState,
        height: u64,
    ) -> Result<Option<(Hash256, Block)>, WalletCoreError> {
        let Some(hash) = Self::block_hash_at_locked(chain, height)? else {
            return Ok(None);
        };
        let Some(body) = chain
            .store
            .get_block_body(&hash)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
        else {
            return Err(WalletCoreError::CanonicalGap(format!(
                "missing block body at height {height}"
            )));
        };
        let block = Block::from_bytes(&body)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
        Ok(Some((Hash256::from_bytes(hash), block)))
    }

    fn project_block(
        identity: &ChainIdentity,
        hash: Hash256,
        block: Block,
        filters: Option<&HashSet<[u8; 33]>>,
    ) -> Result<ScanBlock, WalletCoreError> {
        let block_hash = *hash.as_bytes();
        let mut outputs = Vec::new();
        let mut output_position = 0u32;

        let coinbase_commitment = *block.coinbase.output.commitment.as_bytes();
        if filters.is_none_or(|set| set.contains(&coinbase_commitment)) {
            let coinbase_proof = block
                .coinbase
                .output
                .range_proof_bytes()
                .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
            let coinbase_capsule = block
                .coinbase
                .output
                .recovery_capsule()
                .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
            outputs.push(ScanOutput {
                commitment: coinbase_commitment,
                range_proof: coinbase_proof.to_vec(),
                recovery_version: coinbase_capsule
                    .as_ref()
                    .map_or(0, |capsule| capsule.version()),
                recovery_capsule: coinbase_capsule
                    .map(|capsule| capsule.as_bytes().to_vec())
                    .unwrap_or_default(),
                is_coinbase: true,
                block_height: block.header.height.0,
                block_hash,
                output_position,
            });
        }
        output_position = output_position.saturating_add(1);

        for tx in &block.transactions {
            for output in &tx.outputs {
                let commitment = *output.commitment.as_bytes();
                if filters.is_none_or(|set| set.contains(&commitment)) {
                    let range_proof = output
                        .range_proof_bytes()
                        .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
                    let capsule = output
                        .recovery_capsule()
                        .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
                    outputs.push(ScanOutput {
                        commitment,
                        range_proof: range_proof.to_vec(),
                        recovery_version: capsule.as_ref().map_or(0, |value| value.version()),
                        recovery_capsule: capsule
                            .map(|value| value.as_bytes().to_vec())
                            .unwrap_or_default(),
                        is_coinbase: false,
                        block_height: block.header.height.0,
                        block_hash,
                        output_position,
                    });
                }
                output_position = output_position.saturating_add(1);
            }
        }

        let inputs = block
            .transactions
            .iter()
            .flat_map(|tx| {
                tx.inputs.iter().map(|input| ScanInput {
                    spent_commitment: *input.commitment.as_bytes(),
                })
            })
            .collect();

        let mut kernels = Vec::with_capacity(
            1 + block
                .transactions
                .iter()
                .map(|tx| tx.kernels.len())
                .sum::<usize>(),
        );
        kernels.push(ScanKernel {
            excess: *block.coinbase.kernel.excess.as_bytes(),
            features: block.coinbase.kernel.features,
            fee: 0,
            lock_height: 0,
        });
        for tx in &block.transactions {
            for kernel in &tx.kernels {
                kernels.push(ScanKernel {
                    excess: *kernel.excess.as_bytes(),
                    features: kernel.features,
                    fee: kernel.fee.noms(),
                    lock_height: kernel.lock_height,
                });
            }
        }

        let total_fees_noms = block
            .total_fees()
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;

        Ok(ScanBlock {
            height: block.header.height.0,
            block_hash,
            previous_block_hash: *block.header.prev_hash.as_bytes(),
            timestamp: block.header.timestamp.0,
            canonical_marker: block_hash,
            outputs,
            inputs,
            kernels,
            coinbase: CoinbaseScanMetadata {
                output_commitment: coinbase_commitment,
                explicit_value: block.coinbase.kernel.explicit_value,
                kernel_excess: *block.coinbase.kernel.excess.as_bytes(),
            },
            total_fees_noms,
            protocol_version: block.header.version,
            range_proof_serialization_version: identity.range_proof_serialization_version,
        })
    }

    fn relay_transaction(&self, tx_hash: [u8; 32], tx_bytes: Vec<u8>) -> bool {
        let (phase, stem_target) = if let (Ok(mut dandelion), Ok(peers)) =
            (self.node.dandelion.try_lock(), self.node.peers.try_lock())
        {
            let connected: Vec<std::net::SocketAddr> = peers
                .connected_peers()
                .into_iter()
                .filter_map(|addr| addr.parse().ok())
                .collect();
            let phase = dandelion.route_new_tx(tx_hash, &connected);
            let target = dandelion.get_stem_peer(&tx_hash);
            (phase, target)
        } else {
            (dom_wire::dandelion::DandelionPhase::Fluff, None)
        };
        match phase {
            dom_wire::dandelion::DandelionPhase::Fluff => {
                self.node.tx_fluff_tx.send(tx_bytes).is_ok()
            }
            dom_wire::dandelion::DandelionPhase::Stem => {
                if let Some(target_peer) = stem_target {
                    self.node
                        .tx_stem_tx
                        .send(dom_wire::dandelion::StemEnvelope {
                            target_peer,
                            tx_bytes,
                        })
                        .is_ok()
                } else {
                    self.node.tx_fluff_tx.send(tx_bytes).is_ok()
                }
            }
        }
    }
}

impl WalletCoreApi for EmbeddedWalletCoreApi {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        let chain = self
            .node
            .chain
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("chain lock busy".to_string()))?;
        self.current_identity_locked(&chain)
    }

    fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        let chain = self
            .node
            .chain
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("chain lock busy".to_string()))?;
        let identity = self.current_identity_locked(&chain)?;
        Self::validate_request_identity(&request, &identity)?;

        let start_height = match &request.start {
            ScanStart::Height(height) => *height,
            ScanStart::Cursor(cursor) => {
                self.validate_cursor_locked(&chain, cursor)?;
                cursor.next_height
            }
        };

        let stop_height = request
            .stop_height
            .unwrap_or(identity.current_tip.height)
            .min(identity.current_tip.height);

        if start_height > stop_height {
            return Ok(ScanResult {
                tip: identity.current_tip,
                blocks: Vec::new(),
                continuation: None,
            });
        }

        let filters = (!request.commitment_filters.is_empty()).then(|| {
            request
                .commitment_filters
                .iter()
                .copied()
                .collect::<HashSet<_>>()
        });
        let to_height = start_height
            .saturating_add(request.max_blocks.saturating_sub(1))
            .min(stop_height);

        let mut blocks = Vec::new();
        for height in start_height..=to_height {
            let Some((hash, block)) = Self::load_canonical_block_locked(&chain, height)? else {
                if height == 0
                    && chain.tip_height.0 == 0
                    && chain.tip_hash == Hash256::ZERO
                    && blocks.is_empty()
                {
                    break;
                }
                return Err(WalletCoreError::CanonicalGap(format!(
                    "missing canonical block at height {height}"
                )));
            };
            blocks.push(Self::project_block(
                &identity,
                hash,
                block,
                filters.as_ref(),
            )?);
        }

        let continuation = blocks.last().and_then(|block| {
            if block.height < stop_height {
                Some(WalletScanCursor::new(
                    identity.network,
                    identity.chain_id,
                    block.height.saturating_add(1),
                    BlockRef {
                        height: block.height,
                        hash: block.block_hash,
                    },
                ))
            } else {
                None
            }
        });

        Ok(ScanResult {
            tip: identity.current_tip,
            blocks,
            continuation,
        })
    }

    fn validate_cursor(
        &self,
        cursor: WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError> {
        let chain = self
            .node
            .chain
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("chain lock busy".to_string()))?;
        self.validate_cursor_locked(&chain, &cursor)
    }

    fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        let chain = self
            .node
            .chain
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("chain lock busy".to_string()))?;
        Self::block_hash_at_locked(&chain, height)
    }

    fn get_utxo(&self, commitment: &[u8; 33]) -> Result<Option<UtxoQueryResult>, WalletCoreError> {
        let chain = self
            .node
            .chain
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("chain lock busy".to_string()))?;
        let Some(entry) = chain
            .store
            .get_utxo(commitment)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
        else {
            return Ok(None);
        };
        Ok(Some(UtxoQueryResult {
            commitment: *commitment,
            block_height: entry.block_height,
            is_coinbase: entry.is_coinbase,
            is_mature: entry.is_mature_for(chain.tip_height.0, chain.coinbase_maturity),
        }))
    }

    fn get_kernel(&self, excess: &[u8; 33]) -> Result<Option<KernelQueryResult>, WalletCoreError> {
        let chain = self
            .node
            .chain
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("chain lock busy".to_string()))?;
        let Some(block_hash) = chain
            .store
            .get_kernel_block(excess)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
        else {
            return Ok(None);
        };
        let Some(body) = chain
            .store
            .get_block_body(&block_hash)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
        else {
            return Err(WalletCoreError::InternalFailure(
                "kernel index points to missing block body".to_string(),
            ));
        };
        let block = Block::from_bytes(&body)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
        Ok(Some(KernelQueryResult {
            excess: *excess,
            block: BlockRef {
                height: block.header.height.0,
                hash: block_hash,
            },
        }))
    }

    fn get_block_summary(
        &self,
        selector: BlockSelector,
    ) -> Result<Option<BlockSummary>, WalletCoreError> {
        let chain = self
            .node
            .chain
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("chain lock busy".to_string()))?;
        let block_hash = match selector {
            BlockSelector::Height(height) => {
                let Some(hash) = Self::block_hash_at_locked(&chain, height)? else {
                    return Ok(None);
                };
                hash
            }
            BlockSelector::Hash(hash) => hash,
        };
        let Some(body) = chain
            .store
            .get_block_body(&block_hash)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
        else {
            return Ok(None);
        };
        let block = Block::from_bytes(&body)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?;
        let output_count = 1 + block
            .transactions
            .iter()
            .map(|tx| tx.outputs.len())
            .sum::<usize>();
        let input_count = block
            .transactions
            .iter()
            .map(|tx| tx.inputs.len())
            .sum::<usize>();
        let kernel_count = 1 + block
            .transactions
            .iter()
            .map(|tx| tx.kernels.len())
            .sum::<usize>();
        Ok(Some(BlockSummary {
            block: BlockRef {
                height: block.header.height.0,
                hash: block_hash,
            },
            previous_block_hash: *block.header.prev_hash.as_bytes(),
            timestamp: block.header.timestamp.0,
            output_count: output_count
                .try_into()
                .map_err(|_| WalletCoreError::InternalFailure("output count overflow".into()))?,
            input_count: input_count
                .try_into()
                .map_err(|_| WalletCoreError::InternalFailure("input count overflow".into()))?,
            kernel_count: kernel_count
                .try_into()
                .map_err(|_| WalletCoreError::InternalFailure("kernel count overflow".into()))?,
            total_fees_noms: block
                .total_fees()
                .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?,
        }))
    }

    fn transaction_status(
        &self,
        identifier: TransactionIdentifier,
    ) -> Result<TransactionStatus, WalletCoreError> {
        match identifier {
            TransactionIdentifier::TxHash(tx_hash) => {
                let mempool =
                    self.node.mempool.try_lock().map_err(|_| {
                        WalletCoreError::NodeNotReady("mempool lock busy".to_string())
                    })?;
                if mempool.contains(&tx_hash) {
                    Ok(TransactionStatus::InMempool)
                } else {
                    Ok(TransactionStatus::Unknown)
                }
            }
            TransactionIdentifier::KernelExcess(excess) => self
                .get_kernel(&excess)?
                .map_or(Ok(TransactionStatus::Unknown), |kernel| {
                    Ok(TransactionStatus::Confirmed(kernel.block))
                }),
        }
    }

    fn submit_transaction(
        &self,
        request: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError> {
        let (tx_hash, tx_bytes) = Self::tx_hash(&request.transaction)?;
        let primary_kernel_excess = Self::primary_kernel_excess(&request.transaction);

        if let Ok(mempool) = self.node.mempool.try_lock() {
            if mempool.contains(&tx_hash) {
                return Ok(SubmissionResult {
                    kind: SubmissionResultKind::AlreadyKnown,
                    tx_hash,
                    primary_kernel_excess,
                    accepted_to_mempool: true,
                    broadcast_attempted: false,
                    relayed: false,
                    diagnostic: Some(SubmissionDiagnostic::AlreadyKnown),
                });
            }
        } else {
            return Ok(Self::node_not_ready_result(tx_hash, primary_kernel_excess));
        }

        let chain_view = {
            let chain = match self.node.chain.try_lock() {
                Ok(chain) => chain,
                Err(_) => return Ok(Self::node_not_ready_result(tx_hash, primary_kernel_excess)),
            };
            match snapshot_tx_chain_view(&chain, &request.transaction) {
                Ok(view) => view,
                Err(error) => {
                    return Ok(Self::submission_error_result(
                        tx_hash,
                        primary_kernel_excess,
                        &error,
                    ));
                }
            }
        };

        {
            let mut mempool = match self.node.mempool.try_lock() {
                Ok(mempool) => mempool,
                Err(_) => return Ok(Self::node_not_ready_result(tx_hash, primary_kernel_excess)),
            };
            if let Err(error) = mempool.accept_tx_with_chain_view(
                request.transaction.clone(),
                tx_hash,
                Self::now_secs(),
                chain_view.current_height,
                chain_view.chain_id,
                chain_view.coinbase_maturity,
                |commitment| Ok(chain_view.utxos.get(commitment).cloned().unwrap_or(None)),
            ) {
                return Ok(Self::submission_error_result(
                    tx_hash,
                    primary_kernel_excess,
                    &error,
                ));
            }
            self.node
                .metrics
                .mempool_size
                .store(mempool.len() as u64, Ordering::Relaxed);
        }

        if let Ok(chain) = self.node.chain.try_lock() {
            let _ = clear_persisted_mempool_snapshot(&chain.store);
        }

        let relayed = self.relay_transaction(tx_hash, tx_bytes);
        if relayed {
            self.node
                .metrics
                .txs_relayed
                .fetch_add(1, Ordering::Relaxed);
        }
        self.node.state_events.notify_waiters();

        Ok(SubmissionResult {
            kind: SubmissionResultKind::Accepted,
            tx_hash,
            primary_kernel_excess,
            accepted_to_mempool: true,
            broadcast_attempted: true,
            relayed,
            diagnostic: None,
        })
    }

    fn rebroadcast_transaction(
        &self,
        identifier: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        let TransactionIdentifier::TxHash(tx_hash) = identifier else {
            return Ok(SubmissionResult {
                kind: SubmissionResultKind::RejectedPolicy,
                tx_hash: [0u8; 32],
                primary_kernel_excess: None,
                accepted_to_mempool: false,
                broadcast_attempted: false,
                relayed: false,
                diagnostic: Some(SubmissionDiagnostic::Policy),
            });
        };
        let tx_bytes = {
            let mempool = match self.node.mempool.try_lock() {
                Ok(mempool) => mempool,
                Err(_) => return Ok(Self::node_not_ready_result(tx_hash, None)),
            };
            let Some(entry) = mempool.get_tx(&tx_hash) else {
                return Ok(SubmissionResult {
                    kind: SubmissionResultKind::RejectedPolicy,
                    tx_hash,
                    primary_kernel_excess: None,
                    accepted_to_mempool: false,
                    broadcast_attempted: false,
                    relayed: false,
                    diagnostic: Some(SubmissionDiagnostic::Policy),
                });
            };
            entry
                .tx
                .to_bytes()
                .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
        };
        let relayed = self.relay_transaction(tx_hash, tx_bytes);
        Ok(SubmissionResult {
            kind: SubmissionResultKind::AlreadyKnown,
            tx_hash,
            primary_kernel_excess: None,
            accepted_to_mempool: true,
            broadcast_attempted: true,
            relayed,
            diagnostic: Some(SubmissionDiagnostic::AlreadyKnown),
        })
    }

    fn query_submission(
        &self,
        identifier: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        match identifier {
            TransactionIdentifier::TxHash(tx_hash) => {
                let mempool =
                    self.node.mempool.try_lock().map_err(|_| {
                        WalletCoreError::NodeNotReady("mempool lock busy".to_string())
                    })?;
                let known = mempool.contains(&tx_hash);
                Ok(SubmissionResult {
                    kind: if known {
                        SubmissionResultKind::AlreadyKnown
                    } else {
                        SubmissionResultKind::RejectedPolicy
                    },
                    tx_hash,
                    primary_kernel_excess: None,
                    accepted_to_mempool: known,
                    broadcast_attempted: false,
                    relayed: false,
                    diagnostic: known.then_some(SubmissionDiagnostic::AlreadyKnown),
                })
            }
            TransactionIdentifier::KernelExcess(excess) => {
                let confirmed = self.get_kernel(&excess)?.is_some();
                Ok(SubmissionResult {
                    kind: if confirmed {
                        SubmissionResultKind::AlreadyKnown
                    } else {
                        SubmissionResultKind::RejectedPolicy
                    },
                    tx_hash: [0u8; 32],
                    primary_kernel_excess: Some(excess),
                    accepted_to_mempool: false,
                    broadcast_attempted: false,
                    relayed: false,
                    diagnostic: confirmed.then_some(SubmissionDiagnostic::AlreadyKnown),
                })
            }
        }
    }

    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        if self.node.chain.try_lock().is_err() || self.node.mempool.try_lock().is_err() {
            Ok(SyncStatus::Busy)
        } else {
            Ok(SyncStatus::Ready)
        }
    }

    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        Ok(self.node.chain.try_lock().is_ok() && self.node.mempool.try_lock().is_ok())
    }

    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        let mempool = self
            .node
            .mempool
            .try_lock()
            .map_err(|_| WalletCoreError::NodeNotReady("mempool lock busy".to_string()))?;
        Ok(MempoolPolicySnapshot {
            policy_version: fee_policy::FEE_POLICY_VERSION,
            network: self.network(),
            min_relay_fee_rate: MIN_RELAY_FEE_RATE,
            min_mempool_fee_rate: MIN_RELAY_FEE_RATE,
            transaction_count: mempool.len(),
        })
    }

    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        Ok(FeePolicySnapshot {
            policy_version: fee_policy::FEE_POLICY_VERSION,
            network: self.network(),
            min_relay_fee_rate: MIN_RELAY_FEE_RATE,
            min_mempool_fee_rate: MIN_RELAY_FEE_RATE,
            recommended_fee_rate: fee_policy::FeeRate::recommended()
                .map_err(Self::map_policy_error)?
                .noms_per_weight_unit,
            dust_threshold_noms: fee_policy::DUST_THRESHOLD_NOMS,
            max_tx_weight: u64::from(MAX_TX_WEIGHT),
            validity_horizon: None,
        })
    }

    fn transaction_weight(
        &self,
        shape: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError> {
        let weight = fee_policy::transaction_weight(Self::core_shape(shape))
            .map_err(Self::map_policy_error)?;
        Ok(Self::api_weight(weight))
    }

    fn minimum_fee(&self, shape: TransactionShape) -> Result<FeeBreakdown, WalletCoreError> {
        let breakdown =
            fee_policy::fee_breakdown(Self::core_shape(shape)).map_err(Self::map_policy_error)?;
        Ok(self.api_breakdown(breakdown))
    }

    fn estimate_fee(&self, request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        let breakdown = self.minimum_fee(request.shape)?;
        let (selected_fee_noms, selected_fee_rate) = match request.target {
            FeeEstimateTarget::Minimum => (breakdown.minimum_fee_noms, breakdown.minimum_fee_rate),
            FeeEstimateTarget::Recommended => (
                breakdown.recommended_fee_noms,
                breakdown.recommended_fee_rate,
            ),
        };
        Ok(FeeEstimate {
            breakdown,
            selected_fee_noms,
            selected_fee_rate,
        })
    }

    fn validate_fee(&self, transaction: &Transaction) -> Result<FeeValidation, WalletCoreError> {
        let fee = transaction.total_fee().map_err(Self::map_policy_error)?;
        let shape = transaction.fee_shape().map_err(Self::map_policy_error)?;
        let breakdown = fee_policy::fee_breakdown(shape).map_err(Self::map_policy_error)?;
        let api_breakdown = self.api_breakdown(breakdown);
        let accepted_by_policy = fee >= breakdown.minimum_fee_noms;
        let shortfall_noms = if accepted_by_policy {
            0
        } else {
            breakdown
                .minimum_fee_noms
                .checked_sub(fee)
                .ok_or_else(|| WalletCoreError::InternalFailure("fee shortfall underflow".into()))?
        };
        let actual_fee_rate = fee_policy::actual_fee_rate(fee, breakdown.weight.total_weight)
            .map_err(Self::map_policy_error)?;
        Ok(FeeValidation {
            accepted_by_policy,
            actual_fee_noms: fee,
            minimum_fee_noms: breakdown.minimum_fee_noms,
            shortfall_noms,
            actual_fee_rate: Self::api_fee_rate(actual_fee_rate),
            breakdown: api_breakdown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_config::{MinerThrottleConfig, NodeConfig};
    use dom_consensus::TransactionKernel;
    use dom_core::{Amount, KERNEL_FEAT_PLAIN};
    use dom_crypto::pedersen::Commitment;

    fn test_config(name: &str) -> NodeConfig {
        let dir = std::env::temp_dir().join(format!(
            "dom-wallet-core-api-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        NodeConfig {
            network: Network::Regtest,
            data_dir: dir.to_string_lossy().to_string(),
            p2p_listen_addr: "127.0.0.1:0".to_string(),
            max_inbound: 4,
            min_outbound: 0,
            dns_seeds: Vec::new(),
            disable_dns_seeds: true,
            seed_peers: Vec::new(),
            mine: false,
            miner_throttle: MinerThrottleConfig::default(),
            miner_threads: 1,
            miner_address: None,
            wallet_path: None,
            wallet_password: None,
            log_level: "debug".to_string(),
            rpc_listen_addr: None,
            rpc_bearer_token: None,
            metrics_listen_addr: None,
        }
    }

    fn api(name: &str) -> EmbeddedWalletCoreApi {
        let node = DomNode::init_with_map_size(test_config(name), 16 * 1024 * 1024)
            .expect("init test node");
        EmbeddedWalletCoreApi::new(Arc::new(node))
    }

    fn g_point() -> Commitment {
        Commitment::from_compressed_bytes(&[
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ])
        .expect("valid compressed G point")
    }

    fn fee_test_tx(fee: u64) -> Transaction {
        Transaction {
            inputs: Vec::new(),
            outputs: vec![dom_consensus::transaction::TransactionOutput {
                commitment: g_point(),
                proof: vec![0u8; 100],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).expect("fee"),
                lock_height: 0,
                excess: g_point(),
                excess_signature: [0u8; 65],
            }],
            offset: [0u8; 32],
        }
    }

    #[test]
    fn fee_policy_snapshot_is_network_bound_and_static() {
        let api = api("fee-policy");
        let snapshot = api.fee_policy().expect("fee policy");
        assert_eq!(snapshot.policy_version, fee_policy::FEE_POLICY_VERSION);
        assert_eq!(snapshot.network, CoreNetwork::Regtest);
        assert_eq!(snapshot.min_relay_fee_rate, MIN_RELAY_FEE_RATE);
        assert_eq!(snapshot.min_mempool_fee_rate, MIN_RELAY_FEE_RATE);
        assert_eq!(snapshot.validity_horizon, None);
        assert_eq!(snapshot.dust_threshold_noms, 0);
    }

    #[test]
    fn wallet_fee_estimate_matches_core_policy() {
        let api = api("fee-estimate");
        let shape = TransactionShape {
            input_count: 1,
            output_count: 1,
            kernel_count: 1,
        };
        let estimate = api
            .estimate_fee(FeeEstimateRequest {
                shape,
                target: FeeEstimateTarget::Recommended,
            })
            .expect("estimate");
        assert_eq!(estimate.breakdown.total_weight, 25);
        assert_eq!(estimate.breakdown.minimum_fee_noms, 25_000);
        assert_eq!(estimate.selected_fee_noms, 50_000);
        assert_eq!(
            estimate.breakdown.policy_version,
            fee_policy::FEE_POLICY_VERSION
        );
        assert_eq!(estimate.breakdown.network, CoreNetwork::Regtest);
    }

    #[test]
    fn wallet_fee_validation_reports_structured_shortfall() {
        let api = api("fee-validation");
        let shape = TransactionShape {
            input_count: 0,
            output_count: 1,
            kernel_count: 1,
        };
        let minimum = api.minimum_fee(shape).expect("minimum").minimum_fee_noms;
        let exact = api.validate_fee(&fee_test_tx(minimum)).expect("exact");
        assert!(exact.accepted_by_policy);
        assert_eq!(exact.shortfall_noms, 0);

        let low = api
            .validate_fee(&fee_test_tx(minimum - 1))
            .expect("low fee");
        assert!(!low.accepted_by_policy);
        assert_eq!(low.shortfall_noms, 1);
    }

    #[test]
    fn deterministic_fee_vectors_repeat_fifty_times() {
        let api = api("fee-repeat50");
        let request = FeeEstimateRequest {
            shape: TransactionShape {
                input_count: 2,
                output_count: 3,
                kernel_count: 1,
            },
            target: FeeEstimateTarget::Recommended,
        };
        for _ in 0..50 {
            let estimate = api.estimate_fee(request).expect("estimate");
            assert_eq!(estimate.breakdown.total_weight, 68);
            assert_eq!(estimate.breakdown.minimum_fee_noms, 68_000);
            assert_eq!(estimate.selected_fee_noms, 136_000);
        }
    }

    #[test]
    fn chain_identity_is_network_bound_and_stable() {
        let api = api("identity");
        let first = api.chain_identity().expect("identity");
        let second = api.chain_identity().expect("identity again");
        assert_eq!(first.network, CoreNetwork::Regtest);
        assert_eq!(first.network_magic, dom_core::NETWORK_MAGIC_REGTEST);
        assert_eq!(first.chain_id, second.chain_id);
        assert_eq!(first.genesis_hash, second.genesis_hash);
        assert_eq!(
            first.range_proof_serialization_version,
            dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION
        );
    }

    #[test]
    fn empty_pre_genesis_scan_is_deterministic() {
        let api = api("empty-scan");
        let identity = api.chain_identity().expect("identity");
        let request = ScanRequest {
            network: identity.network,
            chain_id: identity.chain_id,
            start: ScanStart::Height(0),
            max_blocks: 4,
            stop_height: Some(0),
            commitment_filters: Vec::new(),
        };
        let first = api.scan_range(request.clone()).expect("scan");
        let second = api.scan_range(request).expect("scan again");
        assert_eq!(first.blocks, second.blocks);
        assert_eq!(first.continuation, second.continuation);
    }

    #[test]
    fn cursor_rejected_on_another_chain_id() {
        let api = api("wrong-chain");
        let identity = api.chain_identity().expect("identity");
        let mut wrong_chain_id = identity.chain_id;
        wrong_chain_id[0] ^= 0x80;
        let cursor = WalletScanCursor::new(
            identity.network,
            wrong_chain_id,
            1,
            BlockRef {
                height: 0,
                hash: identity.current_tip.hash,
            },
        );
        assert!(matches!(
            api.validate_cursor(cursor),
            Err(WalletCoreError::CursorChainMismatch(_))
        ));
    }

    #[test]
    fn invalid_submission_returns_structured_rejection() {
        let api = api("invalid-submit");
        let result = api
            .submit_transaction(SubmitTransactionRequest {
                transaction: Transaction {
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    kernels: vec![TransactionKernel {
                        features: KERNEL_FEAT_PLAIN,
                        fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 1000).expect("fee"),
                        lock_height: 1,
                        excess: g_point(),
                        excess_signature: [0u8; 65],
                    }],
                    offset: [0u8; 32],
                },
            })
            .expect("submission result");
        assert_eq!(result.kind, SubmissionResultKind::RejectedInvalid);
        assert!(!result.accepted_to_mempool);
        assert!(!result.broadcast_attempted);
    }

    #[test]
    fn node_not_ready_is_structured_when_chain_lock_is_held() {
        let api = api("busy");
        let _chain_guard = api.node.chain.try_lock().expect("chain lock");
        let result = api
            .submit_transaction(SubmitTransactionRequest {
                transaction: Transaction {
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    kernels: Vec::new(),
                    offset: [0u8; 32],
                },
            })
            .expect("submission result");
        assert_eq!(result.kind, SubmissionResultKind::NodeNotReady);
    }

    #[test]
    fn cursor_and_scan_repeat_twenty_times() {
        let api = api("repeat20");
        let identity = api.chain_identity().expect("identity");
        for _ in 0..20 {
            let request = ScanRequest {
                network: identity.network,
                chain_id: identity.chain_id,
                start: ScanStart::Height(0),
                max_blocks: 1,
                stop_height: Some(0),
                commitment_filters: Vec::new(),
            };
            let result = api.scan_range(request).expect("scan");
            assert!(result.blocks.is_empty());
            assert!(result.continuation.is_none());
        }
    }
}

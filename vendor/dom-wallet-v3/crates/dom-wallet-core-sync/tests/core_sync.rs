use dom_consensus::{Block, Transaction, TransactionInput, TransactionKernel};
use dom_core::{Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_PLAIN};
use dom_serialization::DomSerialize;
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoinbaseScanMetadata, CoreNetwork,
    CursorValidation, FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeePolicySnapshot,
    FeeValidation, KernelQueryResult, MempoolPolicySnapshot, ScanBlock, ScanInput, ScanKernel,
    ScanOutput, ScanRequest, ScanResult, ScanStart, ScanTransaction, SubmissionResult,
    SubmitTransactionRequest, SyncStatus, TransactionIdentifier, TransactionLocation,
    TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult, WalletCoreApi,
    WalletCoreError, WalletScanCursor, WALLET_SCAN_CURSOR_LEN,
};
use dom_wallet_core_sync::{
    CoreBlockReference, CoreChainAdapter, CoreChainIdentity, CoreCursorBytes, CoreReconcileResult,
    CoreScanBatch, CoreScanError, CoreScanTransactionSink, PersistedCoreCursorState,
};
use dom_wallet_embedded_core::{
    EmbeddedCoreConfiguration, EmbeddedCoreLifecycle, EmbeddedCoreNetwork,
};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex, OnceLock},
};
use tempfile::TempDir;

#[derive(Clone)]
struct FakeCore {
    state: Arc<Mutex<FakeState>>,
}

struct FakeState {
    identity: ChainIdentity,
    blocks: Vec<ScanBlock>,
    mutation: Mutation,
    fail_scan_at_genesis: bool,
}

#[derive(Clone, Copy, Default)]
enum Mutation {
    #[default]
    None,
    Gap,
    Duplicate,
    Descending,
    PreviousHash,
    Noncanonical,
    Protocol,
    RangeProofVersion,
    ContinuationRegression,
    MissingContinuation,
    TipDisagreement,
    HeaderBytes,
    TransactionHash,
    TransactionBytes,
    TransactionProjection,
    FlatProjection,
}

impl FakeCore {
    fn new(block_count: u64) -> Self {
        assert!(block_count > 0, "fake canonical chain requires genesis");
        let mut blocks = Vec::with_capacity(block_count as usize);
        let mut previous_hash = [0u8; 32];
        for height in 0..block_count {
            let block = scan_block(height, previous_hash, height as u8 + 1);
            previous_hash = block.block_hash;
            blocks.push(block);
        }
        let tip = blocks.last().map_or(
            BlockRef {
                height: 0,
                hash: blocks[0].block_hash,
            },
            |block| BlockRef {
                height: block.height,
                hash: block.block_hash,
            },
        );
        Self {
            state: Arc::new(Mutex::new(FakeState {
                identity: ChainIdentity {
                    network: CoreNetwork::Regtest,
                    network_magic: CoreNetwork::Regtest.magic(),
                    chain_id: [8; 32],
                    genesis_hash: blocks[0].block_hash,
                    protocol_version: dom_core::PROTOCOL_VERSION,
                    range_proof_serialization_version:
                        dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
                    coinbase_maturity: 1,
                    current_tip: tip,
                },
                blocks,
                mutation: Mutation::None,
                fail_scan_at_genesis: false,
            })),
        }
    }

    fn adapter(&self) -> CoreChainAdapter {
        CoreChainAdapter::connect(Arc::new(self.clone()), None, 2, 8).expect("connect fake Core")
    }

    fn set_mutation(&self, mutation: Mutation) {
        self.state.lock().expect("fake state").mutation = mutation;
    }

    fn reject_genesis_scan(&self) {
        self.state.lock().expect("fake state").fail_scan_at_genesis = true;
    }

    fn block(&self, height: u64) -> ScanBlock {
        self.state.lock().expect("fake state").blocks[height as usize].clone()
    }

    fn mutate_identity(&self, change: impl FnOnce(&mut ChainIdentity)) {
        change(&mut self.state.lock().expect("fake state").identity);
    }

    fn use_mainnet_identity(&self) {
        self.mutate_identity(|identity| {
            identity.network = CoreNetwork::Mainnet;
            identity.network_magic = CoreNetwork::Mainnet.magic();
        });
    }

    fn replace_from(&self, height: u64, marker: u8) {
        let mut state = self.state.lock().expect("fake state");
        let previous = if height == 0 {
            [0; 32]
        } else {
            state.blocks[(height - 1) as usize].block_hash
        };
        let block_len = state.blocks.len();
        let mut previous_hash = previous;
        for index in height as usize..block_len {
            let replacement = scan_block(
                index as u64,
                previous_hash,
                marker.wrapping_add(index as u8),
            );
            previous_hash = replacement.block_hash;
            state.blocks[index] = replacement;
        }
        if height == 0 {
            state.identity.genesis_hash = state.blocks[0].block_hash;
        }
        state.identity.current_tip = BlockRef {
            height: state.blocks.last().expect("block").height,
            hash: state.blocks.last().expect("block").block_hash,
        };
    }

    fn truncate_to_height(&self, height: u64) {
        let mut state = self.state.lock().expect("fake state");
        state.blocks.truncate(height as usize + 1);
        let tip = state.blocks.last().expect("genesis remains");
        state.identity.current_tip = BlockRef {
            height: tip.height,
            hash: tip.block_hash,
        };
    }
}

impl WalletCoreApi for FakeCore {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        Ok(self.state.lock().expect("fake state").identity.clone())
    }

    fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        let state = self.state.lock().expect("fake state");
        if request.network != state.identity.network || request.chain_id != state.identity.chain_id
        {
            return Err(WalletCoreError::CursorChainMismatch("identity".into()));
        }
        if !request.commitment_filters.is_empty() {
            return Err(WalletCoreError::InvalidScanRequest("filtered".into()));
        }
        let start = match request.start {
            ScanStart::Height(height) => height,
            ScanStart::Cursor(cursor) => {
                validate_fake_cursor(&state, cursor)?;
                cursor.next_height
            }
        };
        if start == 0 && state.fail_scan_at_genesis {
            return Err(WalletCoreError::InternalFailure(
                "genesis is an anchor, not a wallet scan block".into(),
            ));
        }
        let end = start
            .saturating_add(request.max_blocks.saturating_sub(1))
            .min(state.identity.current_tip.height);
        let mut blocks: Vec<_> = if start > state.identity.current_tip.height {
            Vec::new()
        } else {
            state.blocks[start as usize..=end as usize].to_vec()
        };
        apply_mutation(&mut blocks, state.mutation);
        let mut continuation = blocks.last().and_then(|block| {
            (block.height < state.identity.current_tip.height).then(|| {
                WalletScanCursor::new(
                    state.identity.network,
                    state.identity.chain_id,
                    block.height + 1,
                    BlockRef {
                        height: block.height,
                        hash: block.block_hash,
                    },
                )
            })
        });
        match state.mutation {
            Mutation::ContinuationRegression => {
                if let Some(cursor) = &mut continuation {
                    cursor.anchor_height = cursor.anchor_height.saturating_sub(1);
                    cursor.next_height = cursor.anchor_height + 1;
                }
            }
            Mutation::MissingContinuation => continuation = None,
            _ => {}
        }
        let mut tip = state.identity.current_tip;
        if matches!(state.mutation, Mutation::TipDisagreement) {
            tip.hash = [0x77; 32];
        }
        Ok(ScanResult {
            tip,
            blocks,
            continuation,
        })
    }

    fn validate_cursor(
        &self,
        cursor: WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError> {
        let state = self.state.lock().expect("fake state");
        validate_fake_cursor(&state, cursor)?;
        Ok(CursorValidation {
            valid: true,
            safe_rescan_anchor: BlockRef {
                height: cursor.anchor_height,
                hash: cursor.anchor_hash,
            },
        })
    }

    fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        Ok(self
            .state
            .lock()
            .expect("fake state")
            .blocks
            .get(height as usize)
            .map(|block| block.block_hash))
    }

    fn get_utxo(&self, _: &[u8; 33]) -> Result<Option<UtxoQueryResult>, WalletCoreError> {
        Ok(None)
    }
    fn get_kernel(&self, _: &[u8; 33]) -> Result<Option<KernelQueryResult>, WalletCoreError> {
        Ok(None)
    }
    fn get_block_summary(&self, _: BlockSelector) -> Result<Option<BlockSummary>, WalletCoreError> {
        Ok(None)
    }
    fn transaction_status(
        &self,
        _: TransactionIdentifier,
    ) -> Result<TransactionStatus, WalletCoreError> {
        Ok(TransactionStatus::Unknown)
    }
    fn submit_transaction(
        &self,
        _: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn rebroadcast_transaction(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn query_submission(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        Ok(SyncStatus::Ready)
    }
    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        Ok(true)
    }
    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn transaction_weight(
        &self,
        _: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn minimum_fee(&self, _: TransactionShape) -> Result<FeeBreakdown, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn estimate_fee(&self, _: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn validate_fee(
        &self,
        _: &dom_consensus::Transaction,
    ) -> Result<FeeValidation, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
}

fn validate_fake_cursor(
    state: &FakeState,
    cursor: WalletScanCursor,
) -> Result<(), WalletCoreError> {
    cursor.validate_shape()?;
    if cursor.network_magic != state.identity.network_magic
        || cursor.chain_id != state.identity.chain_id
    {
        return Err(WalletCoreError::CursorChainMismatch("identity".into()));
    }
    if state
        .blocks
        .get(cursor.anchor_height as usize)
        .map(|block| block.block_hash)
        != Some(cursor.anchor_hash)
    {
        return Err(WalletCoreError::CursorReorg("anchor".into()));
    }
    Ok(())
}

fn apply_mutation(blocks: &mut [ScanBlock], mutation: Mutation) {
    match mutation {
        Mutation::Gap if blocks.len() > 1 => blocks[1].height += 1,
        Mutation::Duplicate if blocks.len() > 1 => blocks[1].height = blocks[0].height,
        Mutation::Descending if blocks.len() > 1 => blocks.swap(0, 1),
        Mutation::PreviousHash if !blocks.is_empty() => blocks[0].previous_block_hash = [0x66; 32],
        Mutation::Noncanonical if !blocks.is_empty() => blocks[0].canonical_marker = [0x66; 32],
        Mutation::Protocol if !blocks.is_empty() => blocks[0].protocol_version += 1,
        Mutation::RangeProofVersion if !blocks.is_empty() => {
            blocks[0].range_proof_serialization_version += 1;
        }
        Mutation::HeaderBytes if !blocks.is_empty() => blocks[0].canonical_header_bytes[0] ^= 1,
        Mutation::TransactionHash if !blocks.is_empty() => {
            blocks[0].transactions[0].tx_hash[0] ^= 1
        }
        Mutation::TransactionBytes if !blocks.is_empty() => {
            blocks[0].transactions[0].canonical_bytes.push(0)
        }
        Mutation::TransactionProjection if !blocks.is_empty() => {
            blocks[0].transactions[0].kernels[0].excess_signature[0] ^= 1
        }
        Mutation::FlatProjection if !blocks.is_empty() => {
            blocks[0].kernels.pop();
        }
        _ => {}
    }
}

fn canonical_genesis_template() -> &'static Block {
    static GENESIS: OnceLock<Block> = OnceLock::new();
    GENESIS.get_or_init(|| {
        dom_chain::build_canonical_genesis(CoreNetwork::Regtest.magic(), &[8; 32])
            .expect("regtest genesis")
            .block
            .expect("regtest has a canonical block")
    })
}

fn scan_output(
    output: &dom_consensus::TransactionOutput,
    is_coinbase: bool,
    block_height: u64,
    block_hash: [u8; 32],
    output_position: u32,
) -> ScanOutput {
    let capsule = output.recovery_capsule().expect("capsule envelope");
    ScanOutput {
        commitment: *output.commitment.as_bytes(),
        range_proof: output
            .range_proof_bytes()
            .expect("range proof envelope")
            .to_vec(),
        recovery_capsule: capsule
            .as_ref()
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default(),
        recovery_version: capsule.as_ref().map_or(0, |value| value.version()),
        is_coinbase,
        block_height,
        block_hash,
        output_position,
    }
}

fn scan_block(height: u64, previous_hash: [u8; 32], marker: u8) -> ScanBlock {
    let mut canonical = canonical_genesis_template().clone();
    let mut offset = [0u8; 32];
    offset[31] = marker.max(1);
    let transaction = Transaction {
        inputs: vec![TransactionInput {
            commitment: canonical.coinbase.output.commitment.clone(),
        }],
        outputs: vec![canonical.coinbase.output.clone()],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(height).expect("fee"),
            lock_height: height,
            excess: canonical.coinbase.kernel.excess.clone(),
            excess_signature: [marker.wrapping_add(60); 65],
        }],
        offset,
    };
    canonical.header.version =
        dom_core::required_block_version_for_network(CoreNetwork::Regtest.magic(), height);
    canonical.header.height = BlockHeight(height);
    canonical.header.prev_hash = Hash256::from_bytes(previous_hash);
    canonical.header.timestamp = Timestamp(1_700_000_000 + height + u64::from(marker));
    canonical.header.total_kernel_offset = offset;
    canonical.header.pow.nonce = u64::from(marker);
    canonical.transactions = vec![transaction.clone()];
    let (output_root, kernel_root, rangeproof_root) = dom_consensus::compute_block_pmmr_roots(
        BlockHeight(height),
        &canonical.coinbase,
        &canonical.transactions,
    )
    .expect("canonical body roots");
    canonical.header.output_root = output_root;
    canonical.header.kernel_root = kernel_root;
    canonical.header.rangeproof_root = rangeproof_root;
    let canonical_header_bytes = canonical.header.to_bytes().expect("canonical header");
    let hash = *dom_chain::canonical_header_identifier(
        CoreNetwork::Regtest.magic(),
        &canonical_header_bytes,
    )
    .expect("canonical header id")
    .as_bytes();
    let transaction_bytes = transaction.to_bytes().expect("canonical transaction");
    let transaction_kernel = &transaction.kernels[0];
    let coinbase_output = scan_output(&canonical.coinbase.output, true, height, hash, 0);
    let transaction_output = scan_output(&transaction.outputs[0], false, height, hash, 1);
    let coinbase_kernel = ScanKernel {
        excess: *canonical.coinbase.kernel.excess.as_bytes(),
        features: canonical.coinbase.kernel.features,
        fee: 0,
        lock_height: 0,
        excess_signature: canonical.coinbase.kernel.excess_signature,
    };
    let transaction_kernel = ScanKernel {
        excess: *transaction_kernel.excess.as_bytes(),
        features: transaction_kernel.features,
        fee: transaction_kernel.fee.noms(),
        lock_height: transaction_kernel.lock_height,
        excess_signature: transaction_kernel.excess_signature,
    };
    ScanBlock {
        height,
        block_hash: hash,
        previous_block_hash: previous_hash,
        canonical_header_bytes,
        timestamp: canonical.header.timestamp.0,
        canonical_marker: hash,
        outputs: vec![coinbase_output, transaction_output.clone()],
        inputs: vec![ScanInput {
            spent_commitment: *transaction.inputs[0].commitment.as_bytes(),
        }],
        kernels: vec![coinbase_kernel, transaction_kernel.clone()],
        transactions: vec![ScanTransaction {
            location: TransactionLocation {
                block_height: height,
                block_hash: hash,
                transaction_index: 0,
            },
            tx_hash: *dom_crypto::blake2b_256(&transaction_bytes).as_bytes(),
            canonical_bytes: transaction_bytes,
            inputs: vec![ScanInput {
                spent_commitment: *transaction.inputs[0].commitment.as_bytes(),
            }],
            outputs: vec![transaction_output],
            kernels: vec![transaction_kernel],
            offset,
        }],
        coinbase: CoinbaseScanMetadata {
            output_commitment: *canonical.coinbase.output.commitment.as_bytes(),
            explicit_value: canonical.coinbase.kernel.explicit_value,
            kernel_excess: *canonical.coinbase.kernel.excess.as_bytes(),
            kernel_features: canonical.coinbase.kernel.features,
            kernel_excess_signature: canonical.coinbase.kernel.excess_signature,
            offset: canonical.coinbase.offset,
            output_proof_envelope: canonical.coinbase.output.proof.clone(),
        },
        total_fees_noms: canonical.total_fees().expect("total fees"),
        protocol_version: dom_core::required_block_version_for_network(
            CoreNetwork::Regtest.magic(),
            height,
        ),
        range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
    }
}

#[derive(Default)]
struct MemorySink {
    cursor: PersistedCoreCursorState,
    hashes: BTreeMap<u64, [u8; 32]>,
    fail_commit: bool,
    normal_commits: usize,
    reorg_commits: usize,
}

impl CoreScanTransactionSink for MemorySink {
    type Error = ();

    fn core_cursor_state(&self) -> Result<PersistedCoreCursorState, Self::Error> {
        Ok(self.cursor.clone())
    }

    fn committed_canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, Self::Error> {
        Ok(self.hashes.get(&height).copied())
    }

    fn commit_core_batch(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error> {
        if self.fail_commit {
            return Err(());
        }
        for block in &batch.blocks {
            self.hashes.insert(block.height, block.block_hash);
        }
        self.cursor = PersistedCoreCursorState::Valid(cursor);
        self.normal_commits += 1;
        Ok(())
    }

    fn commit_core_reorg(
        &mut self,
        safe_anchor: CoreBlockReference,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error> {
        if self.fail_commit {
            return Err(());
        }
        self.hashes
            .retain(|height, _| *height <= safe_anchor.height);
        for block in &batch.blocks {
            self.hashes.insert(block.height, block.block_hash);
        }
        self.cursor = PersistedCoreCursorState::Valid(cursor);
        self.reorg_commits += 1;
        Ok(())
    }
}

fn first_cursor(core: &FakeCore) -> CoreCursorBytes {
    core.adapter()
        .scan_from_height(0, 2)
        .expect("initial scan")
        .commit_cursor
        .expect("cursor")
}

#[test]
fn cursor_is_exactly_86_bytes_and_round_trips() {
    let core = FakeCore::new(4);
    let cursor = first_cursor(&core);
    assert_eq!(cursor.as_bytes().len(), WALLET_SCAN_CURSOR_LEN);
    assert_eq!(
        CoreCursorBytes::parse(cursor.as_bytes(), core.adapter().identity()),
        Ok(cursor)
    );
}

#[test]
fn cursor_decodes_version_one() {
    assert_eq!(first_cursor(&FakeCore::new(4)).decode().unwrap().version, 1);
}

#[test]
fn cursor_fields_use_little_endian_vectors() {
    let cursor = first_cursor(&FakeCore::new(4));
    let bytes = cursor.as_bytes();
    assert_eq!(&bytes[0..2], &1u16.to_le_bytes());
    assert_eq!(&bytes[2..6], &CoreNetwork::Regtest.magic().to_le_bytes());
    assert_eq!(&bytes[38..46], &2u64.to_le_bytes());
    assert_eq!(&bytes[46..54], &1u64.to_le_bytes());
}

#[test]
fn cursor_rejects_wrong_size() {
    let adapter = FakeCore::new(2).adapter();
    assert!(matches!(
        CoreCursorBytes::parse(&[0; 85], adapter.identity()),
        Err(CoreScanError::InvalidCursor { .. })
    ));
}

#[test]
fn cursor_rejects_wrong_version() {
    let core = FakeCore::new(2);
    let adapter = core.adapter();
    let mut bytes = first_cursor(&core).as_bytes().to_vec();
    bytes[0..2].copy_from_slice(&2u16.to_le_bytes());
    assert!(CoreCursorBytes::parse(&bytes, adapter.identity()).is_err());
}

#[test]
fn cursor_rejects_network_mismatch() {
    let core = FakeCore::new(2);
    let adapter = core.adapter();
    let mut bytes = first_cursor(&core).as_bytes().to_vec();
    bytes[2..6].copy_from_slice(&CoreNetwork::Testnet.magic().to_le_bytes());
    assert!(matches!(
        CoreCursorBytes::parse(&bytes, adapter.identity()),
        Err(CoreScanError::CursorIdentityMismatch)
    ));
}

#[test]
fn cursor_rejects_chain_id_mismatch() {
    let core = FakeCore::new(2);
    let adapter = core.adapter();
    let mut bytes = first_cursor(&core).as_bytes().to_vec();
    bytes[6] ^= 1;
    assert!(matches!(
        CoreCursorBytes::parse(&bytes, adapter.identity()),
        Err(CoreScanError::CursorIdentityMismatch)
    ));
}

#[test]
fn cursor_rejects_next_anchor_inconsistency() {
    let core = FakeCore::new(2);
    let adapter = core.adapter();
    let mut bytes = first_cursor(&core).as_bytes().to_vec();
    bytes[38..46].copy_from_slice(&9u64.to_le_bytes());
    assert!(CoreCursorBytes::parse(&bytes, adapter.identity()).is_err());
}

#[test]
fn cursor_rejects_zero_anchor_hash() {
    let core = FakeCore::new(2);
    let adapter = core.adapter();
    let mut bytes = first_cursor(&core).as_bytes().to_vec();
    bytes[54..86].fill(0);
    assert!(CoreCursorBytes::parse(&bytes, adapter.identity()).is_err());
}

#[test]
fn identity_mapping_is_complete_and_network_bound() {
    let core = FakeCore::new(2);
    let expected_genesis = core.block(0).block_hash;
    let adapter = core.adapter();
    let identity = adapter.identity();
    assert_eq!(identity.network_magic, CoreNetwork::Regtest.magic());
    assert_eq!(identity.chain_id, [8; 32]);
    assert_eq!(identity.genesis_hash, expected_genesis);
    assert_eq!(identity.protocol_version, dom_core::PROTOCOL_VERSION);
    assert_eq!(identity.coinbase_maturity, 1);
}

#[test]
fn identity_mismatch_fails_closed() {
    let core = FakeCore::new(2);
    let mut expected: CoreChainIdentity = core.adapter().identity().clone();
    expected.chain_id[0] ^= 1;
    assert!(matches!(
        CoreChainAdapter::connect(Arc::new(core), Some(&expected), 2, 8),
        Err(CoreScanError::IdentityMismatch { .. })
    ));
}

#[test]
fn unsupported_protocol_identity_fails_closed() {
    let core = FakeCore::new(2);
    core.mutate_identity(|identity| identity.protocol_version += 1);
    assert!(matches!(
        CoreChainAdapter::connect(Arc::new(core), None, 2, 8),
        Err(CoreScanError::InvalidIdentity { .. })
    ));
}

#[test]
fn initial_scan_is_unfiltered_and_starts_at_genesis() {
    let batch = FakeCore::new(4).adapter().scan_from_height(0, 2).unwrap();
    assert_eq!(
        batch
            .blocks
            .iter()
            .map(|block| block.height)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
}

#[test]
fn scan_continuation_starts_after_anchor() {
    let core = FakeCore::new(4);
    let adapter = core.adapter();
    let next = adapter.scan_next(first_cursor(&core), 2).unwrap();
    assert_eq!(
        next.blocks
            .iter()
            .map(|block| block.height)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
}

#[test]
fn scan_rejects_height_gap() {
    reject_mutation(Mutation::Gap);
}

#[test]
fn scan_rejects_duplicate_height() {
    reject_mutation(Mutation::Duplicate);
}

#[test]
fn scan_rejects_descending_blocks() {
    reject_mutation(Mutation::Descending);
}

#[test]
fn scan_rejects_previous_hash_mismatch() {
    reject_mutation(Mutation::PreviousHash);
}

#[test]
fn scan_rejects_noncanonical_marker() {
    reject_mutation(Mutation::Noncanonical);
}

#[test]
fn scan_rejects_unsupported_protocol_version() {
    reject_mutation(Mutation::Protocol);
}

#[test]
fn scan_rejects_unsupported_range_proof_version() {
    reject_mutation(Mutation::RangeProofVersion);
}

#[test]
fn scan_rejects_noncanonical_header_bytes() {
    reject_mutation(Mutation::HeaderBytes);
}

#[test]
fn scan_rejects_transaction_hash_mismatch() {
    reject_mutation(Mutation::TransactionHash);
}

#[test]
fn scan_rejects_noncanonical_transaction_bytes() {
    reject_mutation(Mutation::TransactionBytes);
}

#[test]
fn scan_rejects_transaction_projection_mismatch() {
    reject_mutation(Mutation::TransactionProjection);
}

#[test]
fn scan_rejects_flat_projection_mismatch() {
    reject_mutation(Mutation::FlatProjection);
}

#[test]
fn scan_rejects_continuation_regression() {
    reject_mutation(Mutation::ContinuationRegression);
}

#[test]
fn scan_rejects_missing_continuation_before_tip() {
    reject_mutation(Mutation::MissingContinuation);
}

#[test]
fn scan_rejects_canonical_tip_disagreement() {
    reject_mutation(Mutation::TipDisagreement);
}

fn reject_mutation(mutation: Mutation) {
    let core = FakeCore::new(4);
    core.set_mutation(mutation);
    assert!(matches!(
        core.adapter().scan_from_height(0, 2),
        Err(CoreScanError::InvalidScan { .. })
            | Err(CoreScanError::InvalidCursor { .. })
            | Err(CoreScanError::ReorgDetected)
    ));
}

#[test]
fn proof_and_capsule_bytes_are_preserved() {
    let core = FakeCore::new(2);
    let expected = core.block(0).outputs[0].clone();
    let batch = core.adapter().scan_from_height(0, 2).unwrap();
    let output = &batch.blocks[0].outputs[0];
    assert_eq!(output.range_proof, expected.range_proof);
    assert_eq!(output.recovery_capsule, expected.recovery_capsule);
}

#[test]
fn full_fidelity_scriptless_evidence_is_preserved() {
    let core = FakeCore::new(2);
    let expected = core.block(0);
    let batch = core.adapter().scan_from_height(0, 2).unwrap();
    let block = &batch.blocks[0];
    assert_eq!(
        block.canonical_header_bytes,
        expected.canonical_header_bytes
    );
    assert_eq!(block.kernels[1].excess_signature, [61; 65]);
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(
        block.transactions[0].canonical_bytes,
        expected.transactions[0].canonical_bytes
    );
    assert_eq!(block.transactions[0].kernels[0].excess_signature, [61; 65]);
    assert_eq!(
        block.coinbase.kernel_excess_signature,
        expected.coinbase.kernel_excess_signature
    );
    assert_eq!(
        block.coinbase.output_proof_envelope,
        expected.coinbase.output_proof_envelope
    );
}

#[test]
fn persisted_cursor_restarts_scan() {
    let core = FakeCore::new(4);
    let cursor = first_cursor(&core);
    let adapter = core.adapter();
    assert_eq!(adapter.scan_next(cursor, 2).unwrap().blocks[0].height, 2);
}

#[test]
fn stale_cursor_is_detected() {
    let core = FakeCore::new(4);
    let cursor = first_cursor(&core);
    core.replace_from(1, 30);
    assert_eq!(
        core.adapter().validate_cursor(cursor),
        Err(CoreScanError::ReorgDetected)
    );
}

#[test]
fn same_height_reorg_is_detected() {
    let core = FakeCore::new(4);
    let cursor = core
        .adapter()
        .scan_from_height(0, 2)
        .unwrap()
        .commit_cursor
        .unwrap();
    core.replace_from(1, 40);
    assert_eq!(
        core.adapter().validate_cursor(cursor),
        Err(CoreScanError::ReorgDetected)
    );
}

#[test]
fn bounded_deep_reorg_rewinds_and_commits_replacement_atomically() {
    let core = FakeCore::new(4);
    let adapter = core.adapter();
    let mut sink = MemorySink::default();
    adapter.reconcile_once(&mut sink).unwrap();
    adapter.reconcile_once(&mut sink).unwrap();
    core.replace_from(2, 50);
    let result = adapter.reconcile_once(&mut sink).unwrap();
    assert!(matches!(
        result,
        CoreReconcileResult::ReorgCommitted {
            safe_anchor: CoreBlockReference { height: 1, .. },
            ..
        }
    ));
    assert_eq!(sink.reorg_commits, 1);
}

#[test]
fn reorg_beyond_bound_fails_closed() {
    let core = FakeCore::new(4);
    let adapter = CoreChainAdapter::connect(Arc::new(core.clone()), None, 2, 1).unwrap();
    let mut sink = MemorySink::default();
    adapter.reconcile_once(&mut sink).unwrap();
    adapter.reconcile_once(&mut sink).unwrap();
    core.replace_from(2, 60);
    assert_eq!(
        adapter.reconcile_once(&mut sink),
        Err(CoreScanError::ReorgBeyondBound)
    );
}

#[test]
fn cursor_ahead_of_tip_rewinds_atomically_to_the_common_ancestor() {
    let core = FakeCore::new(5);
    let adapter = core.adapter();
    let mut sink = MemorySink::default();
    adapter.reconcile_to_tip(&mut sink).unwrap();
    core.truncate_to_height(2);

    let result = adapter.reconcile_to_tip(&mut sink).unwrap();

    assert!(matches!(
        result,
        CoreReconcileResult::ReorgCommitted {
            safe_anchor: CoreBlockReference { height: 2, .. },
            ..
        }
    ));
    let PersistedCoreCursorState::Valid(cursor) = sink.cursor else {
        panic!("missing rewound cursor");
    };
    let cursor = cursor.decode().unwrap();
    assert_eq!(cursor.anchor_height, 2);
    assert_eq!(cursor.anchor_hash, core.block(2).block_hash);
    assert_eq!(sink.hashes.keys().copied().collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn second_sync_at_the_same_height_and_hash_is_idempotent() {
    let core = FakeCore::new(5);
    let adapter = core.adapter();
    let mut sink = MemorySink::default();
    adapter.reconcile_to_tip(&mut sink).unwrap();
    let cursor = sink.cursor.clone();
    let hashes = sink.hashes.clone();
    let normal_commits = sink.normal_commits;

    assert_eq!(
        adapter.reconcile_to_tip(&mut sink),
        Ok(CoreReconcileResult::NoChanges)
    );
    assert_eq!(sink.cursor, cursor);
    assert_eq!(sink.hashes, hashes);
    assert_eq!(sink.normal_commits, normal_commits);
}

#[test]
fn interrupted_commit_does_not_publish_cursor() {
    let core = FakeCore::new(4);
    let mut sink = MemorySink {
        fail_commit: true,
        ..MemorySink::default()
    };
    assert_eq!(
        core.adapter().reconcile_once(&mut sink),
        Err(CoreScanError::Persistence)
    );
    assert_eq!(sink.cursor, PersistedCoreCursorState::Absent);
    assert!(sink.hashes.is_empty());
}

#[test]
fn state_and_cursor_commit_together() {
    let mut sink = MemorySink::default();
    let result = FakeCore::new(4)
        .adapter()
        .reconcile_once(&mut sink)
        .unwrap();
    assert!(matches!(result, CoreReconcileResult::Committed(_)));
    assert_eq!(sink.hashes.len(), 2);
    assert!(matches!(sink.cursor, PersistedCoreCursorState::Valid(_)));
}

#[test]
fn missing_cursor_genesis_only_initializes_height_zero() {
    let core = FakeCore::new(1);
    let adapter = core.adapter();
    let mut sink = MemorySink::default();

    adapter.reconcile_to_tip(&mut sink).unwrap();

    let PersistedCoreCursorState::Valid(cursor) = sink.cursor else {
        panic!("missing persisted cursor");
    };
    let cursor = cursor.decode().unwrap();
    assert_eq!(cursor.anchor_height, 0);
    assert_eq!(cursor.anchor_hash, core.block(0).block_hash);
    assert!(sink.hashes.is_empty());
}

#[test]
fn missing_cursor_scans_existing_height_one() {
    let core = FakeCore::new(2);
    core.reject_genesis_scan();
    let adapter = core.adapter();
    let mut sink = MemorySink::default();

    adapter.reconcile_to_tip(&mut sink).unwrap();

    let PersistedCoreCursorState::Valid(cursor) = sink.cursor else {
        panic!("missing persisted cursor");
    };
    let cursor = cursor.decode().unwrap();
    assert_eq!(cursor.anchor_height, 1);
    let height_one_hash = core.block(1).block_hash;
    assert_eq!(cursor.anchor_hash, height_one_hash);
    assert_eq!(sink.hashes, BTreeMap::from([(1, height_one_hash)]));
}

#[test]
fn mainnet_missing_cursor_rejects_genesis_mismatch() {
    let core = FakeCore::new(2);
    core.use_mainnet_identity();
    core.mutate_identity(|identity| identity.genesis_hash = [9; 32]);
    let adapter = core.adapter();
    let mut sink = MemorySink::default();

    assert_eq!(
        adapter.reconcile_to_tip(&mut sink),
        Err(CoreScanError::InvalidScan {
            code: "GENESIS_HASH_DISAGREEMENT"
        })
    );
    assert_eq!(sink.cursor, PersistedCoreCursorState::Absent);
}

#[test]
fn complete_wallet_scan_is_success() {
    let core = FakeCore::new(2);
    let adapter = core.adapter();
    let mut sink = MemorySink::default();

    adapter.reconcile_to_tip(&mut sink).unwrap();

    let PersistedCoreCursorState::Valid(cursor) = sink.cursor else {
        panic!("missing persisted cursor");
    };
    assert_eq!(cursor.decode().unwrap().anchor_height, 1);
}

#[test]
fn missing_cursor_reconciles_every_existing_page_to_tip() {
    let core = FakeCore::new(5);
    core.reject_genesis_scan();
    let adapter = core.adapter();
    let mut sink = MemorySink::default();

    adapter.reconcile_to_tip(&mut sink).unwrap();

    let PersistedCoreCursorState::Valid(cursor) = sink.cursor else {
        panic!("missing persisted cursor");
    };
    assert_eq!(cursor.decode().unwrap().anchor_height, 4);
    assert_eq!(
        sink.hashes.keys().copied().collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
}

#[test]
fn duplicate_page_is_deterministic_without_implicit_overlap() {
    let core = FakeCore::new(4);
    let adapter = core.adapter();
    let first = adapter.scan_from_height(0, 2).unwrap();
    let duplicate = adapter.scan_from_height(0, 2).unwrap();
    assert_eq!(first, duplicate);
}

#[test]
fn real_embedded_core_identity_scan_and_cursor_validation() {
    let directory = TempDir::new().expect("temporary data directory");
    let address = unused_loopback_address();
    let configuration =
        EmbeddedCoreConfiguration::new(EmbeddedCoreNetwork::Regtest, directory.path(), address);
    let mut lifecycle = EmbeddedCoreLifecycle::new(configuration);
    lifecycle.start().expect("start isolated Core");
    let adapter = CoreChainAdapter::connect(lifecycle.wallet_api().unwrap(), None, 8, 8).unwrap();

    assert_eq!(adapter.identity().network, CoreNetwork::Regtest);
    let batch = adapter.scan_from_height(0, 8).expect("scan genesis");
    let cursor = batch.commit_cursor.expect("tip-anchored cursor");
    assert_eq!(adapter.validate_cursor(cursor).unwrap().height, 0);

    lifecycle.request_shutdown().unwrap();
    lifecycle.wait_for_shutdown().unwrap();
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    address
}

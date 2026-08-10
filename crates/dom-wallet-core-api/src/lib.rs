//! Final embedded Core <-> Wallet API for Wallet V3.
//!
//! This crate defines the stable Rust contract between an embedded DOM node and
//! wallet code. It deliberately contains no wallet state, no business logic, no
//! LMDB handles, no `ChainState` handles, and no peer/mempool task channels.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use dom_consensus::transaction::Transaction;
use thiserror::Error;

/// Current scanner cursor wire version.
pub const WALLET_SCAN_CURSOR_VERSION: u16 = 1;

/// Current scanner cursor serialized byte length.
pub const WALLET_SCAN_CURSOR_LEN: usize = 2 + 4 + 32 + 8 + 8 + 32;

/// Wallet-facing network identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreNetwork {
    /// Mainnet.
    Mainnet,
    /// Testnet.
    Testnet,
    /// Local regtest.
    Regtest,
}

impl CoreNetwork {
    /// Stable lowercase network name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }

    /// Network magic bytes.
    pub fn magic(self) -> u32 {
        match self {
            Self::Mainnet => dom_core::NETWORK_MAGIC_MAINNET,
            Self::Testnet => dom_core::NETWORK_MAGIC_TESTNET,
            Self::Regtest => dom_core::NETWORK_MAGIC_REGTEST,
        }
    }

    /// Convert network magic to a wallet API network.
    pub fn from_magic(magic: u32) -> Result<Self, WalletCoreError> {
        match magic {
            dom_core::NETWORK_MAGIC_MAINNET => Ok(Self::Mainnet),
            dom_core::NETWORK_MAGIC_TESTNET => Ok(Self::Testnet),
            dom_core::NETWORK_MAGIC_REGTEST => Ok(Self::Regtest),
            other => Err(WalletCoreError::InternalFailure(format!(
                "unknown network magic 0x{other:08x}"
            ))),
        }
    }
}

/// Chain identity and tip status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainIdentity {
    /// Network.
    pub network: CoreNetwork,
    /// Network magic.
    pub network_magic: u32,
    /// Consensus chain id.
    pub chain_id: [u8; 32],
    /// Startup genesis hash for this network.
    pub genesis_hash: [u8; 32],
    /// Consensus protocol version.
    pub protocol_version: u32,
    /// Range-proof serialization version.
    pub range_proof_serialization_version: u8,
    /// Coinbase maturity for this network.
    pub coinbase_maturity: u64,
    /// Current canonical tip.
    pub current_tip: BlockRef,
}

/// Canonical block reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub hash: [u8; 32],
}

/// Cursor-bound scan starting point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStart {
    /// Start from an explicit height.
    Height(u64),
    /// Continue from a validated cursor.
    Cursor(WalletScanCursor),
}

/// Canonical scan request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    /// Network expected by the wallet.
    pub network: CoreNetwork,
    /// Chain id expected by the wallet.
    pub chain_id: [u8; 32],
    /// Start height or cursor.
    pub start: ScanStart,
    /// Maximum number of blocks to return.
    pub max_blocks: u64,
    /// Optional inclusive stop height.
    pub stop_height: Option<u64>,
    /// Optional commitment filters. Empty means return all outputs.
    pub commitment_filters: Vec<[u8; 33]>,
}

/// Versioned, restart-safe scanner cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletScanCursor {
    /// Cursor format version.
    pub version: u16,
    /// Network magic this cursor belongs to.
    pub network_magic: u32,
    /// Chain id this cursor belongs to.
    pub chain_id: [u8; 32],
    /// Next height the wallet must request.
    pub next_height: u64,
    /// Height of the canonical anchor hash.
    pub anchor_height: u64,
    /// Canonical hash at `anchor_height`.
    pub anchor_hash: [u8; 32],
}

impl WalletScanCursor {
    /// Construct a version 1 cursor.
    pub fn new(
        network: CoreNetwork,
        chain_id: [u8; 32],
        next_height: u64,
        anchor: BlockRef,
    ) -> Self {
        Self {
            version: WALLET_SCAN_CURSOR_VERSION,
            network_magic: network.magic(),
            chain_id,
            next_height,
            anchor_height: anchor.height,
            anchor_hash: anchor.hash,
        }
    }

    /// Deterministic binary serialization.
    pub fn to_bytes(self) -> [u8; WALLET_SCAN_CURSOR_LEN] {
        let mut out = [0u8; WALLET_SCAN_CURSOR_LEN];
        out[0..2].copy_from_slice(&self.version.to_le_bytes());
        out[2..6].copy_from_slice(&self.network_magic.to_le_bytes());
        out[6..38].copy_from_slice(&self.chain_id);
        out[38..46].copy_from_slice(&self.next_height.to_le_bytes());
        out[46..54].copy_from_slice(&self.anchor_height.to_le_bytes());
        out[54..86].copy_from_slice(&self.anchor_hash);
        out
    }

    /// Parse a deterministic binary cursor.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletCoreError> {
        if bytes.len() != WALLET_SCAN_CURSOR_LEN {
            return Err(WalletCoreError::MalformedCursor(format!(
                "cursor length {} != {}",
                bytes.len(),
                WALLET_SCAN_CURSOR_LEN
            )));
        }
        let version = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let network_magic = u32::from_le_bytes(bytes[2..6].try_into().unwrap());
        let mut chain_id = [0u8; 32];
        chain_id.copy_from_slice(&bytes[6..38]);
        let next_height = u64::from_le_bytes(bytes[38..46].try_into().unwrap());
        let anchor_height = u64::from_le_bytes(bytes[46..54].try_into().unwrap());
        let mut anchor_hash = [0u8; 32];
        anchor_hash.copy_from_slice(&bytes[54..86]);
        let cursor = Self {
            version,
            network_magic,
            chain_id,
            next_height,
            anchor_height,
            anchor_hash,
        };
        cursor.validate_shape()?;
        Ok(cursor)
    }

    /// Validate cursor format and monotonic shape, independent of chain state.
    pub fn validate_shape(self) -> Result<(), WalletCoreError> {
        if self.version != WALLET_SCAN_CURSOR_VERSION {
            return Err(WalletCoreError::MalformedCursor(format!(
                "unsupported cursor version {}",
                self.version
            )));
        }
        CoreNetwork::from_magic(self.network_magic)?;
        if self.next_height != self.anchor_height.saturating_add(1) {
            return Err(WalletCoreError::MalformedCursor(
                "cursor next_height must equal anchor_height + 1".into(),
            ));
        }
        Ok(())
    }
}

/// Canonical scan response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Current tip observed while scanning.
    pub tip: BlockRef,
    /// Returned blocks.
    pub blocks: Vec<ScanBlock>,
    /// Continuation cursor when more scanning can continue.
    pub continuation: Option<WalletScanCursor>,
}

/// Reorg-safe block projection for wallets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBlock {
    /// Height.
    pub height: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// Previous block hash.
    pub previous_block_hash: [u8; 32],
    /// Block timestamp.
    pub timestamp: u64,
    /// Canonical continuity marker.
    pub canonical_marker: [u8; 32],
    /// Outputs created by this block.
    pub outputs: Vec<ScanOutput>,
    /// Inputs spent by this block.
    pub inputs: Vec<ScanInput>,
    /// Kernels in this block.
    pub kernels: Vec<ScanKernel>,
    /// Coinbase metadata.
    pub coinbase: CoinbaseScanMetadata,
    /// Total transaction fees in noms.
    pub total_fees_noms: u64,
    /// Protocol version.
    pub protocol_version: u32,
    /// Range-proof serialization version.
    pub range_proof_serialization_version: u8,
}

/// Output projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutput {
    /// Output commitment.
    pub commitment: [u8; 33],
    /// Immutable proof bytes.
    pub range_proof: Vec<u8>,
    /// Immutable authenticated recovery capsule bytes. Empty only for a legacy
    /// protocol/test output that Wallet V3 must not claim as recoverable.
    pub recovery_capsule: Vec<u8>,
    /// Recovery capsule version, or zero when no capsule is present.
    pub recovery_version: u16,
    /// Whether this output is the block coinbase output.
    pub is_coinbase: bool,
    /// Block height.
    pub block_height: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// Canonical output position within the block projection.
    pub output_position: u32,
}

/// Input projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanInput {
    /// Spent commitment.
    pub spent_commitment: [u8; 33],
}

/// Kernel projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanKernel {
    /// Kernel excess.
    pub excess: [u8; 33],
    /// Kernel features byte.
    pub features: u8,
    /// Fee in noms.
    pub fee: u64,
    /// Absolute lock height.
    pub lock_height: u64,
}

/// Coinbase metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseScanMetadata {
    /// Coinbase output commitment.
    pub output_commitment: [u8; 33],
    /// Explicit coinbase value in noms.
    pub explicit_value: u64,
    /// Coinbase kernel excess.
    pub kernel_excess: [u8; 33],
}

/// UTXO query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtxoQueryResult {
    /// Commitment.
    pub commitment: [u8; 33],
    /// Block height.
    pub block_height: u64,
    /// Whether it is coinbase.
    pub is_coinbase: bool,
    /// Whether it is mature at the current tip.
    pub is_mature: bool,
}

/// Kernel query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelQueryResult {
    /// Kernel excess.
    pub excess: [u8; 33],
    /// Canonical block containing the kernel.
    pub block: BlockRef,
}

/// Block query selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSelector {
    /// By height.
    Height(u64),
    /// By hash.
    Hash([u8; 32]),
}

/// Block summary for wallets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    /// Block reference.
    pub block: BlockRef,
    /// Previous hash.
    pub previous_block_hash: [u8; 32],
    /// Timestamp.
    pub timestamp: u64,
    /// Output count including coinbase.
    pub output_count: u32,
    /// Input count.
    pub input_count: u32,
    /// Kernel count including coinbase.
    pub kernel_count: u32,
    /// Total fees.
    pub total_fees_noms: u64,
}

/// Stable transaction identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionIdentifier {
    /// Transaction hash.
    TxHash([u8; 32]),
    /// Kernel excess.
    KernelExcess([u8; 33]),
}

/// Transaction status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Unknown to the node.
    Unknown,
    /// Accepted in mempool.
    InMempool,
    /// Confirmed in canonical chain.
    Confirmed(BlockRef),
}

/// Transaction submission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitTransactionRequest {
    /// Transaction.
    pub transaction: Transaction,
}

/// Stable submission outcome categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionResultKind {
    /// Accepted into the local mempool.
    Accepted,
    /// Already known to the mempool or chain index.
    AlreadyKnown,
    /// Consensus-invalid or malformed transaction.
    RejectedInvalid,
    /// Rejected for fee policy.
    RejectedFee,
    /// Rejected because an input is already spent or reserved.
    RejectedDoubleSpend,
    /// Rejected because a coinbase input is immature.
    RejectedImmatureCoinbase,
    /// Rejected because a time or lock condition is not yet met.
    RejectedExpired,
    /// Rejected by other local policy.
    RejectedPolicy,
    /// Node is not ready to serve wallet operations.
    NodeNotReady,
    /// Retryable temporary failure.
    TemporaryFailure,
    /// Internal failure.
    InternalFailure,
}

/// Transaction submission result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionResult {
    /// Stable category.
    pub kind: SubmissionResultKind,
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Primary kernel excess, when available.
    pub primary_kernel_excess: Option<[u8; 33]>,
    /// Whether the transaction was accepted into the mempool.
    pub accepted_to_mempool: bool,
    /// Whether broadcast was attempted.
    pub broadcast_attempted: bool,
    /// Whether any relay subscriber accepted the broadcast.
    pub relayed: bool,
    /// Stable diagnostic code.
    pub diagnostic: Option<SubmissionDiagnostic>,
}

/// Stable diagnostic code for submission failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionDiagnostic {
    /// Invalid encoding or consensus syntax.
    Invalid,
    /// Fee below relay floor.
    FeeTooLow,
    /// Input double-spent or already reserved.
    DoubleSpend,
    /// Coinbase input is immature.
    ImmatureCoinbase,
    /// Lock height or temporal condition not satisfied.
    Locked,
    /// Already known.
    AlreadyKnown,
    /// Node lock or sync state is busy.
    NodeBusy,
    /// Other policy rejection.
    Policy,
    /// Internal failure.
    Internal,
}

/// Node sync status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    /// Ready.
    Ready,
    /// Starting up.
    Starting,
    /// Syncing.
    Syncing,
    /// Busy with a local operation.
    Busy,
}

/// Final fee policy version exposed to Wallet V3.
pub type FeePolicyVersion = u16;

/// Stable wallet-facing fee rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeRate {
    /// Noms per transaction weight unit.
    pub noms_per_weight_unit: u64,
}

/// Wallet-facing transaction shape for fee queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionShape {
    /// Number of inputs.
    pub input_count: u32,
    /// Number of outputs.
    pub output_count: u32,
    /// Number of kernels.
    pub kernel_count: u32,
}

/// Wallet-facing transaction weight breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionWeight {
    /// Weight contributed by inputs.
    pub input_weight: u64,
    /// Weight contributed by outputs.
    pub output_weight: u64,
    /// Weight contributed by kernels.
    pub kernel_weight: u64,
    /// Total transaction weight.
    pub total_weight: u64,
}

/// Fee estimate target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeEstimateTarget {
    /// Minimum relay and mempool admission fee.
    Minimum,
    /// Static recommended wallet fee.
    Recommended,
}

/// Wallet fee estimate request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimateRequest {
    /// Transaction shape.
    pub shape: TransactionShape,
    /// Requested estimate target.
    pub target: FeeEstimateTarget,
}

/// Complete wallet-facing fee calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBreakdown {
    /// Input count.
    pub input_count: u32,
    /// Output count.
    pub output_count: u32,
    /// Kernel count.
    pub kernel_count: u32,
    /// Weight contributed by inputs.
    pub input_weight: u64,
    /// Weight contributed by outputs.
    pub output_weight: u64,
    /// Weight contributed by kernels.
    pub kernel_weight: u64,
    /// Total transaction weight.
    pub total_weight: u64,
    /// Minimum acceptable fee in noms.
    pub minimum_fee_noms: u64,
    /// Recommended fee in noms.
    pub recommended_fee_noms: u64,
    /// Minimum fee rate.
    pub minimum_fee_rate: FeeRate,
    /// Recommended fee rate.
    pub recommended_fee_rate: FeeRate,
    /// Fee policy version.
    pub policy_version: FeePolicyVersion,
    /// Network the estimate is bound to.
    pub network: CoreNetwork,
    /// Optional validity horizon for dynamic policies. `None` means static.
    pub validity_horizon: Option<u64>,
    /// Dust threshold in noms.
    pub dust_threshold_noms: u64,
}

/// Wallet fee estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    /// Complete calculation.
    pub breakdown: FeeBreakdown,
    /// Fee selected for the requested target.
    pub selected_fee_noms: u64,
    /// Fee rate selected for the requested target.
    pub selected_fee_rate: FeeRate,
}

/// Wallet-facing fee validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeValidation {
    /// Whether the fee meets relay and mempool policy.
    pub accepted_by_policy: bool,
    /// Actual transaction fee in noms.
    pub actual_fee_noms: u64,
    /// Minimum acceptable fee in noms.
    pub minimum_fee_noms: u64,
    /// Fee shortfall in noms.
    pub shortfall_noms: u64,
    /// Actual fee rate.
    pub actual_fee_rate: FeeRate,
    /// Full policy breakdown.
    pub breakdown: FeeBreakdown,
}

/// Mempool policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolPolicySnapshot {
    /// Fee policy version.
    pub policy_version: FeePolicyVersion,
    /// Network the policy is bound to.
    pub network: CoreNetwork,
    /// Minimum relay fee rate.
    pub min_relay_fee_rate: u64,
    /// Minimum mempool admission fee rate.
    pub min_mempool_fee_rate: u64,
    /// Current accepted transaction count.
    pub transaction_count: usize,
}

/// Fee policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicySnapshot {
    /// Fee policy version.
    pub policy_version: FeePolicyVersion,
    /// Network the policy is bound to.
    pub network: CoreNetwork,
    /// Minimum relay fee rate.
    pub min_relay_fee_rate: u64,
    /// Minimum mempool admission fee rate.
    pub min_mempool_fee_rate: u64,
    /// Recommended fee rate.
    pub recommended_fee_rate: u64,
    /// Dust threshold in noms.
    pub dust_threshold_noms: u64,
    /// Maximum transaction weight.
    pub max_tx_weight: u64,
    /// Optional validity horizon for dynamic policies. `None` means static.
    pub validity_horizon: Option<u64>,
}

/// Reorg-safe cursor validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorValidation {
    /// Cursor is valid on the current canonical chain.
    pub valid: bool,
    /// Safe rescan anchor.
    pub safe_rescan_anchor: BlockRef,
}

/// Canonical embedded node API consumed by Wallet V3.
pub trait WalletCoreApi {
    /// Return chain identity and current tip.
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError>;

    /// Scan a canonical range.
    fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError>;

    /// Continue from a cursor.
    fn scan_next(
        &self,
        cursor: WalletScanCursor,
        limit: u64,
    ) -> Result<ScanResult, WalletCoreError> {
        let identity = self.chain_identity()?;
        self.scan_range(ScanRequest {
            network: identity.network,
            chain_id: identity.chain_id,
            start: ScanStart::Cursor(cursor),
            max_blocks: limit,
            stop_height: None,
            commitment_filters: Vec::new(),
        })
    }

    /// Validate a cursor against the current canonical chain.
    fn validate_cursor(
        &self,
        cursor: WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError>;

    /// Get canonical hash at a height.
    fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError>;

    /// Get UTXO by commitment.
    fn get_utxo(&self, commitment: &[u8; 33]) -> Result<Option<UtxoQueryResult>, WalletCoreError>;

    /// Get kernel by excess.
    fn get_kernel(&self, excess: &[u8; 33]) -> Result<Option<KernelQueryResult>, WalletCoreError>;

    /// Get block summary by height or hash.
    fn get_block_summary(
        &self,
        selector: BlockSelector,
    ) -> Result<Option<BlockSummary>, WalletCoreError>;

    /// Query transaction status.
    fn transaction_status(
        &self,
        id: TransactionIdentifier,
    ) -> Result<TransactionStatus, WalletCoreError>;

    /// Submit transaction through the canonical node admission and relay path.
    fn submit_transaction(
        &self,
        request: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError>;

    /// Rebroadcast a known transaction.
    fn rebroadcast_transaction(
        &self,
        id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError>;

    /// Query a prior submission.
    fn query_submission(
        &self,
        id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError>;

    /// Current sync status.
    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError>;

    /// Whether wallet operations are currently ready.
    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError>;

    /// Mempool policy snapshot.
    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError>;

    /// Fee policy snapshot.
    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError>;

    /// Current fee policy snapshot.
    fn fee_policy(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        self.fee_policy_snapshot()
    }

    /// Calculate transaction weight for a wallet-provided shape.
    fn transaction_weight(
        &self,
        shape: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError>;

    /// Calculate the minimum acceptable fee for a wallet-provided shape.
    fn minimum_fee(&self, shape: TransactionShape) -> Result<FeeBreakdown, WalletCoreError>;

    /// Estimate fee for a wallet-provided request.
    fn estimate_fee(&self, request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError>;

    /// Validate the fee of a concrete transaction.
    fn validate_fee(&self, transaction: &Transaction) -> Result<FeeValidation, WalletCoreError>;

    /// Recommended fee for a wallet-provided request.
    fn recommended_fee(&self, request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        self.estimate_fee(FeeEstimateRequest {
            target: FeeEstimateTarget::Recommended,
            ..request
        })
    }
}

/// Structured API errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WalletCoreError {
    /// Cursor is malformed.
    #[error("malformed cursor: {0}")]
    MalformedCursor(String),
    /// Cursor belongs to another network or chain.
    #[error("cursor chain mismatch: {0}")]
    CursorChainMismatch(String),
    /// Cursor was validly formed but no longer matches the canonical chain.
    #[error("cursor reorg detected: {0}")]
    CursorReorg(String),
    /// Scan request is invalid.
    #[error("invalid scan request: {0}")]
    InvalidScanRequest(String),
    /// Canonical height gap.
    #[error("canonical gap: {0}")]
    CanonicalGap(String),
    /// Node is not ready.
    #[error("node not ready: {0}")]
    NodeNotReady(String),
    /// Transaction was rejected.
    #[error("transaction rejected: {0:?}")]
    SubmissionRejected(SubmissionResultKind),
    /// Temporary failure.
    #[error("temporary failure: {0}")]
    TemporaryFailure(String),
    /// Internal failure.
    #[error("internal failure: {0}")]
    InternalFailure(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor() -> WalletScanCursor {
        WalletScanCursor::new(
            CoreNetwork::Regtest,
            [0x11; 32],
            8,
            BlockRef {
                height: 7,
                hash: [0x22; 32],
            },
        )
    }

    #[test]
    fn cursor_serialization_is_deterministic_and_restart_safe() {
        let c = cursor();
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), WALLET_SCAN_CURSOR_LEN);
        assert_eq!(WalletScanCursor::from_bytes(&bytes).unwrap(), c);
        assert_eq!(
            WalletScanCursor::from_bytes(&bytes).unwrap().to_bytes(),
            bytes
        );
    }

    #[test]
    fn cursor_rejects_wrong_length() {
        let err = WalletScanCursor::from_bytes(&[0u8; 12]).unwrap_err();
        assert!(matches!(err, WalletCoreError::MalformedCursor(_)));
    }

    #[test]
    fn cursor_rejects_wrong_version() {
        let mut bytes = cursor().to_bytes();
        bytes[0..2].copy_from_slice(&99u16.to_le_bytes());
        let err = WalletScanCursor::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, WalletCoreError::MalformedCursor(_)));
    }

    #[test]
    fn cursor_rejects_gaps() {
        let mut c = cursor();
        c.next_height = 9;
        let err = c.validate_shape().unwrap_err();
        assert!(matches!(err, WalletCoreError::MalformedCursor(_)));
    }

    #[test]
    fn deterministic_cursor_repeat_20() {
        let c = cursor();
        let expected = c.to_bytes();
        for _ in 0..20 {
            assert_eq!(c.to_bytes(), expected);
            assert_eq!(WalletScanCursor::from_bytes(&expected).unwrap(), c);
        }
    }
}

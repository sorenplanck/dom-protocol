//! Wallet-owned validation and persistence boundary for canonical Core scans.

#![forbid(unsafe_code)]

use dom_consensus::{
    Block, BlockHeader, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionOutput,
};
use dom_crypto::pedersen::Commitment;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet_core_api::{
    BlockRef, ChainIdentity, CoinbaseScanMetadata, CoreNetwork, CursorValidation, ScanBlock,
    ScanInput, ScanKernel, ScanOutput, ScanRequest, ScanResult, ScanStart, ScanTransaction,
    TransactionLocation, WalletCoreApi, WalletCoreError, WalletScanCursor, WALLET_SCAN_CURSOR_LEN,
    WALLET_SCAN_CURSOR_VERSION,
};
use std::{fmt, sync::Arc};
use thiserror::Error;

/// Conservative maximum number of blocks accepted in one Wallet-side batch.
pub const MAX_CORE_SCAN_BATCH_BLOCKS: u64 = 1_024;

/// Wallet-owned chain identity copied from the frozen Core contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreChainIdentity {
    /// Core network.
    pub network: CoreNetwork,
    /// Network magic.
    pub network_magic: u32,
    /// Consensus chain identifier.
    pub chain_id: [u8; 32],
    /// Genesis block hash.
    pub genesis_hash: [u8; 32],
    /// Consensus protocol version.
    pub protocol_version: u32,
    /// Range-proof serialization version.
    pub range_proof_serialization_version: u8,
    /// Coinbase maturity.
    pub coinbase_maturity: u64,
    /// Current canonical tip.
    pub current_tip: CoreBlockReference,
}

/// Wallet-owned canonical block reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreBlockReference {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub hash: [u8; 32],
}

impl From<BlockRef> for CoreBlockReference {
    fn from(value: BlockRef) -> Self {
        Self {
            height: value.height,
            hash: value.hash,
        }
    }
}

/// Exact canonical bytes of a frozen WalletScanCursor v1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreCursorBytes([u8; WALLET_SCAN_CURSOR_LEN]);

impl CoreCursorBytes {
    /// Parse bytes with the frozen Core decoder and bind them to an identity.
    pub fn parse(bytes: &[u8], identity: &CoreChainIdentity) -> Result<Self, CoreScanError> {
        let cursor = WalletScanCursor::from_bytes(bytes).map_err(CoreScanError::from_core)?;
        validate_cursor_identity(&cursor, identity)?;
        let canonical = cursor.to_bytes();
        Ok(Self(canonical))
    }

    fn from_cursor(
        cursor: WalletScanCursor,
        identity: &CoreChainIdentity,
    ) -> Result<Self, CoreScanError> {
        cursor.validate_shape().map_err(CoreScanError::from_core)?;
        validate_cursor_identity(&cursor, identity)?;
        Ok(Self(cursor.to_bytes()))
    }

    /// Return the exact 86 persisted bytes.
    pub fn as_bytes(&self) -> &[u8; WALLET_SCAN_CURSOR_LEN] {
        &self.0
    }

    /// Decode with the frozen Core decoder.
    pub fn decode(&self) -> Result<WalletScanCursor, CoreScanError> {
        WalletScanCursor::from_bytes(&self.0).map_err(CoreScanError::from_core)
    }
}

impl fmt::Debug for CoreCursorBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreCursorBytes")
            .field("length", &WALLET_SCAN_CURSOR_LEN)
            .finish_non_exhaustive()
    }
}

/// Durable Core cursor state. Legacy custom cursors remain outside this field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PersistedCoreCursorState {
    /// No Core scan has committed yet.
    #[default]
    Absent,
    /// Exact frozen Core cursor bytes.
    Valid(CoreCursorBytes),
    /// Persisted bytes failed canonical decoding or identity validation.
    Invalid,
    /// A previously valid cursor was invalidated by a canonical reorganization.
    ReorgInvalidated(CoreCursorBytes),
}

/// Wallet-owned output projection. Proof and capsule bytes remain public data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanOutput {
    /// Output commitment.
    pub commitment: [u8; 33],
    /// Exact 739-byte range proof.
    pub range_proof: Vec<u8>,
    /// Exact public recovery capsule bytes.
    pub recovery_capsule: Vec<u8>,
    /// Recovery capsule version.
    pub recovery_version: u16,
    /// Coinbase marker.
    pub is_coinbase: bool,
    /// Containing block height.
    pub block_height: u64,
    /// Containing block hash.
    pub block_hash: [u8; 32],
    /// Canonical output position in the block projection.
    pub output_position: u32,
}

/// Wallet-owned input projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreScanInput {
    /// Spent commitment.
    pub spent_commitment: [u8; 33],
}

/// Wallet-owned kernel projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanKernel {
    /// Kernel excess.
    pub excess: [u8; 33],
    /// Kernel feature byte.
    pub features: u8,
    /// Fee in noms.
    pub fee: u64,
    /// Absolute lock height.
    pub lock_height: u64,
    /// Exact final DOM Schnorr signature retained for Scriptless evidence.
    pub excess_signature: [u8; 65],
}

/// Wallet-owned coinbase metadata projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreCoinbaseMetadata {
    /// Coinbase output commitment.
    pub output_commitment: [u8; 33],
    /// Explicit coinbase value.
    pub explicit_value: u64,
    /// Coinbase kernel excess.
    pub kernel_excess: [u8; 33],
    /// Coinbase kernel feature byte.
    pub kernel_features: u8,
    /// Exact coinbase kernel signature.
    pub kernel_excess_signature: [u8; 65],
    /// Canonical coinbase transaction offset.
    pub offset: [u8; 32],
    /// Exact coinbase output proof envelope.
    pub output_proof_envelope: Vec<u8>,
}

impl From<CoinbaseScanMetadata> for CoreCoinbaseMetadata {
    fn from(value: CoinbaseScanMetadata) -> Self {
        Self {
            output_commitment: value.output_commitment,
            explicit_value: value.explicit_value,
            kernel_excess: value.kernel_excess,
            kernel_features: value.kernel_features,
            kernel_excess_signature: value.kernel_excess_signature,
            offset: value.offset,
            output_proof_envelope: value.output_proof_envelope,
        }
    }
}

/// Fully validated canonical block projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanBlock {
    /// Height.
    pub height: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// Previous block hash.
    pub previous_block_hash: [u8; 32],
    /// Exact canonical header bytes authenticated by `block_hash`.
    pub canonical_header_bytes: Vec<u8>,
    /// Timestamp.
    pub timestamp: u64,
    /// Canonical marker supplied by Core.
    pub canonical_marker: [u8; 32],
    /// Outputs.
    pub outputs: Vec<CoreScanOutput>,
    /// Inputs.
    pub inputs: Vec<CoreScanInput>,
    /// Kernels.
    pub kernels: Vec<CoreScanKernel>,
    /// Full canonical non-coinbase transactions in block order.
    pub transactions: Vec<ScanTransaction>,
    /// Coinbase metadata.
    pub coinbase: CoreCoinbaseMetadata,
    /// Total fees.
    pub total_fees_noms: u64,
    /// Protocol version.
    pub protocol_version: u32,
    /// Range-proof serialization version.
    pub range_proof_serialization_version: u8,
}

/// One validated scan page and the cursor that may be committed with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanBatch {
    /// Core tip observed for this scan.
    pub observed_tip: CoreBlockReference,
    /// Ascending contiguous canonical blocks.
    pub blocks: Vec<CoreScanBlock>,
    /// Exact cursor bytes. Present whenever at least one block was returned.
    pub commit_cursor: Option<CoreCursorBytes>,
}

/// Result of one atomic reconciliation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreReconcileResult {
    /// No canonical blocks were available to commit.
    NoChanges,
    /// A normal page and cursor committed atomically.
    Committed(CoreCursorBytes),
    /// A reorg rewind, replacement page, and cursor committed atomically.
    ReorgCommitted {
        /// Last locally known anchor that still matches Core.
        safe_anchor: CoreBlockReference,
        /// Replacement cursor.
        cursor: CoreCursorBytes,
    },
}

/// Durable transaction boundary implemented by Wallet state/storage integration.
///
/// Implementations must apply all effects represented by a batch and publish
/// the supplied cursor in one atomic durable transaction. The legacy custom
/// cursor must not be synthesized into or deleted by this interface.
pub trait CoreScanTransactionSink {
    /// Storage-specific error.
    type Error;

    /// Load the separately versioned Core cursor state.
    fn core_cursor_state(&self) -> Result<PersistedCoreCursorState, Self::Error>;

    /// Return a previously committed canonical hash for bounded reorg search.
    fn committed_canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, Self::Error>;

    /// Atomically apply a normal batch and publish its exact cursor bytes.
    fn commit_core_batch(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error>;

    /// Atomically rewind to `safe_anchor`, apply replacement blocks, and publish
    /// the replacement cursor.
    fn commit_core_reorg(
        &mut self,
        safe_anchor: CoreBlockReference,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error>;
}

/// Typed failures at the Wallet/Core identity and canonical-scan boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreScanError {
    /// Core identity is malformed or unsupported.
    #[error("invalid Core chain identity ({code})")]
    InvalidIdentity { code: &'static str },
    /// Persisted identity conflicts with Core.
    #[error("Core chain identity mismatch ({code})")]
    IdentityMismatch { code: &'static str },
    /// Cursor bytes or shape are invalid.
    #[error("invalid Core cursor ({code})")]
    InvalidCursor { code: &'static str },
    /// Cursor belongs to another network or chain.
    #[error("Core cursor identity mismatch")]
    CursorIdentityMismatch,
    /// Cursor anchor is no longer canonical.
    #[error("Core cursor was invalidated by a reorganization")]
    ReorgDetected,
    /// A scan page violates canonical ordering or continuity.
    #[error("invalid canonical scan page ({code})")]
    InvalidScan { code: &'static str },
    /// Scan request exceeds the Wallet-side bound.
    #[error("invalid scan limit")]
    InvalidScanLimit,
    /// No matching local/Core anchor was found inside the configured bound.
    #[error("reorganization exceeds the configured reconciliation bound")]
    ReorgBeyondBound,
    /// Core is temporarily unavailable.
    #[error("Core is not ready")]
    CoreNotReady,
    /// Core returned a stable contract failure.
    #[error("Core scan contract failed ({code})")]
    CoreContract { code: &'static str },
    /// Wallet persistence failed. No storage text crosses this boundary.
    #[error("Wallet scan transaction failed")]
    Persistence,
}

impl CoreScanError {
    fn from_core(error: WalletCoreError) -> Self {
        match error {
            WalletCoreError::MalformedCursor(_) => Self::InvalidCursor {
                code: "MALFORMED_CURSOR",
            },
            WalletCoreError::CursorChainMismatch(_) => Self::CursorIdentityMismatch,
            WalletCoreError::CursorReorg(_) => Self::ReorgDetected,
            WalletCoreError::CanonicalGap(_) => Self::InvalidScan {
                code: "CANONICAL_GAP",
            },
            WalletCoreError::InvalidScanRequest(_) => Self::InvalidScan {
                code: "REQUEST_REJECTED",
            },
            WalletCoreError::NodeNotReady(_) | WalletCoreError::TemporaryFailure(_) => {
                Self::CoreNotReady
            }
            WalletCoreError::InternalFailure(_) => Self::CoreContract {
                code: "CORE_INTERNAL_FAILURE",
            },
            WalletCoreError::SubmissionRejected(_) => Self::CoreContract {
                code: "UNEXPECTED_SUBMISSION_FAILURE",
            },
        }
    }
}

/// Wallet-owned orchestrator over the frozen WalletCoreApi scanner contract.
pub struct CoreChainAdapter {
    api: Arc<dyn WalletCoreApi + Send + Sync>,
    identity: CoreChainIdentity,
    maximum_batch_blocks: u64,
    maximum_reorg_depth: u64,
}

impl fmt::Debug for CoreChainAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreChainAdapter")
            .field("identity", &self.identity)
            .field("maximum_batch_blocks", &self.maximum_batch_blocks)
            .field("maximum_reorg_depth", &self.maximum_reorg_depth)
            .finish_non_exhaustive()
    }
}

impl CoreChainAdapter {
    /// Bind a Wallet scan session to Core identity and optional persisted identity.
    pub fn connect(
        api: Arc<dyn WalletCoreApi + Send + Sync>,
        persisted_identity: Option<&CoreChainIdentity>,
        maximum_batch_blocks: u64,
        maximum_reorg_depth: u64,
    ) -> Result<Self, CoreScanError> {
        validate_scan_limit(maximum_batch_blocks)?;
        let identity = map_identity(api.chain_identity().map_err(CoreScanError::from_core)?)?;
        if let Some(expected) = persisted_identity {
            validate_same_chain(expected, &identity)?;
        }
        Ok(Self {
            api,
            identity,
            maximum_batch_blocks,
            maximum_reorg_depth,
        })
    }

    /// Return the identity that binds this session.
    pub fn identity(&self) -> &CoreChainIdentity {
        &self.identity
    }

    /// Refresh current tip while requiring all immutable identity fields to match.
    pub fn current_identity(&self) -> Result<CoreChainIdentity, CoreScanError> {
        let current = map_identity(
            self.api
                .chain_identity()
                .map_err(CoreScanError::from_core)?,
        )?;
        validate_same_chain(&self.identity, &current)?;
        Ok(current)
    }

    /// Return the current canonical tip through Core identity.
    pub fn current_tip(&self) -> Result<CoreBlockReference, CoreScanError> {
        Ok(self.current_identity()?.current_tip)
    }

    /// Start an unfiltered canonical scan at an explicit height.
    pub fn scan_from_height(
        &self,
        start_height: u64,
        limit: u64,
    ) -> Result<CoreScanBatch, CoreScanError> {
        self.check_limit(limit)?;
        let identity = self.current_identity()?;
        let result = self
            .api
            .scan_range(ScanRequest {
                network: identity.network,
                chain_id: identity.chain_id,
                start: ScanStart::Height(start_height),
                max_blocks: limit,
                stop_height: None,
                commitment_filters: Vec::new(),
            })
            .map_err(CoreScanError::from_core)?;
        self.validate_and_map(result, start_height, None, &identity)
    }

    /// Continue an unfiltered scan from exact persisted cursor bytes.
    pub fn scan_next(
        &self,
        cursor_bytes: CoreCursorBytes,
        limit: u64,
    ) -> Result<CoreScanBatch, CoreScanError> {
        self.check_limit(limit)?;
        let identity = self.current_identity()?;
        let cursor = cursor_bytes.decode()?;
        validate_cursor_identity(&cursor, &identity)?;
        self.validate_cursor(cursor_bytes)?;
        let result = self
            .api
            .scan_next(cursor, limit)
            .map_err(CoreScanError::from_core)?;
        self.validate_and_map(
            result,
            cursor.next_height,
            Some(CoreBlockReference {
                height: cursor.anchor_height,
                hash: cursor.anchor_hash,
            }),
            &identity,
        )
    }

    /// Validate exact cursor bytes against current canonical Core state.
    pub fn validate_cursor(
        &self,
        cursor_bytes: CoreCursorBytes,
    ) -> Result<CoreBlockReference, CoreScanError> {
        let cursor = cursor_bytes.decode()?;
        validate_cursor_identity(&cursor, &self.identity)?;
        let validation = self
            .api
            .validate_cursor(cursor)
            .map_err(CoreScanError::from_core)?;
        validate_cursor_result(cursor, validation)
    }

    /// Look up the canonical hash at a height through Core.
    pub fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, CoreScanError> {
        self.api
            .canonical_hash_at_height(height)
            .map_err(CoreScanError::from_core)
    }

    /// Validate, scan, and atomically commit one normal or reorg page.
    pub fn reconcile_once<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        match sink
            .core_cursor_state()
            .map_err(|_| CoreScanError::Persistence)?
        {
            PersistedCoreCursorState::Absent => {
                let batch = self.scan_from_height(0, self.maximum_batch_blocks)?;
                self.commit_normal(sink, batch)
            }
            PersistedCoreCursorState::Valid(cursor) => match self.validate_cursor(cursor) {
                Ok(_) => {
                    let batch = self.scan_next(cursor, self.maximum_batch_blocks)?;
                    self.commit_normal(sink, batch)
                }
                Err(CoreScanError::ReorgDetected) => self.reconcile_reorg(sink, cursor),
                Err(error) => Err(error),
            },
            PersistedCoreCursorState::ReorgInvalidated(cursor) => {
                self.reconcile_reorg(sink, cursor)
            }
            PersistedCoreCursorState::Invalid => Err(CoreScanError::InvalidCursor {
                code: "PERSISTED_CURSOR_INVALID",
            }),
        }
    }

    /// Bootstrap a missing production Wallet cursor from the canonical genesis anchor.
    pub fn reconcile_wallet_once<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        if !matches!(
            sink.core_cursor_state()
                .map_err(|_| CoreScanError::Persistence)?,
            PersistedCoreCursorState::Absent
        ) {
            return self.reconcile_once(sink);
        }
        let identity = self.current_identity()?;
        let genesis_hash = self
            .canonical_hash_at_height(0)?
            .ok_or(CoreScanError::InvalidScan {
                code: "MISSING_CANONICAL_GENESIS",
            })?;
        if identity.network == CoreNetwork::Mainnet && genesis_hash != identity.genesis_hash {
            return Err(CoreScanError::InvalidScan {
                code: "GENESIS_HASH_DISAGREEMENT",
            });
        }
        let batch = if identity.current_tip.height == 0 {
            if genesis_hash != identity.current_tip.hash {
                return Err(CoreScanError::InvalidScan {
                    code: "TIP_GENESIS_DISAGREEMENT",
                });
            }
            let cursor = WalletScanCursor::new(
                identity.network,
                identity.chain_id,
                1,
                BlockRef {
                    height: 0,
                    hash: identity.current_tip.hash,
                },
            );
            let cursor = CoreCursorBytes::from_cursor(cursor, &identity)?;
            self.validate_cursor(cursor)?;
            CoreScanBatch {
                observed_tip: identity.current_tip,
                blocks: Vec::new(),
                commit_cursor: Some(cursor),
            }
        } else {
            self.scan_from_height(1, self.maximum_batch_blocks)?
        };
        self.commit_normal(sink, batch)
    }

    /// Reconcile canonical pages until the committed cursor reaches the observed tip.
    pub fn reconcile_to_tip<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        loop {
            let result = self.reconcile_wallet_once(sink)?;
            let cursor = match sink
                .core_cursor_state()
                .map_err(|_| CoreScanError::Persistence)?
            {
                PersistedCoreCursorState::Valid(cursor) => cursor,
                PersistedCoreCursorState::Absent => {
                    return Err(CoreScanError::InvalidScan {
                        code: "SCAN_STALLED_WITHOUT_CURSOR",
                    });
                }
                PersistedCoreCursorState::Invalid => {
                    return Err(CoreScanError::InvalidCursor {
                        code: "PERSISTED_CURSOR_INVALID",
                    });
                }
                PersistedCoreCursorState::ReorgInvalidated(_) => {
                    return Err(CoreScanError::ReorgDetected);
                }
            };
            let anchor = self.validate_cursor(cursor)?;
            let current_tip = self.current_tip()?;
            if anchor == current_tip {
                return Ok(result);
            }
            if matches!(result, CoreReconcileResult::NoChanges) {
                return Err(CoreScanError::InvalidScan {
                    code: "SCAN_STALLED_BEFORE_TARGET",
                });
            }
        }
    }

    fn commit_normal<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
        batch: CoreScanBatch,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        let Some(cursor) = batch.commit_cursor else {
            return Ok(CoreReconcileResult::NoChanges);
        };
        sink.commit_core_batch(&batch, cursor)
            .map_err(|_| CoreScanError::Persistence)?;
        Ok(CoreReconcileResult::Committed(cursor))
    }

    fn reconcile_reorg<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
        invalid_cursor: CoreCursorBytes,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        let cursor = invalid_cursor.decode()?;
        let safe_anchor = self.find_safe_anchor(sink, cursor.anchor_height)?;
        let start_height =
            safe_anchor
                .height
                .checked_add(1)
                .ok_or(CoreScanError::InvalidCursor {
                    code: "ANCHOR_HEIGHT_OVERFLOW",
                })?;
        let batch = self.scan_from_height(start_height, self.maximum_batch_blocks)?;
        let replacement = match batch.commit_cursor {
            Some(replacement) => replacement,
            None if batch.observed_tip == safe_anchor => {
                let cursor = WalletScanCursor::new(
                    self.identity.network,
                    self.identity.chain_id,
                    safe_anchor
                        .height
                        .checked_add(1)
                        .ok_or(CoreScanError::InvalidCursor {
                            code: "ANCHOR_HEIGHT_OVERFLOW",
                        })?,
                    BlockRef {
                        height: safe_anchor.height,
                        hash: safe_anchor.hash,
                    },
                );
                let replacement = CoreCursorBytes::from_cursor(cursor, &self.identity)?;
                self.validate_cursor(replacement)?;
                replacement
            }
            None => {
                return Err(CoreScanError::InvalidScan {
                    code: "REORG_REPLACEMENT_EMPTY",
                });
            }
        };
        sink.commit_core_reorg(safe_anchor, &batch, replacement)
            .map_err(|_| CoreScanError::Persistence)?;
        Ok(CoreReconcileResult::ReorgCommitted {
            safe_anchor,
            cursor: replacement,
        })
    }

    fn find_safe_anchor<S: CoreScanTransactionSink>(
        &self,
        sink: &S,
        invalid_height: u64,
    ) -> Result<CoreBlockReference, CoreScanError> {
        let lowest = invalid_height.saturating_sub(self.maximum_reorg_depth);
        for height in (lowest..invalid_height).rev() {
            let local = sink
                .committed_canonical_hash(height)
                .map_err(|_| CoreScanError::Persistence)?;
            let core = self.canonical_hash_at_height(height)?;
            if let (Some(local_hash), Some(core_hash)) = (local, core) {
                if local_hash == core_hash && core_hash != [0u8; 32] {
                    return Ok(CoreBlockReference {
                        height,
                        hash: core_hash,
                    });
                }
            }
        }
        Err(CoreScanError::ReorgBeyondBound)
    }

    fn check_limit(&self, limit: u64) -> Result<(), CoreScanError> {
        validate_scan_limit(limit)?;
        if limit > self.maximum_batch_blocks {
            return Err(CoreScanError::InvalidScanLimit);
        }
        Ok(())
    }

    fn validate_and_map(
        &self,
        result: ScanResult,
        expected_start: u64,
        previous_anchor: Option<CoreBlockReference>,
        identity: &CoreChainIdentity,
    ) -> Result<CoreScanBatch, CoreScanError> {
        if result.blocks.len() as u64 > self.maximum_batch_blocks {
            return Err(CoreScanError::InvalidScan {
                code: "BATCH_TOO_LARGE",
            });
        }
        if result.tip.hash == [0u8; 32] {
            return Err(CoreScanError::InvalidScan {
                code: "ZERO_TIP_HASH",
            });
        }
        let canonical_tip = self.canonical_hash_at_height(result.tip.height)?;
        if canonical_tip != Some(result.tip.hash) {
            return Err(CoreScanError::InvalidScan {
                code: "TIP_HASH_DISAGREEMENT",
            });
        }

        let expected_previous = if expected_start == 0 {
            [0u8; 32]
        } else if let Some(anchor) = previous_anchor {
            if anchor.height.checked_add(1) != Some(expected_start) {
                return Err(CoreScanError::InvalidScan {
                    code: "START_ANCHOR_GAP",
                });
            }
            anchor.hash
        } else {
            self.canonical_hash_at_height(expected_start - 1)?.ok_or(
                CoreScanError::InvalidScan {
                    code: "MISSING_PREVIOUS_HASH",
                },
            )?
        };

        let mut mapped = Vec::with_capacity(result.blocks.len());
        let mut next_height = expected_start;
        let mut previous_hash = expected_previous;
        for block in result.blocks {
            if block.height != next_height {
                return Err(CoreScanError::InvalidScan {
                    code: "NONCONTIGUOUS_HEIGHT",
                });
            }
            if block.previous_block_hash != previous_hash {
                return Err(CoreScanError::InvalidScan {
                    code: "PREVIOUS_HASH_MISMATCH",
                });
            }
            let mapped_block = map_block(block, identity)?;
            previous_hash = mapped_block.block_hash;
            next_height = next_height
                .checked_add(1)
                .ok_or(CoreScanError::InvalidScan {
                    code: "HEIGHT_OVERFLOW",
                })?;
            mapped.push(mapped_block);
        }

        let commit_cursor = match mapped.last() {
            None => {
                if result.continuation.is_some() {
                    return Err(CoreScanError::InvalidScan {
                        code: "CURSOR_WITHOUT_BLOCKS",
                    });
                }
                if expected_start == 0 && result.tip.height == 0 {
                    let cursor = WalletScanCursor::new(
                        identity.network,
                        identity.chain_id,
                        1,
                        BlockRef {
                            height: 0,
                            hash: result.tip.hash,
                        },
                    );
                    let bytes = CoreCursorBytes::from_cursor(cursor, identity)?;
                    self.validate_cursor(bytes)?;
                    Some(bytes)
                } else {
                    None
                }
            }
            Some(last) => {
                let cursor = if let Some(cursor) = result.continuation {
                    if last.height >= result.tip.height {
                        return Err(CoreScanError::InvalidScan {
                            code: "CURSOR_PAST_TIP",
                        });
                    }
                    cursor
                } else {
                    if last.height < result.tip.height {
                        return Err(CoreScanError::InvalidScan {
                            code: "MISSING_CONTINUATION",
                        });
                    }
                    WalletScanCursor::new(
                        identity.network,
                        identity.chain_id,
                        last.height
                            .checked_add(1)
                            .ok_or(CoreScanError::InvalidScan {
                                code: "HEIGHT_OVERFLOW",
                            })?,
                        BlockRef {
                            height: last.height,
                            hash: last.block_hash,
                        },
                    )
                };
                if cursor.next_height != last.height.saturating_add(1)
                    || cursor.anchor_height != last.height
                    || cursor.anchor_hash != last.block_hash
                {
                    return Err(CoreScanError::InvalidScan {
                        code: "CONTINUATION_REGRESSION",
                    });
                }
                let bytes = CoreCursorBytes::from_cursor(cursor, identity)?;
                self.validate_cursor(bytes)?;
                Some(bytes)
            }
        };

        Ok(CoreScanBatch {
            observed_tip: result.tip.into(),
            blocks: mapped,
            commit_cursor,
        })
    }
}

fn validate_scan_limit(limit: u64) -> Result<(), CoreScanError> {
    if limit == 0 || limit > MAX_CORE_SCAN_BATCH_BLOCKS {
        Err(CoreScanError::InvalidScanLimit)
    } else {
        Ok(())
    }
}

fn map_identity(identity: ChainIdentity) -> Result<CoreChainIdentity, CoreScanError> {
    if identity.network.magic() != identity.network_magic {
        return Err(CoreScanError::InvalidIdentity {
            code: "NETWORK_MAGIC_MISMATCH",
        });
    }
    if identity.chain_id == [0u8; 32] {
        return Err(CoreScanError::InvalidIdentity {
            code: "ZERO_CHAIN_ID",
        });
    }
    // Frozen pre-launch Core intentionally retains the configured zero genesis
    // constant on regtest so chain-ID and kernel-signature derivation agree.
    // The live canonical genesis is still bound below through the nonzero tip
    // and canonical-hash checks. Real networks must never accept a zero value.
    if identity.genesis_hash == [0u8; 32] && identity.network != CoreNetwork::Regtest {
        return Err(CoreScanError::InvalidIdentity {
            code: "ZERO_GENESIS_HASH",
        });
    }
    if identity.protocol_version != dom_core::PROTOCOL_VERSION {
        return Err(CoreScanError::InvalidIdentity {
            code: "UNSUPPORTED_PROTOCOL_VERSION",
        });
    }
    if identity.range_proof_serialization_version != dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION {
        return Err(CoreScanError::InvalidIdentity {
            code: "UNSUPPORTED_RANGE_PROOF_VERSION",
        });
    }
    if identity.current_tip.hash == [0u8; 32] {
        return Err(CoreScanError::InvalidIdentity {
            code: "ZERO_TIP_HASH",
        });
    }
    Ok(CoreChainIdentity {
        network: identity.network,
        network_magic: identity.network_magic,
        chain_id: identity.chain_id,
        genesis_hash: identity.genesis_hash,
        protocol_version: identity.protocol_version,
        range_proof_serialization_version: identity.range_proof_serialization_version,
        coinbase_maturity: identity.coinbase_maturity,
        current_tip: identity.current_tip.into(),
    })
}

fn validate_same_chain(
    expected: &CoreChainIdentity,
    actual: &CoreChainIdentity,
) -> Result<(), CoreScanError> {
    if expected.network != actual.network {
        return Err(CoreScanError::IdentityMismatch { code: "NETWORK" });
    }
    if expected.network_magic != actual.network_magic {
        return Err(CoreScanError::IdentityMismatch {
            code: "NETWORK_MAGIC",
        });
    }
    if expected.chain_id != actual.chain_id {
        return Err(CoreScanError::IdentityMismatch { code: "CHAIN_ID" });
    }
    if expected.genesis_hash != actual.genesis_hash {
        return Err(CoreScanError::IdentityMismatch {
            code: "GENESIS_HASH",
        });
    }
    if expected.protocol_version != actual.protocol_version {
        return Err(CoreScanError::IdentityMismatch {
            code: "PROTOCOL_VERSION",
        });
    }
    if expected.range_proof_serialization_version != actual.range_proof_serialization_version {
        return Err(CoreScanError::IdentityMismatch {
            code: "RANGE_PROOF_VERSION",
        });
    }
    if expected.coinbase_maturity != actual.coinbase_maturity {
        return Err(CoreScanError::IdentityMismatch {
            code: "COINBASE_MATURITY",
        });
    }
    Ok(())
}

fn validate_cursor_identity(
    cursor: &WalletScanCursor,
    identity: &CoreChainIdentity,
) -> Result<(), CoreScanError> {
    if cursor.version != WALLET_SCAN_CURSOR_VERSION {
        return Err(CoreScanError::InvalidCursor {
            code: "UNSUPPORTED_VERSION",
        });
    }
    if cursor.network_magic != identity.network_magic || cursor.chain_id != identity.chain_id {
        return Err(CoreScanError::CursorIdentityMismatch);
    }
    if cursor.anchor_hash == [0u8; 32] {
        return Err(CoreScanError::InvalidCursor {
            code: "ZERO_ANCHOR_HASH",
        });
    }
    Ok(())
}

fn validate_cursor_result(
    cursor: WalletScanCursor,
    validation: CursorValidation,
) -> Result<CoreBlockReference, CoreScanError> {
    if !validation.valid
        || validation.safe_rescan_anchor.height != cursor.anchor_height
        || validation.safe_rescan_anchor.hash != cursor.anchor_hash
    {
        return Err(CoreScanError::ReorgDetected);
    }
    Ok(validation.safe_rescan_anchor.into())
}

fn map_block(
    block: ScanBlock,
    identity: &CoreChainIdentity,
) -> Result<CoreScanBlock, CoreScanError> {
    if block.block_hash == [0u8; 32] || block.canonical_marker != block.block_hash {
        return Err(CoreScanError::InvalidScan {
            code: "NONCANONICAL_BLOCK",
        });
    }
    if block.protocol_version
        != dom_core::required_block_version_for_network(identity.network_magic, block.height)
    {
        return Err(CoreScanError::InvalidScan {
            code: "PROTOCOL_VERSION",
        });
    }
    if block.range_proof_serialization_version != identity.range_proof_serialization_version {
        return Err(CoreScanError::InvalidScan {
            code: "RANGE_PROOF_VERSION",
        });
    }
    validate_full_fidelity_projection(&block, identity)?;
    let mut outputs = Vec::with_capacity(block.outputs.len());
    for output in block.outputs {
        if output.block_height != block.height || output.block_hash != block.block_hash {
            return Err(CoreScanError::InvalidScan {
                code: "OUTPUT_BLOCK_CONTEXT",
            });
        }
        if output.range_proof.len() != dom_crypto::RANGE_PROOF_SIZE {
            return Err(CoreScanError::InvalidScan {
                code: "RANGE_PROOF_LENGTH",
            });
        }
        match (output.recovery_version, output.recovery_capsule.len()) {
            (0, 0) => {}
            (
                dom_crypto::recovery::RECOVERY_VERSION,
                dom_crypto::recovery::RECOVERY_CAPSULE_SIZE,
            ) => {}
            _ => {
                return Err(CoreScanError::InvalidScan {
                    code: "RECOVERY_CAPSULE_FORMAT",
                })
            }
        }
        outputs.push(CoreScanOutput {
            commitment: output.commitment,
            range_proof: output.range_proof,
            recovery_capsule: output.recovery_capsule,
            recovery_version: output.recovery_version,
            is_coinbase: output.is_coinbase,
            block_height: output.block_height,
            block_hash: output.block_hash,
            output_position: output.output_position,
        });
    }
    Ok(CoreScanBlock {
        height: block.height,
        block_hash: block.block_hash,
        previous_block_hash: block.previous_block_hash,
        canonical_header_bytes: block.canonical_header_bytes,
        timestamp: block.timestamp,
        canonical_marker: block.canonical_marker,
        outputs,
        inputs: block
            .inputs
            .into_iter()
            .map(|input| CoreScanInput {
                spent_commitment: input.spent_commitment,
            })
            .collect(),
        kernels: block
            .kernels
            .into_iter()
            .map(|kernel| CoreScanKernel {
                excess: kernel.excess,
                features: kernel.features,
                fee: kernel.fee,
                lock_height: kernel.lock_height,
                excess_signature: kernel.excess_signature,
            })
            .collect(),
        transactions: block.transactions,
        coinbase: block.coinbase.into(),
        total_fees_noms: block.total_fees_noms,
        protocol_version: block.protocol_version,
        range_proof_serialization_version: block.range_proof_serialization_version,
    })
}

/// Reconstruct the canonical DOM block view and require every redundant scanner
/// projection to agree with the bytes committed by the header. The Core RPC is
/// authenticated, but Wallet must still fail closed if a buggy or compromised
/// adapter changes transaction boundaries, signatures, or evidence fields.
fn validate_full_fidelity_projection(
    block: &ScanBlock,
    identity: &CoreChainIdentity,
) -> Result<(), CoreScanError> {
    let header = BlockHeader::from_bytes(&block.canonical_header_bytes).map_err(|_| {
        CoreScanError::InvalidScan {
            code: "HEADER_DECODE",
        }
    })?;
    if header.to_bytes().map_err(|_| CoreScanError::InvalidScan {
        code: "HEADER_ENCODE",
    })? != block.canonical_header_bytes
    {
        return Err(CoreScanError::InvalidScan {
            code: "NONCANONICAL_HEADER_BYTES",
        });
    }
    if header.height.0 != block.height
        || header.prev_hash.as_bytes() != &block.previous_block_hash
        || header.timestamp.0 != block.timestamp
        || header.version != block.protocol_version
    {
        return Err(CoreScanError::InvalidScan {
            code: "HEADER_PROJECTION_MISMATCH",
        });
    }
    dom_consensus::block::validate_header_syntax(&header, identity.network_magic).map_err(
        |_| CoreScanError::InvalidScan {
            code: "HEADER_SYNTAX",
        },
    )?;
    let header_identifier = dom_chain::canonical_header_identifier(
        identity.network_magic,
        &block.canonical_header_bytes,
    )
    .map_err(|_| CoreScanError::InvalidScan {
        code: "HEADER_IDENTIFIER",
    })?;
    if header_identifier.as_bytes() != &block.block_hash {
        return Err(CoreScanError::InvalidScan {
            code: "HEADER_HASH_MISMATCH",
        });
    }

    let coinbase_commitment = Commitment::from_compressed_bytes(&block.coinbase.output_commitment)
        .map_err(|_| CoreScanError::InvalidScan {
            code: "COINBASE_COMMITMENT",
        })?;
    let coinbase_excess = Commitment::from_compressed_bytes(&block.coinbase.kernel_excess)
        .map_err(|_| CoreScanError::InvalidScan {
            code: "COINBASE_EXCESS",
        })?;
    let coinbase = CoinbaseTransaction {
        output: TransactionOutput {
            commitment: coinbase_commitment,
            proof: block.coinbase.output_proof_envelope.clone(),
        },
        kernel: CoinbaseKernel {
            features: block.coinbase.kernel_features,
            explicit_value: block.coinbase.explicit_value,
            excess: coinbase_excess,
            excess_signature: block.coinbase.kernel_excess_signature,
        },
        offset: block.coinbase.offset,
    };
    let coinbase_bytes = coinbase
        .to_bytes()
        .map_err(|_| CoreScanError::InvalidScan {
            code: "COINBASE_ENCODE",
        })?;
    let coinbase = CoinbaseTransaction::from_bytes(&coinbase_bytes).map_err(|_| {
        CoreScanError::InvalidScan {
            code: "COINBASE_DECODE",
        }
    })?;

    let mut transactions = Vec::with_capacity(block.transactions.len());
    let mut expected_inputs = Vec::new();
    let mut expected_outputs = Vec::new();
    let mut expected_kernels = Vec::new();
    expected_outputs.push(scan_output_from_transaction_output(
        &coinbase.output,
        true,
        block.height,
        block.block_hash,
        0,
    )?);
    expected_kernels.push(ScanKernel {
        excess: *coinbase.kernel.excess.as_bytes(),
        features: coinbase.kernel.features,
        fee: 0,
        lock_height: 0,
        excess_signature: coinbase.kernel.excess_signature,
    });

    let mut output_position = 1u32;
    for (index, projected) in block.transactions.iter().enumerate() {
        let transaction_index = u32::try_from(index).map_err(|_| CoreScanError::InvalidScan {
            code: "TRANSACTION_INDEX_OVERFLOW",
        })?;
        if projected.location
            != (TransactionLocation {
                block_height: block.height,
                block_hash: block.block_hash,
                transaction_index,
            })
        {
            return Err(CoreScanError::InvalidScan {
                code: "TRANSACTION_LOCATION",
            });
        }
        if dom_crypto::blake2b_256(&projected.canonical_bytes).as_bytes() != &projected.tx_hash {
            return Err(CoreScanError::InvalidScan {
                code: "TRANSACTION_HASH",
            });
        }
        let transaction = Transaction::from_bytes(&projected.canonical_bytes).map_err(|_| {
            CoreScanError::InvalidScan {
                code: "TRANSACTION_DECODE",
            }
        })?;
        if transaction
            .to_bytes()
            .map_err(|_| CoreScanError::InvalidScan {
                code: "TRANSACTION_ENCODE",
            })?
            != projected.canonical_bytes
        {
            return Err(CoreScanError::InvalidScan {
                code: "NONCANONICAL_TRANSACTION_BYTES",
            });
        }
        if transaction.offset != projected.offset {
            return Err(CoreScanError::InvalidScan {
                code: "TRANSACTION_OFFSET",
            });
        }

        let transaction_inputs: Vec<_> = transaction
            .inputs
            .iter()
            .map(|input| ScanInput {
                spent_commitment: *input.commitment.as_bytes(),
            })
            .collect();
        if transaction_inputs != projected.inputs {
            return Err(CoreScanError::InvalidScan {
                code: "TRANSACTION_INPUT_PROJECTION",
            });
        }
        expected_inputs.extend(transaction_inputs);

        let mut transaction_outputs = Vec::with_capacity(transaction.outputs.len());
        for output in &transaction.outputs {
            let projected_output = scan_output_from_transaction_output(
                output,
                false,
                block.height,
                block.block_hash,
                output_position,
            )?;
            output_position = output_position
                .checked_add(1)
                .ok_or(CoreScanError::InvalidScan {
                    code: "OUTPUT_POSITION_OVERFLOW",
                })?;
            transaction_outputs.push(projected_output.clone());
            expected_outputs.push(projected_output);
        }
        if transaction_outputs != projected.outputs {
            return Err(CoreScanError::InvalidScan {
                code: "TRANSACTION_OUTPUT_PROJECTION",
            });
        }

        let transaction_kernels: Vec<_> = transaction
            .kernels
            .iter()
            .map(|kernel| ScanKernel {
                excess: *kernel.excess.as_bytes(),
                features: kernel.features,
                fee: kernel.fee.noms(),
                lock_height: kernel.lock_height,
                excess_signature: kernel.excess_signature,
            })
            .collect();
        if transaction_kernels != projected.kernels {
            return Err(CoreScanError::InvalidScan {
                code: "TRANSACTION_KERNEL_PROJECTION",
            });
        }
        expected_kernels.extend(transaction_kernels);
        transactions.push(transaction);
    }

    if block.inputs != expected_inputs {
        return Err(CoreScanError::InvalidScan {
            code: "FLAT_INPUT_PROJECTION",
        });
    }
    if block.outputs != expected_outputs {
        return Err(CoreScanError::InvalidScan {
            code: "FLAT_OUTPUT_PROJECTION",
        });
    }
    if block.kernels != expected_kernels {
        return Err(CoreScanError::InvalidScan {
            code: "FLAT_KERNEL_PROJECTION",
        });
    }

    let reconstructed = Block {
        header,
        coinbase,
        transactions,
    };
    if reconstructed
        .total_fees()
        .map_err(|_| CoreScanError::InvalidScan {
            code: "TOTAL_FEE_OVERFLOW",
        })?
        != block.total_fees_noms
    {
        return Err(CoreScanError::InvalidScan {
            code: "TOTAL_FEE_PROJECTION",
        });
    }
    dom_consensus::validate_pmmr_roots(&reconstructed).map_err(|_| CoreScanError::InvalidScan {
        code: "BLOCK_BODY_COMMITMENT",
    })
}

fn scan_output_from_transaction_output(
    output: &TransactionOutput,
    is_coinbase: bool,
    block_height: u64,
    block_hash: [u8; 32],
    output_position: u32,
) -> Result<ScanOutput, CoreScanError> {
    let range_proof = output
        .range_proof_bytes()
        .map_err(|_| CoreScanError::InvalidScan {
            code: "OUTPUT_PROOF_ENVELOPE",
        })?;
    let capsule = output
        .recovery_capsule()
        .map_err(|_| CoreScanError::InvalidScan {
            code: "OUTPUT_RECOVERY_CAPSULE",
        })?;
    Ok(ScanOutput {
        commitment: *output.commitment.as_bytes(),
        range_proof: range_proof.to_vec(),
        recovery_version: capsule.as_ref().map_or(0, |value| value.version()),
        recovery_capsule: capsule
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default(),
        is_coinbase,
        block_height,
        block_hash,
        output_position,
    })
}

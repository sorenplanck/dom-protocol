//! Wallet-owned structured submission boundary for the embedded DOM Core API.

#![forbid(unsafe_code)]

use dom_consensus::Transaction;
use dom_wallet_core_api::{
    CoreNetwork, MempoolPolicySnapshot, SubmissionDiagnostic, SubmissionResult,
    SubmissionResultKind, SubmitTransactionRequest, SyncStatus, TransactionIdentifier,
    TransactionStatus, WalletCoreApi, WalletCoreError,
};
use dom_wallet_core_sync::CoreChainIdentity;
use std::{fmt, sync::Arc};
use thiserror::Error;

/// Wallet-owned stable readiness categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletReadiness {
    /// Core is starting.
    Starting,
    /// Core is synchronizing.
    Synchronizing,
    /// Core reports that Wallet operations are ready.
    Ready,
    /// Core is busy or otherwise not ready.
    NotReady,
}

/// Wallet-owned projection of the frozen mempool policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletMempoolPolicy {
    /// Policy version reported by Core.
    pub policy_version: u16,
    /// Network reported by Core.
    pub network: CoreNetwork,
    /// Chain identifier bound by the adapter session.
    pub chain_id: [u8; 32],
    /// Minimum relay fee rate reported by Core.
    pub minimum_relay_fee_rate: u64,
    /// Minimum mempool admission fee rate reported by Core.
    pub minimum_mempool_fee_rate: u64,
    /// Current accepted transaction count.
    pub transaction_count: usize,
}

/// Wallet-owned readiness and synchronization snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletReadinessSnapshot {
    /// Stable Wallet readiness category.
    pub readiness: WalletReadiness,
    /// Exact frozen Core synchronization status.
    pub sync_status: SyncStatus,
    /// Core readiness boolean.
    pub core_ready: bool,
    /// Network and policy projection.
    pub mempool_policy: WalletMempoolPolicy,
}

/// Stable Wallet transaction identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletTransactionIdentifier {
    /// Canonical transaction hash.
    TransactionHash([u8; 32]),
    /// Primary kernel excess.
    KernelExcess([u8; 33]),
}

impl WalletTransactionIdentifier {
    fn to_core(self) -> TransactionIdentifier {
        match self {
            Self::TransactionHash(hash) => TransactionIdentifier::TxHash(hash),
            Self::KernelExcess(excess) => TransactionIdentifier::KernelExcess(excess),
        }
    }
}

/// A finalized transaction and the identities already persisted by the Wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTransactionSubmission {
    transaction: Transaction,
    transaction_hash: [u8; 32],
    primary_kernel_excess: Option<[u8; 33]>,
}

impl CanonicalTransactionSubmission {
    /// Bind immutable transaction data to its persisted identifiers.
    pub fn new(
        transaction: Transaction,
        transaction_hash: [u8; 32],
        primary_kernel_excess: Option<[u8; 33]>,
    ) -> Result<Self, WalletSubmissionError> {
        if transaction_hash == [0; 32] {
            return Err(WalletSubmissionError::InvalidRequest {
                code: "ZERO_TRANSACTION_HASH",
            });
        }
        if primary_kernel_excess == Some([0; 33]) {
            return Err(WalletSubmissionError::InvalidRequest {
                code: "ZERO_KERNEL_EXCESS",
            });
        }
        Ok(Self {
            transaction,
            transaction_hash,
            primary_kernel_excess,
        })
    }

    /// Persisted canonical transaction hash.
    pub fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }

    /// Persisted primary kernel excess, when present.
    pub fn primary_kernel_excess(&self) -> Option<[u8; 33]> {
        self.primary_kernel_excess
    }
}

/// Wallet-owned stable diagnostic projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSubmissionDiagnostic {
    /// Invalid encoding or consensus syntax.
    Invalid,
    /// Fee below policy floor.
    FeeTooLow,
    /// Input conflict.
    DoubleSpend,
    /// Immature coinbase input.
    ImmatureCoinbase,
    /// Lock condition not satisfied.
    Locked,
    /// Already known.
    AlreadyKnown,
    /// Core is busy.
    NodeBusy,
    /// Other policy rejection.
    Policy,
    /// Internal Core failure.
    Internal,
}

impl From<SubmissionDiagnostic> for WalletSubmissionDiagnostic {
    fn from(value: SubmissionDiagnostic) -> Self {
        match value {
            SubmissionDiagnostic::Invalid => Self::Invalid,
            SubmissionDiagnostic::FeeTooLow => Self::FeeTooLow,
            SubmissionDiagnostic::DoubleSpend => Self::DoubleSpend,
            SubmissionDiagnostic::ImmatureCoinbase => Self::ImmatureCoinbase,
            SubmissionDiagnostic::Locked => Self::Locked,
            SubmissionDiagnostic::AlreadyKnown => Self::AlreadyKnown,
            SubmissionDiagnostic::NodeBusy => Self::NodeBusy,
            SubmissionDiagnostic::Policy => Self::Policy,
            SubmissionDiagnostic::Internal => Self::Internal,
        }
    }
}

/// Facts returned by Core without collapsing acceptance and relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletSubmissionEvidence {
    /// Canonical transaction hash.
    pub transaction_hash: [u8; 32],
    /// Primary kernel excess, when Core can provide it.
    pub primary_kernel_excess: Option<[u8; 33]>,
    /// Whether Core accepted the transaction into its mempool.
    pub accepted_to_mempool: bool,
    /// Whether relay was attempted.
    pub broadcast_attempted: bool,
    /// Whether at least one relay subscriber accepted it.
    pub relayed: bool,
    /// Stable Core diagnostic category.
    pub diagnostic: Option<WalletSubmissionDiagnostic>,
}

/// Complete Wallet-owned mapping of frozen Core submission categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSubmissionOutcome {
    Accepted(WalletSubmissionEvidence),
    AlreadyKnown(WalletSubmissionEvidence),
    RejectedInvalid(WalletSubmissionEvidence),
    RejectedFee(WalletSubmissionEvidence),
    RejectedDoubleSpend(WalletSubmissionEvidence),
    RejectedImmatureCoinbase(WalletSubmissionEvidence),
    RejectedExpired(WalletSubmissionEvidence),
    RejectedPolicy(WalletSubmissionEvidence),
    NodeNotReady(WalletSubmissionEvidence),
    TemporaryFailure(WalletSubmissionEvidence),
    InternalFailure(WalletSubmissionEvidence),
}

impl WalletSubmissionOutcome {
    /// Return the immutable Core evidence carried by every outcome.
    pub fn evidence(self) -> WalletSubmissionEvidence {
        match self {
            Self::Accepted(value)
            | Self::AlreadyKnown(value)
            | Self::RejectedInvalid(value)
            | Self::RejectedFee(value)
            | Self::RejectedDoubleSpend(value)
            | Self::RejectedImmatureCoinbase(value)
            | Self::RejectedExpired(value)
            | Self::RejectedPolicy(value)
            | Self::NodeNotReady(value)
            | Self::TemporaryFailure(value)
            | Self::InternalFailure(value) => value,
        }
    }
}

/// Wallet-owned canonical transaction status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletTransactionStatus {
    Unknown,
    InMempool,
    Confirmed { height: u64, block_hash: [u8; 32] },
}

/// Authoritative result of uncertainty recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSubmissionQuery {
    InMempool(WalletSubmissionOutcome),
    Confirmed {
        height: u64,
        block_hash: [u8; 32],
        submission: WalletSubmissionOutcome,
    },
    Rejected(WalletSubmissionOutcome),
    Unknown,
    TemporarilyUnavailable(WalletSubmissionOutcome),
}

/// Durable transaction-lifecycle decisions consumed by a later state adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSubmissionState {
    Finalized,
    Submitting,
    Accepted,
    AcceptedNotRelayed,
    AlreadyKnown,
    TemporarilyUncertain,
    RejectedInvalid,
    RejectedFee,
    RejectedDoubleSpend,
    RejectedImmatureCoinbase,
    RejectedExpired,
    RejectedPolicy,
    NodeNotReady,
    InternalUncertain,
    Confirmed,
    Reorged,
}

/// Conservative pure decision returned to the existing durable state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletTransitionDecision {
    pub state: WalletSubmissionState,
    pub preserve_canonical_transaction: bool,
    pub release_reservations: bool,
    pub create_duplicate_transaction: bool,
    pub rebuild_transaction: bool,
    pub mutate_fee: bool,
}

impl WalletTransitionDecision {
    fn conservative(state: WalletSubmissionState) -> Self {
        Self {
            state,
            preserve_canonical_transaction: true,
            release_reservations: false,
            create_duplicate_transaction: false,
            rebuild_transaction: false,
            mutate_fee: false,
        }
    }
}

/// Typed adapter failures. Raw Core messages never cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WalletSubmissionError {
    #[error("invalid submission request ({code})")]
    InvalidRequest { code: &'static str },
    #[error("embedded Core identity mismatch ({code})")]
    IdentityMismatch { code: &'static str },
    #[error("embedded Core is not ready")]
    NotReady { readiness: WalletReadiness },
    #[error("embedded Core request failed ({code})")]
    CoreUnavailable { code: &'static str },
    #[error("inconsistent embedded Core result ({code})")]
    InconsistentResult { code: &'static str },
}

/// Additive structured submission service over the frozen embedded API.
pub struct CoreSubmissionService {
    api: Arc<dyn WalletCoreApi + Send + Sync>,
    identity: CoreChainIdentity,
}

impl fmt::Debug for CoreSubmissionService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreSubmissionService")
            .field("network", &self.identity.network)
            .field("protocol_version", &self.identity.protocol_version)
            .finish_non_exhaustive()
    }
}

impl CoreSubmissionService {
    /// Bind the service to an identity already validated by the Slice C adapter.
    pub fn connect(
        api: Arc<dyn WalletCoreApi + Send + Sync>,
        identity: CoreChainIdentity,
    ) -> Result<Self, WalletSubmissionError> {
        validate_identity(&identity)?;
        let service = Self { api, identity };
        service.require_same_chain()?;
        Ok(service)
    }

    /// Return a network- and chain-bound readiness snapshot.
    pub fn readiness(&self) -> Result<WalletReadinessSnapshot, WalletSubmissionError> {
        self.require_same_chain()?;
        let sync_status = self.api.sync_status().map_err(map_core_error)?;
        let core_ready = self
            .api
            .is_ready_for_wallet_operations()
            .map_err(map_core_error)?;
        let policy = self.api.mempool_policy_snapshot().map_err(map_core_error)?;
        let mempool_policy = self.map_policy(policy)?;
        let readiness = match (sync_status, core_ready) {
            (SyncStatus::Starting, _) => WalletReadiness::Starting,
            (SyncStatus::Syncing, _) => WalletReadiness::Synchronizing,
            (SyncStatus::Ready, true) => WalletReadiness::Ready,
            (SyncStatus::Ready | SyncStatus::Busy, false) | (SyncStatus::Busy, true) => {
                WalletReadiness::NotReady
            }
        };
        Ok(WalletReadinessSnapshot {
            readiness,
            sync_status,
            core_ready,
            mempool_policy,
        })
    }

    /// Submit exactly the finalized transaction retained by the Wallet.
    pub fn submit_transaction(
        &self,
        submission: &CanonicalTransactionSubmission,
    ) -> Result<WalletSubmissionOutcome, WalletSubmissionError> {
        self.require_ready()?;
        let result = self
            .api
            .submit_transaction(SubmitTransactionRequest {
                transaction: submission.transaction.clone(),
            })
            .map_err(map_core_error)?;
        map_submission_result(
            result,
            Some(submission.transaction_hash),
            submission.primary_kernel_excess,
        )
    }

    /// Rebroadcast a known immutable transaction identity through Core.
    pub fn rebroadcast_transaction(
        &self,
        identifier: WalletTransactionIdentifier,
    ) -> Result<WalletSubmissionOutcome, WalletSubmissionError> {
        self.require_ready()?;
        let expected = expected_identities(identifier);
        let result = self
            .api
            .rebroadcast_transaction(identifier.to_core())
            .map_err(map_core_error)?;
        map_submission_result(result, expected.0, expected.1)
    }

    /// Recover an uncertain submission using both Core query and chain status evidence.
    pub fn query_submission(
        &self,
        identifier: WalletTransactionIdentifier,
    ) -> Result<WalletSubmissionQuery, WalletSubmissionError> {
        self.require_same_chain()?;
        let expected = expected_identities(identifier);
        let raw = self
            .api
            .query_submission(identifier.to_core())
            .map_err(map_core_error)?;
        let outcome = map_submission_result(raw, expected.0, expected.1)?;
        let status = self.transaction_status(identifier)?;
        Ok(match status {
            WalletTransactionStatus::InMempool => WalletSubmissionQuery::InMempool(outcome),
            WalletTransactionStatus::Confirmed { height, block_hash } => {
                WalletSubmissionQuery::Confirmed {
                    height,
                    block_hash,
                    submission: outcome,
                }
            }
            WalletTransactionStatus::Unknown => match outcome {
                WalletSubmissionOutcome::RejectedInvalid(_)
                | WalletSubmissionOutcome::RejectedFee(_)
                | WalletSubmissionOutcome::RejectedDoubleSpend(_)
                | WalletSubmissionOutcome::RejectedImmatureCoinbase(_)
                | WalletSubmissionOutcome::RejectedExpired(_) => {
                    WalletSubmissionQuery::Rejected(outcome)
                }
                WalletSubmissionOutcome::NodeNotReady(_)
                | WalletSubmissionOutcome::TemporaryFailure(_)
                | WalletSubmissionOutcome::InternalFailure(_) => {
                    WalletSubmissionQuery::TemporarilyUnavailable(outcome)
                }
                WalletSubmissionOutcome::RejectedPolicy(evidence)
                    if evidence.diagnostic.is_none() =>
                {
                    WalletSubmissionQuery::Unknown
                }
                _ => WalletSubmissionQuery::Unknown,
            },
        })
    }

    /// Query canonical transaction status without inferring from mempool absence.
    pub fn transaction_status(
        &self,
        identifier: WalletTransactionIdentifier,
    ) -> Result<WalletTransactionStatus, WalletSubmissionError> {
        self.require_same_chain()?;
        self.api
            .transaction_status(identifier.to_core())
            .map(map_transaction_status)
            .map_err(map_core_error)
    }

    fn require_ready(&self) -> Result<WalletReadinessSnapshot, WalletSubmissionError> {
        let snapshot = self.readiness()?;
        if snapshot.readiness != WalletReadiness::Ready {
            return Err(WalletSubmissionError::NotReady {
                readiness: snapshot.readiness,
            });
        }
        Ok(snapshot)
    }

    fn require_same_chain(&self) -> Result<(), WalletSubmissionError> {
        let current = self.api.chain_identity().map_err(map_core_error)?;
        if current.network != self.identity.network
            || current.network_magic != self.identity.network_magic
            || current.chain_id != self.identity.chain_id
            || current.genesis_hash != self.identity.genesis_hash
            || current.protocol_version != self.identity.protocol_version
            || current.range_proof_serialization_version
                != self.identity.range_proof_serialization_version
            || current.coinbase_maturity != self.identity.coinbase_maturity
        {
            return Err(WalletSubmissionError::IdentityMismatch {
                code: "CHAIN_IDENTITY_CHANGED",
            });
        }
        Ok(())
    }

    fn map_policy(
        &self,
        policy: MempoolPolicySnapshot,
    ) -> Result<WalletMempoolPolicy, WalletSubmissionError> {
        if policy.network != self.identity.network {
            return Err(WalletSubmissionError::IdentityMismatch {
                code: "POLICY_NETWORK_MISMATCH",
            });
        }
        if policy.policy_version == 0 {
            return Err(WalletSubmissionError::InconsistentResult {
                code: "ZERO_POLICY_VERSION",
            });
        }
        Ok(WalletMempoolPolicy {
            policy_version: policy.policy_version,
            network: policy.network,
            chain_id: self.identity.chain_id,
            minimum_relay_fee_rate: policy.min_relay_fee_rate,
            minimum_mempool_fee_rate: policy.min_mempool_fee_rate,
            transaction_count: policy.transaction_count,
        })
    }
}

/// Derive a conservative durable transition without mutating Wallet state.
pub fn transition_for_outcome(outcome: WalletSubmissionOutcome) -> WalletTransitionDecision {
    let state = match outcome {
        WalletSubmissionOutcome::Accepted(evidence) if evidence.relayed => {
            WalletSubmissionState::Accepted
        }
        WalletSubmissionOutcome::Accepted(_) => WalletSubmissionState::AcceptedNotRelayed,
        WalletSubmissionOutcome::AlreadyKnown(_) => WalletSubmissionState::AlreadyKnown,
        WalletSubmissionOutcome::RejectedInvalid(_) => WalletSubmissionState::RejectedInvalid,
        WalletSubmissionOutcome::RejectedFee(_) => WalletSubmissionState::RejectedFee,
        WalletSubmissionOutcome::RejectedDoubleSpend(_) => {
            WalletSubmissionState::RejectedDoubleSpend
        }
        WalletSubmissionOutcome::RejectedImmatureCoinbase(_) => {
            WalletSubmissionState::RejectedImmatureCoinbase
        }
        WalletSubmissionOutcome::RejectedExpired(_) => WalletSubmissionState::RejectedExpired,
        WalletSubmissionOutcome::RejectedPolicy(_) => WalletSubmissionState::RejectedPolicy,
        WalletSubmissionOutcome::NodeNotReady(_) => WalletSubmissionState::NodeNotReady,
        WalletSubmissionOutcome::TemporaryFailure(_) => WalletSubmissionState::TemporarilyUncertain,
        WalletSubmissionOutcome::InternalFailure(_) => WalletSubmissionState::InternalUncertain,
    };
    WalletTransitionDecision::conservative(state)
}

/// Derive canonical status transitions; unknown after confirmation is a reorg signal.
pub fn transition_for_status(
    previous: WalletSubmissionState,
    status: WalletTransactionStatus,
) -> WalletTransitionDecision {
    let state = match status {
        WalletTransactionStatus::Confirmed { .. } => WalletSubmissionState::Confirmed,
        WalletTransactionStatus::InMempool => WalletSubmissionState::Accepted,
        WalletTransactionStatus::Unknown if previous == WalletSubmissionState::Confirmed => {
            WalletSubmissionState::Reorged
        }
        WalletTransactionStatus::Unknown => WalletSubmissionState::TemporarilyUncertain,
    };
    WalletTransitionDecision::conservative(state)
}

fn validate_identity(identity: &CoreChainIdentity) -> Result<(), WalletSubmissionError> {
    if identity.chain_id == [0; 32]
        || (identity.genesis_hash == [0; 32] && identity.network != CoreNetwork::Regtest)
    {
        return Err(WalletSubmissionError::InvalidRequest {
            code: "MALFORMED_CHAIN_IDENTITY",
        });
    }
    Ok(())
}

fn expected_identities(
    identifier: WalletTransactionIdentifier,
) -> (Option<[u8; 32]>, Option<[u8; 33]>) {
    match identifier {
        WalletTransactionIdentifier::TransactionHash(hash) => (Some(hash), None),
        WalletTransactionIdentifier::KernelExcess(excess) => (None, Some(excess)),
    }
}

fn map_submission_result(
    result: SubmissionResult,
    expected_hash: Option<[u8; 32]>,
    expected_kernel: Option<[u8; 33]>,
) -> Result<WalletSubmissionOutcome, WalletSubmissionError> {
    if result.relayed && !result.broadcast_attempted {
        return Err(WalletSubmissionError::InconsistentResult {
            code: "RELAY_WITHOUT_BROADCAST",
        });
    }
    if let Some(expected) = expected_hash {
        if result.tx_hash != expected {
            return Err(WalletSubmissionError::InconsistentResult {
                code: "TRANSACTION_HASH_MISMATCH",
            });
        }
    }
    if let (Some(expected), Some(actual)) = (expected_kernel, result.primary_kernel_excess) {
        if actual != expected {
            return Err(WalletSubmissionError::InconsistentResult {
                code: "KERNEL_EXCESS_MISMATCH",
            });
        }
    }
    if result.kind == SubmissionResultKind::Accepted && !result.accepted_to_mempool {
        return Err(WalletSubmissionError::InconsistentResult {
            code: "ACCEPTANCE_FLAG_MISMATCH",
        });
    }
    let rejected_kind = !matches!(
        result.kind,
        SubmissionResultKind::Accepted | SubmissionResultKind::AlreadyKnown
    );
    if rejected_kind && result.accepted_to_mempool {
        return Err(WalletSubmissionError::InconsistentResult {
            code: "REJECTION_ACCEPTED_TO_MEMPOOL",
        });
    }
    if rejected_kind && (result.broadcast_attempted || result.relayed) {
        return Err(WalletSubmissionError::InconsistentResult {
            code: "REJECTED_RESULT_RELAYED",
        });
    }
    let evidence = WalletSubmissionEvidence {
        transaction_hash: result.tx_hash,
        primary_kernel_excess: result.primary_kernel_excess,
        accepted_to_mempool: result.accepted_to_mempool,
        broadcast_attempted: result.broadcast_attempted,
        relayed: result.relayed,
        diagnostic: result.diagnostic.map(Into::into),
    };
    Ok(match result.kind {
        SubmissionResultKind::Accepted => WalletSubmissionOutcome::Accepted(evidence),
        SubmissionResultKind::AlreadyKnown => WalletSubmissionOutcome::AlreadyKnown(evidence),
        SubmissionResultKind::RejectedInvalid => WalletSubmissionOutcome::RejectedInvalid(evidence),
        SubmissionResultKind::RejectedFee => WalletSubmissionOutcome::RejectedFee(evidence),
        SubmissionResultKind::RejectedDoubleSpend => {
            WalletSubmissionOutcome::RejectedDoubleSpend(evidence)
        }
        SubmissionResultKind::RejectedImmatureCoinbase => {
            WalletSubmissionOutcome::RejectedImmatureCoinbase(evidence)
        }
        SubmissionResultKind::RejectedExpired => WalletSubmissionOutcome::RejectedExpired(evidence),
        SubmissionResultKind::RejectedPolicy => WalletSubmissionOutcome::RejectedPolicy(evidence),
        SubmissionResultKind::NodeNotReady => WalletSubmissionOutcome::NodeNotReady(evidence),
        SubmissionResultKind::TemporaryFailure => {
            WalletSubmissionOutcome::TemporaryFailure(evidence)
        }
        SubmissionResultKind::InternalFailure => WalletSubmissionOutcome::InternalFailure(evidence),
    })
}

fn map_transaction_status(status: TransactionStatus) -> WalletTransactionStatus {
    match status {
        TransactionStatus::Unknown => WalletTransactionStatus::Unknown,
        TransactionStatus::InMempool => WalletTransactionStatus::InMempool,
        TransactionStatus::Confirmed(block) => WalletTransactionStatus::Confirmed {
            height: block.height,
            block_hash: block.hash,
        },
    }
}

fn map_core_error(error: WalletCoreError) -> WalletSubmissionError {
    let code = match error {
        WalletCoreError::MalformedCursor(_) => "CORE_MALFORMED_CURSOR",
        WalletCoreError::CursorChainMismatch(_) => "CORE_CHAIN_MISMATCH",
        WalletCoreError::CursorReorg(_) => "CORE_CURSOR_REORG",
        WalletCoreError::InvalidScanRequest(_) => "CORE_INVALID_SCAN_REQUEST",
        WalletCoreError::CanonicalGap(_) => "CORE_CANONICAL_GAP",
        WalletCoreError::NodeNotReady(_) => "CORE_NODE_NOT_READY",
        WalletCoreError::SubmissionRejected(_) => "CORE_SUBMISSION_REJECTED",
        WalletCoreError::TemporaryFailure(_) => "CORE_TEMPORARY_FAILURE",
        WalletCoreError::InternalFailure(_) => "CORE_INTERNAL_FAILURE",
    };
    WalletSubmissionError::CoreUnavailable { code }
}

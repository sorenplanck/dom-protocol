use dom_consensus::Transaction;
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoreNetwork, CursorValidation,
    FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeePolicySnapshot, FeeValidation,
    KernelQueryResult, MempoolPolicySnapshot, ScanRequest, ScanResult, SubmissionDiagnostic,
    SubmissionResult, SubmissionResultKind, SubmitTransactionRequest, SyncStatus,
    TransactionIdentifier, TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult,
    WalletCoreApi, WalletCoreError, WalletScanCursor,
};
use dom_wallet_core_submit::{
    transition_for_outcome, transition_for_status, CanonicalTransactionSubmission,
    CoreSubmissionService, WalletReadiness, WalletSubmissionError, WalletSubmissionOutcome,
    WalletSubmissionQuery, WalletSubmissionState, WalletTransactionIdentifier,
    WalletTransactionStatus,
};
use dom_wallet_core_sync::{CoreBlockReference, CoreChainIdentity};
use dom_wallet_embedded_core::{
    EmbeddedCoreConfiguration, EmbeddedCoreLifecycle, EmbeddedCoreNetwork,
};
use std::{
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
};
use tempfile::TempDir;

const TX_HASH: [u8; 32] = [0x31; 32];
const KERNEL: [u8; 33] = [0x41; 33];

#[derive(Clone)]
struct FakeCore(Arc<Mutex<FakeState>>);

#[derive(Clone)]
struct FakeState {
    identity: ChainIdentity,
    sync_status: SyncStatus,
    ready: bool,
    policy: MempoolPolicySnapshot,
    submit: SubmissionResult,
    rebroadcast: SubmissionResult,
    query: SubmissionResult,
    status: TransactionStatus,
    submitted: Vec<Transaction>,
    rebroadcast_ids: Vec<TransactionIdentifier>,
    query_ids: Vec<TransactionIdentifier>,
}

impl FakeCore {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(FakeState {
            identity: core_identity(),
            sync_status: SyncStatus::Ready,
            ready: true,
            policy: MempoolPolicySnapshot {
                policy_version: 1,
                network: CoreNetwork::Regtest,
                min_relay_fee_rate: 2,
                min_mempool_fee_rate: 3,
                transaction_count: 4,
            },
            submit: result(SubmissionResultKind::Accepted, true, true, true),
            rebroadcast: result(SubmissionResultKind::AlreadyKnown, true, true, true),
            query: result(SubmissionResultKind::AlreadyKnown, true, false, false),
            status: TransactionStatus::InMempool,
            submitted: Vec::new(),
            rebroadcast_ids: Vec::new(),
            query_ids: Vec::new(),
        })))
    }

    fn service(&self) -> CoreSubmissionService {
        CoreSubmissionService::connect(Arc::new(self.clone()), wallet_identity()).unwrap()
    }

    fn update(&self, update: impl FnOnce(&mut FakeState)) {
        update(&mut self.0.lock().unwrap());
    }

    fn state(&self) -> FakeState {
        self.0.lock().unwrap().clone()
    }
}

impl WalletCoreApi for FakeCore {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        Ok(self.state().identity)
    }
    fn scan_range(&self, _: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        Err(WalletCoreError::InvalidScanRequest("unused".into()))
    }
    fn validate_cursor(&self, _: WalletScanCursor) -> Result<CursorValidation, WalletCoreError> {
        Err(WalletCoreError::InvalidScanRequest("unused".into()))
    }
    fn canonical_hash_at_height(&self, _: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        Ok(None)
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
        Ok(self.state().status)
    }
    fn submit_transaction(
        &self,
        request: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError> {
        let mut state = self.0.lock().unwrap();
        state.submitted.push(request.transaction);
        Ok(state.submit.clone())
    }
    fn rebroadcast_transaction(
        &self,
        id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        let mut state = self.0.lock().unwrap();
        state.rebroadcast_ids.push(id);
        Ok(state.rebroadcast.clone())
    }
    fn query_submission(
        &self,
        id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        let mut state = self.0.lock().unwrap();
        state.query_ids.push(id);
        Ok(state.query.clone())
    }
    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        Ok(self.state().sync_status)
    }
    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        Ok(self.state().ready)
    }
    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        Ok(self.state().policy)
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
    fn validate_fee(&self, _: &Transaction) -> Result<FeeValidation, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
}

fn core_identity() -> ChainIdentity {
    ChainIdentity {
        network: CoreNetwork::Regtest,
        network_magic: CoreNetwork::Regtest.magic(),
        chain_id: [8; 32],
        genesis_hash: [9; 32],
        protocol_version: dom_core::PROTOCOL_VERSION,
        range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        coinbase_maturity: 1,
        current_tip: BlockRef {
            height: 3,
            hash: [7; 32],
        },
    }
}

fn wallet_identity() -> CoreChainIdentity {
    let value = core_identity();
    CoreChainIdentity {
        network: value.network,
        network_magic: value.network_magic,
        chain_id: value.chain_id,
        genesis_hash: value.genesis_hash,
        protocol_version: value.protocol_version,
        range_proof_serialization_version: value.range_proof_serialization_version,
        coinbase_maturity: value.coinbase_maturity,
        current_tip: CoreBlockReference {
            height: value.current_tip.height,
            hash: value.current_tip.hash,
        },
    }
}

fn transaction() -> Transaction {
    Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: Vec::new(),
        offset: [5; 32],
    }
}

fn submission() -> CanonicalTransactionSubmission {
    CanonicalTransactionSubmission::new(transaction(), TX_HASH, Some(KERNEL)).unwrap()
}

fn result(
    kind: SubmissionResultKind,
    accepted: bool,
    broadcast: bool,
    relayed: bool,
) -> SubmissionResult {
    SubmissionResult {
        kind,
        tx_hash: TX_HASH,
        primary_kernel_excess: Some(KERNEL),
        accepted_to_mempool: accepted,
        broadcast_attempted: broadcast,
        relayed,
        diagnostic: diagnostic(kind),
    }
}

fn diagnostic(kind: SubmissionResultKind) -> Option<SubmissionDiagnostic> {
    match kind {
        SubmissionResultKind::Accepted => None,
        SubmissionResultKind::AlreadyKnown => Some(SubmissionDiagnostic::AlreadyKnown),
        SubmissionResultKind::RejectedInvalid => Some(SubmissionDiagnostic::Invalid),
        SubmissionResultKind::RejectedFee => Some(SubmissionDiagnostic::FeeTooLow),
        SubmissionResultKind::RejectedDoubleSpend => Some(SubmissionDiagnostic::DoubleSpend),
        SubmissionResultKind::RejectedImmatureCoinbase => {
            Some(SubmissionDiagnostic::ImmatureCoinbase)
        }
        SubmissionResultKind::RejectedExpired => Some(SubmissionDiagnostic::Locked),
        SubmissionResultKind::RejectedPolicy => Some(SubmissionDiagnostic::Policy),
        SubmissionResultKind::NodeNotReady | SubmissionResultKind::TemporaryFailure => {
            Some(SubmissionDiagnostic::NodeBusy)
        }
        SubmissionResultKind::InternalFailure => Some(SubmissionDiagnostic::Internal),
    }
}

fn set_submit_kind(core: &FakeCore, kind: SubmissionResultKind) {
    let accepted = matches!(
        kind,
        SubmissionResultKind::Accepted | SubmissionResultKind::AlreadyKnown
    );
    core.update(|state| state.submit = result(kind, accepted, false, false));
}

#[test]
fn readiness_false_while_starting() {
    let core = FakeCore::new();
    core.update(|state| {
        state.sync_status = SyncStatus::Starting;
        state.ready = false;
    });
    assert_eq!(
        core.service().readiness().unwrap().readiness,
        WalletReadiness::Starting
    );
}

#[test]
fn readiness_false_while_syncing() {
    let core = FakeCore::new();
    core.update(|state| {
        state.sync_status = SyncStatus::Syncing;
        state.ready = false;
    });
    assert_eq!(
        core.service().readiness().unwrap().readiness,
        WalletReadiness::Synchronizing
    );
}

#[test]
fn readiness_true_only_when_core_reports_ready() {
    let core = FakeCore::new();
    assert_eq!(
        core.service().readiness().unwrap().readiness,
        WalletReadiness::Ready
    );
    core.update(|state| state.ready = false);
    assert_eq!(
        core.service().readiness().unwrap().readiness,
        WalletReadiness::NotReady
    );
}

#[test]
fn submit_is_blocked_when_not_ready() {
    let core = FakeCore::new();
    core.update(|state| state.ready = false);
    assert!(matches!(
        core.service().submit_transaction(&submission()),
        Err(WalletSubmissionError::NotReady { .. })
    ));
    assert!(core.state().submitted.is_empty());
}

#[test]
fn accepted_and_relay_success_are_preserved() {
    let outcome = FakeCore::new()
        .service()
        .submit_transaction(&submission())
        .unwrap();
    assert!(matches!(outcome, WalletSubmissionOutcome::Accepted(_)));
    let evidence = outcome.evidence();
    assert!(evidence.accepted_to_mempool && evidence.broadcast_attempted && evidence.relayed);
}

#[test]
fn accepted_without_relay_remains_accepted() {
    let core = FakeCore::new();
    core.update(|state| state.submit = result(SubmissionResultKind::Accepted, true, true, false));
    let outcome = core.service().submit_transaction(&submission()).unwrap();
    assert!(matches!(outcome, WalletSubmissionOutcome::Accepted(_)));
    assert_eq!(
        transition_for_outcome(outcome).state,
        WalletSubmissionState::AcceptedNotRelayed
    );
}

#[test]
fn already_known_is_idempotent() {
    let core = FakeCore::new();
    set_submit_kind(&core, SubmissionResultKind::AlreadyKnown);
    let decision =
        transition_for_outcome(core.service().submit_transaction(&submission()).unwrap());
    assert_eq!(decision.state, WalletSubmissionState::AlreadyKnown);
    assert!(!decision.create_duplicate_transaction);
}

macro_rules! rejection_mapping_test {
    ($name:ident, $kind:expr, $variant:path, $state:expr) => {
        #[test]
        fn $name() {
            let core = FakeCore::new();
            set_submit_kind(&core, $kind);
            let outcome = core.service().submit_transaction(&submission()).unwrap();
            assert!(matches!(outcome, $variant(_)));
            let decision = transition_for_outcome(outcome);
            assert_eq!(decision.state, $state);
            assert!(!decision.release_reservations);
        }
    };
}

rejection_mapping_test!(
    rejected_invalid_mapping,
    SubmissionResultKind::RejectedInvalid,
    WalletSubmissionOutcome::RejectedInvalid,
    WalletSubmissionState::RejectedInvalid
);
rejection_mapping_test!(
    rejected_fee_mapping,
    SubmissionResultKind::RejectedFee,
    WalletSubmissionOutcome::RejectedFee,
    WalletSubmissionState::RejectedFee
);
rejection_mapping_test!(
    rejected_double_spend_mapping,
    SubmissionResultKind::RejectedDoubleSpend,
    WalletSubmissionOutcome::RejectedDoubleSpend,
    WalletSubmissionState::RejectedDoubleSpend
);
rejection_mapping_test!(
    rejected_immature_coinbase_mapping,
    SubmissionResultKind::RejectedImmatureCoinbase,
    WalletSubmissionOutcome::RejectedImmatureCoinbase,
    WalletSubmissionState::RejectedImmatureCoinbase
);
rejection_mapping_test!(
    rejected_expired_mapping,
    SubmissionResultKind::RejectedExpired,
    WalletSubmissionOutcome::RejectedExpired,
    WalletSubmissionState::RejectedExpired
);
rejection_mapping_test!(
    rejected_policy_mapping,
    SubmissionResultKind::RejectedPolicy,
    WalletSubmissionOutcome::RejectedPolicy,
    WalletSubmissionState::RejectedPolicy
);
rejection_mapping_test!(
    node_not_ready_mapping,
    SubmissionResultKind::NodeNotReady,
    WalletSubmissionOutcome::NodeNotReady,
    WalletSubmissionState::NodeNotReady
);
rejection_mapping_test!(
    temporary_failure_mapping,
    SubmissionResultKind::TemporaryFailure,
    WalletSubmissionOutcome::TemporaryFailure,
    WalletSubmissionState::TemporarilyUncertain
);
rejection_mapping_test!(
    internal_failure_mapping,
    SubmissionResultKind::InternalFailure,
    WalletSubmissionOutcome::InternalFailure,
    WalletSubmissionState::InternalUncertain
);

#[test]
fn transaction_and_kernel_identity_are_preserved() {
    let outcome = FakeCore::new()
        .service()
        .submit_transaction(&submission())
        .unwrap();
    assert_eq!(outcome.evidence().transaction_hash, TX_HASH);
    assert_eq!(outcome.evidence().primary_kernel_excess, Some(KERNEL));
}

#[test]
fn stable_diagnostic_is_preserved_without_text() {
    let core = FakeCore::new();
    set_submit_kind(&core, SubmissionResultKind::RejectedFee);
    let evidence = core
        .service()
        .submit_transaction(&submission())
        .unwrap()
        .evidence();
    assert_eq!(format!("{:?}", evidence.diagnostic), "Some(FeeTooLow)");
}

#[test]
fn rebroadcast_uses_exact_core_identifier_repeatedly() {
    let core = FakeCore::new();
    let service = core.service();
    let id = WalletTransactionIdentifier::TransactionHash(TX_HASH);
    service.rebroadcast_transaction(id).unwrap();
    service.rebroadcast_transaction(id).unwrap();
    assert_eq!(
        core.state().rebroadcast_ids,
        vec![TransactionIdentifier::TxHash(TX_HASH); 2]
    );
}

#[test]
fn timeout_query_known_in_mempool() {
    let query = FakeCore::new()
        .service()
        .query_submission(WalletTransactionIdentifier::TransactionHash(TX_HASH))
        .unwrap();
    assert!(matches!(query, WalletSubmissionQuery::InMempool(_)));
}

#[test]
fn timeout_query_confirmed() {
    let core = FakeCore::new();
    core.update(|state| {
        state.status = TransactionStatus::Confirmed(BlockRef {
            height: 12,
            hash: [0x77; 32],
        })
    });
    let query = core
        .service()
        .query_submission(WalletTransactionIdentifier::TransactionHash(TX_HASH))
        .unwrap();
    assert!(matches!(
        query,
        WalletSubmissionQuery::Confirmed { height: 12, .. }
    ));
}

#[test]
fn timeout_query_unknown_is_not_rejection() {
    let core = FakeCore::new();
    core.update(|state| {
        state.status = TransactionStatus::Unknown;
        state.query = result(SubmissionResultKind::RejectedPolicy, false, false, false);
        state.query.diagnostic = None;
    });
    let query = core
        .service()
        .query_submission(WalletTransactionIdentifier::TransactionHash(TX_HASH))
        .unwrap();
    assert_eq!(query, WalletSubmissionQuery::Unknown);
}

#[test]
fn timeout_query_explicit_rejection() {
    let core = FakeCore::new();
    core.update(|state| {
        state.status = TransactionStatus::Unknown;
        state.query = result(SubmissionResultKind::RejectedFee, false, false, false);
    });
    let query = core
        .service()
        .query_submission(WalletTransactionIdentifier::TransactionHash(TX_HASH))
        .unwrap();
    assert!(matches!(
        query,
        WalletSubmissionQuery::Rejected(WalletSubmissionOutcome::RejectedFee(_))
    ));
}

#[test]
fn timeout_query_invalid_is_an_explicit_rejection() {
    let core = FakeCore::new();
    core.update(|state| {
        state.status = TransactionStatus::Unknown;
        state.query = result(SubmissionResultKind::RejectedInvalid, false, false, false);
    });
    let query = core
        .service()
        .query_submission(WalletTransactionIdentifier::TransactionHash(TX_HASH))
        .unwrap();
    assert!(matches!(
        query,
        WalletSubmissionQuery::Rejected(WalletSubmissionOutcome::RejectedInvalid(_))
    ));
}

#[test]
fn timeout_query_temporary_failure_remains_uncertain() {
    let core = FakeCore::new();
    core.update(|state| {
        state.status = TransactionStatus::Unknown;
        state.query = result(SubmissionResultKind::TemporaryFailure, false, false, false);
    });
    let query = core
        .service()
        .query_submission(WalletTransactionIdentifier::TransactionHash(TX_HASH))
        .unwrap();
    assert!(matches!(
        query,
        WalletSubmissionQuery::TemporarilyUnavailable(_)
    ));
}

#[test]
fn restart_query_converges_to_confirmation() {
    let core = FakeCore::new();
    let first = core.service();
    core.update(|state| state.status = TransactionStatus::Unknown);
    assert_eq!(
        first
            .transaction_status(WalletTransactionIdentifier::TransactionHash(TX_HASH))
            .unwrap(),
        WalletTransactionStatus::Unknown
    );
    drop(first);
    core.update(|state| {
        state.status = TransactionStatus::Confirmed(BlockRef {
            height: 14,
            hash: [0x55; 32],
        })
    });
    assert!(matches!(
        core.service()
            .transaction_status(WalletTransactionIdentifier::TransactionHash(TX_HASH))
            .unwrap(),
        WalletTransactionStatus::Confirmed { height: 14, .. }
    ));
}

#[test]
fn canonical_transaction_is_forwarded_without_mutation() {
    let core = FakeCore::new();
    let original = transaction();
    let submission =
        CanonicalTransactionSubmission::new(original.clone(), TX_HASH, Some(KERNEL)).unwrap();
    core.service().submit_transaction(&submission).unwrap();
    assert_eq!(core.state().submitted, vec![original]);
}

#[test]
fn uncertain_decisions_never_release_or_rebuild() {
    let core = FakeCore::new();
    set_submit_kind(&core, SubmissionResultKind::TemporaryFailure);
    let decision =
        transition_for_outcome(core.service().submit_transaction(&submission()).unwrap());
    assert!(
        !decision.release_reservations && !decision.rebuild_transaction && !decision.mutate_fee
    );
}

#[test]
fn rejected_fee_never_mutates_fee() {
    let core = FakeCore::new();
    set_submit_kind(&core, SubmissionResultKind::RejectedFee);
    assert!(
        !transition_for_outcome(core.service().submit_transaction(&submission()).unwrap())
            .mutate_fee
    );
}

#[test]
fn policy_snapshot_is_network_version_and_chain_bound() {
    let snapshot = FakeCore::new().service().readiness().unwrap();
    assert_eq!(snapshot.mempool_policy.network, CoreNetwork::Regtest);
    assert_eq!(snapshot.mempool_policy.policy_version, 1);
    assert_eq!(snapshot.mempool_policy.chain_id, [8; 32]);
}

#[test]
fn inconsistent_policy_network_fails_closed() {
    let core = FakeCore::new();
    core.update(|state| state.policy.network = CoreNetwork::Testnet);
    assert!(matches!(
        core.service().readiness(),
        Err(WalletSubmissionError::IdentityMismatch { .. })
    ));
}

#[test]
fn changed_chain_identity_fails_closed() {
    let core = FakeCore::new();
    let service = core.service();
    core.update(|state| state.identity.chain_id = [0x99; 32]);
    assert!(matches!(
        service.readiness(),
        Err(WalletSubmissionError::IdentityMismatch { .. })
    ));
}

#[test]
fn malformed_result_relay_without_broadcast_fails_closed() {
    let core = FakeCore::new();
    core.update(|state| state.submit = result(SubmissionResultKind::Accepted, true, false, true));
    assert!(matches!(
        core.service().submit_transaction(&submission()),
        Err(WalletSubmissionError::InconsistentResult { .. })
    ));
}

#[test]
fn malformed_result_hash_mismatch_fails_closed() {
    let core = FakeCore::new();
    core.update(|state| state.submit.tx_hash = [0x88; 32]);
    assert!(matches!(
        core.service().submit_transaction(&submission()),
        Err(WalletSubmissionError::InconsistentResult { .. })
    ));
}

#[test]
fn malformed_result_acceptance_flag_fails_closed() {
    let core = FakeCore::new();
    core.update(|state| state.submit.accepted_to_mempool = false);
    assert!(matches!(
        core.service().submit_transaction(&submission()),
        Err(WalletSubmissionError::InconsistentResult { .. })
    ));
}

#[test]
fn confirmed_then_unknown_is_reorged_not_rejected() {
    let decision = transition_for_status(
        WalletSubmissionState::Confirmed,
        WalletTransactionStatus::Unknown,
    );
    assert_eq!(decision.state, WalletSubmissionState::Reorged);
    assert!(!decision.release_reservations);
}

#[test]
fn api_unavailable_before_embedded_startup() {
    let directory = TempDir::new().unwrap();
    let lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::new(
        EmbeddedCoreNetwork::Regtest,
        directory.path(),
        "127.0.0.1:1".parse().unwrap(),
    ));
    assert!(lifecycle.wallet_api().is_err());
}

#[test]
fn real_embedded_core_readiness_and_stale_handle_are_gated() {
    let directory = TempDir::new().unwrap();
    let mut lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::new(
        EmbeddedCoreNetwork::Regtest,
        directory.path(),
        unused_loopback_address(),
    ));
    lifecycle.start().expect("start isolated Core");
    let api = lifecycle.wallet_api().unwrap();
    let identity = api.chain_identity().unwrap();
    let service = CoreSubmissionService::connect(
        api,
        CoreChainIdentity {
            network: identity.network,
            network_magic: identity.network_magic,
            chain_id: identity.chain_id,
            genesis_hash: identity.genesis_hash,
            protocol_version: identity.protocol_version,
            range_proof_serialization_version: identity.range_proof_serialization_version,
            coinbase_maturity: identity.coinbase_maturity,
            current_tip: CoreBlockReference {
                height: identity.current_tip.height,
                hash: identity.current_tip.hash,
            },
        },
    )
    .unwrap();
    assert_eq!(
        service.readiness().unwrap().readiness,
        WalletReadiness::Ready
    );
    lifecycle.request_shutdown().unwrap();
    lifecycle.wait_for_shutdown().unwrap();
    assert!(matches!(
        service.readiness(),
        Err(WalletSubmissionError::CoreUnavailable { .. })
    ));
    assert!(matches!(
        service.submit_transaction(&submission()),
        Err(WalletSubmissionError::CoreUnavailable { .. })
    ));
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

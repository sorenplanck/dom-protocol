//! Adversarial coverage for the durable Solana actuator: byte custody,
//! idempotent mutations, fencing, quorum promotion and the expiry proof.

use solana_actuator::{
    custody_digest_v1, DurableSolanaActuatorV1, SolanaActuatorErrorV1, SolanaActuatorLeaseV1,
    SolanaOperationKindV1, SolanaOperationLocatorV1, SolanaOperationStoreV1,
    SolanaReconciliationKindV1, SolanaTxStageV1,
};
use solana_rpc::{RpcError, SolanaRpc};
use solana_rpc_pool::SolanaRpcPool;
use solana_types::{
    Commitment, SolanaAccountSnapshot, SolanaBlockAnchor, SolanaHash, SolanaPubkey,
    SolanaSignature, SolanaSignatureStatus, SolanaTransactionRecord,
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MockState {
    block_height: u64,
    status: Option<SolanaSignatureStatus>,
    status_error: bool,
    transaction: Option<SolanaTransactionRecord>,
    anchor: Option<SolanaBlockAnchor>,
    send_echo: Option<SolanaSignature>,
    sent: Vec<Vec<u8>>,
}

#[derive(Default)]
struct MockRpc {
    state: Mutex<MockState>,
}

impl MockRpc {
    fn set(&self, mutate: impl FnOnce(&mut MockState)) {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        mutate(&mut guard);
    }

    fn sent(&self) -> Vec<Vec<u8>> {
        match self.state.lock() {
            Ok(guard) => guard.sent.clone(),
            Err(poisoned) => poisoned.into_inner().sent.clone(),
        }
    }
}

impl SolanaRpc for MockRpc {
    fn get_slot(&self, _commitment: Commitment) -> Result<u64, RpcError> {
        Ok(0)
    }

    fn get_block_height(&self, _commitment: Commitment) -> Result<u64, RpcError> {
        let guard = self.state.lock().map_err(|_| RpcError::Unavailable)?;
        Ok(guard.block_height)
    }

    fn get_block_anchor(&self, slot: u64) -> Result<Option<SolanaBlockAnchor>, RpcError> {
        let guard = self.state.lock().map_err(|_| RpcError::Unavailable)?;
        Ok(guard.anchor.filter(|anchor| anchor.slot == slot))
    }

    fn get_account(
        &self,
        _key: SolanaPubkey,
        _commitment: Commitment,
    ) -> Result<Option<SolanaAccountSnapshot>, RpcError> {
        Err(RpcError::Unavailable)
    }

    fn get_signature_status(
        &self,
        _signature: SolanaSignature,
    ) -> Result<Option<SolanaSignatureStatus>, RpcError> {
        let guard = self.state.lock().map_err(|_| RpcError::Unavailable)?;
        if guard.status_error {
            return Err(RpcError::Unavailable);
        }
        Ok(guard.status)
    }

    fn get_transaction(
        &self,
        _signature: SolanaSignature,
        _commitment: Commitment,
    ) -> Result<Option<SolanaTransactionRecord>, RpcError> {
        let guard = self.state.lock().map_err(|_| RpcError::Unavailable)?;
        Ok(guard.transaction.clone())
    }

    fn get_latest_blockhash(&self) -> Result<SolanaHash, RpcError> {
        Err(RpcError::Unavailable)
    }

    fn get_latest_blockhash_with_validity(&self) -> Result<(SolanaHash, u64), RpcError> {
        Err(RpcError::Unavailable)
    }

    fn send_transaction(&self, raw_transaction: &[u8]) -> Result<SolanaSignature, RpcError> {
        let mut guard = self.state.lock().map_err(|_| RpcError::Unavailable)?;
        guard.sent.push(raw_transaction.to_vec());
        guard.send_echo.ok_or(RpcError::Unavailable)
    }
}

const NOW: u64 = 1_000_000;

fn lease(fence: u64) -> SolanaActuatorLeaseV1 {
    SolanaActuatorLeaseV1::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        SolanaPubkey([0x44; 32]),
        fence,
        NOW + 60_000,
    )
    .unwrap_or_else(|_| panic!("lease"))
}

fn locator() -> SolanaOperationLocatorV1 {
    SolanaOperationLocatorV1 {
        settlement_id: [0x55; 32],
        kind: SolanaOperationKindV1::Claim,
    }
}

fn signature() -> SolanaSignature {
    SolanaSignature([0x66; 64])
}

fn blockhash() -> SolanaHash {
    SolanaHash([0x77; 32])
}

fn raw() -> Vec<u8> {
    vec![0xAB; 200]
}

fn fixture() -> (tempfile::TempDir, DurableSolanaActuatorV1) {
    let dir = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let store = SolanaOperationStoreV1::open(dir.path().join("solana-actuator.sqlite"))
        .unwrap_or_else(|_| panic!("open"));
    (dir, DurableSolanaActuatorV1::new(store))
}

fn prepared() -> (tempfile::TempDir, DurableSolanaActuatorV1) {
    let (dir, actuator) = fixture();
    actuator
        .prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &raw(),
            blockhash(),
            500,
            NOW,
        )
        .unwrap_or_else(|_| panic!("prepare"));
    (dir, actuator)
}

fn pool(node: &Arc<MockRpc>) -> SolanaRpcPool<MockRpc> {
    SolanaRpcPool::new(vec![Arc::clone(node)], 1).unwrap_or_else(|_| panic!("pool"))
}

#[test]
fn prepare_is_idempotent_on_identical_replay_and_conflicts_on_divergence() {
    let (_dir, actuator) = prepared();
    let replay = actuator
        .prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &raw(),
            blockhash(),
            500,
            NOW,
        )
        .unwrap_or_else(|_| panic!("replay"));
    assert_eq!(replay.revision, 1);
    assert_eq!(replay.stage, SolanaTxStageV1::Signed);
    assert!(replay.secret_exposed);
    let mut other = raw();
    other[0] ^= 1;
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &other,
            blockhash(),
            500,
            NOW
        ),
        Err(SolanaActuatorErrorV1::Conflict)
    );
}

#[test]
fn prepare_refuses_out_of_bounds_inputs_and_expired_leases() {
    let (_dir, actuator) = fixture();
    let zero_id = SolanaOperationLocatorV1 {
        settlement_id: [0; 32],
        kind: SolanaOperationKindV1::Fund,
    };
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            zero_id,
            signature(),
            &raw(),
            blockhash(),
            500,
            NOW
        ),
        Err(SolanaActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &[],
            blockhash(),
            500,
            NOW
        ),
        Err(SolanaActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &vec![0; 1_233],
            blockhash(),
            500,
            NOW
        ),
        Err(SolanaActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &raw(),
            SolanaHash([0; 32]),
            500,
            NOW
        ),
        Err(SolanaActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &raw(),
            blockhash(),
            0,
            NOW
        ),
        Err(SolanaActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            signature(),
            &raw(),
            blockhash(),
            500,
            NOW + 120_000
        ),
        Err(SolanaActuatorErrorV1::LeaseExpired)
    );
}

#[test]
fn broadcast_records_send_attempted_before_offering_exact_bytes() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| state.send_echo = Some(signature()));
    let outcome = actuator
        .broadcast_current(&lease(1), locator(), [0x01; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    assert_eq!(outcome.view.stage, SolanaTxStageV1::SendAttempted);
    assert_eq!(outcome.accepted, 1);
    assert_eq!(outcome.contacted, 1);
    assert_eq!(node.sent(), vec![raw()]);
}

#[test]
fn broadcast_counts_only_nodes_echoing_the_retained_signature() {
    let (_dir, actuator) = prepared();
    let honest = Arc::new(MockRpc::default());
    honest.set(|state| state.send_echo = Some(signature()));
    let liar = Arc::new(MockRpc::default());
    liar.set(|state| state.send_echo = Some(SolanaSignature([0x99; 64])));
    let pool = SolanaRpcPool::new(vec![Arc::clone(&honest), Arc::clone(&liar)], 1)
        .unwrap_or_else(|_| panic!("pool"));
    let outcome = actuator
        .broadcast_current(&lease(1), locator(), [0x02; 32], &pool, NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    assert_eq!(outcome.accepted, 1);
    assert_eq!(outcome.contacted, 2);
}

#[test]
fn broadcast_attempt_replay_does_not_advance_revision_twice() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| state.send_echo = Some(signature()));
    let first = actuator
        .broadcast_current(&lease(1), locator(), [0x03; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("first"));
    let replay = actuator
        .broadcast_current(&lease(1), locator(), [0x03; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("replay"));
    assert_eq!(first.view.revision, replay.view.revision);
    // The bytes may be re-offered — retransmission is byte-exact and safe —
    // but the durable attempt is recorded exactly once.
    assert_eq!(node.sent().len(), 2);
}

#[test]
fn observe_promotes_to_observed_below_finality_and_final_with_facts() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| {
        state.status = Some(SolanaSignatureStatus {
            slot: 900,
            confirmation: Commitment::Confirmed,
            failed: false,
        });
    });
    let observed = actuator
        .observe_current(&lease(1), locator(), [0x04; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("observe"));
    assert_eq!(observed.stage, SolanaTxStageV1::Observed);
    assert!(observed.finality.is_none());
    let record = SolanaTransactionRecord {
        slot: 901,
        signature: signature(),
        recent_blockhash: blockhash(),
        success: true,
        instructions: Vec::new(),
    };
    node.set(|state| {
        state.status = Some(SolanaSignatureStatus {
            slot: 901,
            confirmation: Commitment::Finalized,
            failed: false,
        });
        state.transaction = Some(record.clone());
        state.anchor = Some(SolanaBlockAnchor {
            slot: 901,
            blockhash: SolanaHash([0x88; 32]),
        });
    });
    let finalized = actuator
        .observe_current(&lease(1), locator(), [0x05; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("finalize"));
    assert_eq!(finalized.stage, SolanaTxStageV1::Final);
    let facts = finalized.finality.unwrap_or_else(|| panic!("facts"));
    assert_eq!(facts.final_slot, 901);
    assert_eq!(facts.final_blockhash, SolanaHash([0x88; 32]));
    assert_eq!(facts.final_evidence_digest, record.commitment_hash());
}

#[test]
fn observe_refuses_finality_evidence_naming_different_bytes() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| {
        state.status = Some(SolanaSignatureStatus {
            slot: 901,
            confirmation: Commitment::Finalized,
            failed: false,
        });
        state.transaction = Some(SolanaTransactionRecord {
            slot: 901,
            signature: signature(),
            recent_blockhash: SolanaHash([0xEE; 32]),
            success: true,
            instructions: Vec::new(),
        });
        state.anchor = Some(SolanaBlockAnchor {
            slot: 901,
            blockhash: SolanaHash([0x88; 32]),
        });
    });
    assert_eq!(
        actuator.observe_current(&lease(1), locator(), [0x06; 32], &pool(&node), NOW),
        Err(SolanaActuatorErrorV1::Corrupt)
    );
}

#[test]
fn observe_marks_a_landed_failed_transaction_finality_invalidated() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| {
        state.status = Some(SolanaSignatureStatus {
            slot: 902,
            confirmation: Commitment::Confirmed,
            failed: true,
        });
    });
    let view = actuator
        .observe_current(&lease(1), locator(), [0x07; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("observe"));
    assert_eq!(view.stage, SolanaTxStageV1::FinalityInvalidated);
    // Publicity is monotone even for a failed landing.
    assert!(view.secret_exposed);
}

#[test]
fn observe_without_evidence_changes_nothing() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    let view = actuator
        .observe_current(&lease(1), locator(), [0x08; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("observe"));
    assert_eq!(view.stage, SolanaTxStageV1::Signed);
    assert_eq!(view.revision, 1);
}

#[test]
fn stale_fence_reads_but_never_writes() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| state.send_echo = Some(signature()));
    actuator
        .broadcast_current(&lease(5), locator(), [0x09; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    assert_eq!(
        actuator.broadcast_current(&lease(4), locator(), [0x0A; 32], &pool(&node), NOW),
        Err(SolanaActuatorErrorV1::Conflict)
    );
    assert!(actuator.view(locator()).is_ok());
}

#[test]
fn lease_for_a_different_cluster_is_refused() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| state.send_echo = Some(signature()));
    let foreign = SolanaActuatorLeaseV1::new(
        [0x11; 32],
        [0x22; 32],
        [0xAA; 32],
        SolanaPubkey([0x44; 32]),
        9,
        NOW + 60_000,
    )
    .unwrap_or_else(|_| panic!("lease"));
    assert_eq!(
        actuator.broadcast_current(&foreign, locator(), [0x0B; 32], &pool(&node), NOW),
        Err(SolanaActuatorErrorV1::Conflict)
    );
}

#[test]
fn reconcile_expiry_is_the_positive_proof_of_never_landed() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| state.send_echo = Some(signature()));
    actuator
        .broadcast_current(&lease(1), locator(), [0x0C; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    // Inside the window: absence proves nothing and writes nothing.
    node.set(|state| state.block_height = 500);
    let ambiguous = actuator
        .reconcile_takeover(&lease(2), locator(), [0x0D; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("reconcile"));
    assert_eq!(ambiguous.kind, SolanaReconciliationKindV1::Unknown);
    assert_eq!(ambiguous.view.stage, SolanaTxStageV1::SendAttempted);
    // Past the window: the retained bytes can never land.
    node.set(|state| state.block_height = 501);
    let proven = actuator
        .reconcile_takeover(&lease(2), locator(), [0x0E; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("reconcile"));
    assert_eq!(proven.kind, SolanaReconciliationKindV1::ExpiredNeverLanded);
    assert_eq!(proven.view.stage, SolanaTxStageV1::Reconciled);
    assert_eq!(
        proven.view.reconciliation_kind,
        Some(SolanaReconciliationKindV1::ExpiredNeverLanded)
    );
}

#[test]
fn reconcile_finds_finalized_evidence_and_promotes_to_final() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    let record = SolanaTransactionRecord {
        slot: 950,
        signature: signature(),
        recent_blockhash: blockhash(),
        success: true,
        instructions: Vec::new(),
    };
    node.set(|state| {
        state.status = Some(SolanaSignatureStatus {
            slot: 950,
            confirmation: Commitment::Finalized,
            failed: false,
        });
        state.transaction = Some(record);
        state.anchor = Some(SolanaBlockAnchor {
            slot: 950,
            blockhash: SolanaHash([0xCC; 32]),
        });
    });
    let outcome = actuator
        .reconcile_takeover(&lease(2), locator(), [0x0F; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("reconcile"));
    assert_eq!(outcome.kind, SolanaReconciliationKindV1::Final);
    assert_eq!(outcome.view.stage, SolanaTxStageV1::Final);
    assert!(outcome.view.finality.is_some());
    assert_eq!(
        outcome.view.reconciliation_kind,
        Some(SolanaReconciliationKindV1::Final)
    );
}

#[test]
fn reconcile_absence_never_downgrades_recorded_evidence() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| {
        state.status = Some(SolanaSignatureStatus {
            slot: 960,
            confirmation: Commitment::Confirmed,
            failed: false,
        });
    });
    actuator
        .observe_current(&lease(1), locator(), [0x10; 32], &pool(&node), NOW)
        .unwrap_or_else(|_| panic!("observe"));
    node.set(|state| {
        state.status = None;
        state.block_height = 10_000;
    });
    assert_eq!(
        actuator
            .reconcile_takeover(&lease(2), locator(), [0x11; 32], &pool(&node), NOW)
            .map(|outcome| outcome.kind),
        Err(SolanaActuatorErrorV1::Conflict)
    );
}

#[test]
fn reconcile_refuses_when_the_quorum_is_dark() {
    let (_dir, actuator) = prepared();
    let node = Arc::new(MockRpc::default());
    node.set(|state| state.status_error = true);
    assert_eq!(
        actuator
            .reconcile_takeover(&lease(2), locator(), [0x12; 32], &pool(&node), NOW)
            .map(|outcome| outcome.kind),
        Err(SolanaActuatorErrorV1::QuorumUnavailable)
    );
}

#[test]
fn retained_bytes_round_trip_and_custody_digest_binds_them() {
    let (_dir, actuator) = prepared();
    let view = actuator.view(locator()).unwrap_or_else(|_| panic!("view"));
    assert_eq!(
        view.custody_digest,
        custody_digest_v1(&raw()).unwrap_or_else(|_| panic!("digest"))
    );
}

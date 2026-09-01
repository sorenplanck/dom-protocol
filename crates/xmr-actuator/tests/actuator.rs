//! Adversarial coverage for the durable Monero actuator: byte custody,
//! idempotent mutations, fencing, verified depth and the key-image
//! absence statement.

use xmr_actuator::{
    custody_digest_v1, DurableXmrActuatorV1, XmrActuatorErrorV1, XmrActuatorLeaseV1,
    XmrObservationPortV1, XmrOperationKindV1, XmrOperationLocatorV1, XmrOperationStoreV1,
    XmrReconciliationKindV1, XmrTxInclusionV1, XmrTxStageV1,
};
use xmr_spend_port::{BroadcastAcceptance, ExactBroadcastPort, SpendPortError};

#[derive(Default)]
struct MockBroadcast {
    accept: Option<BroadcastAcceptance>,
    submitted: Vec<([u8; 32], Vec<u8>)>,
}

impl ExactBroadcastPort for MockBroadcast {
    fn submit_exact(
        &mut self,
        tx_hash: [u8; 32],
        raw_tx: &[u8],
    ) -> Result<BroadcastAcceptance, SpendPortError> {
        self.submitted.push((tx_hash, raw_tx.to_vec()));
        self.accept.ok_or(SpendPortError::Retryable)
    }
}

#[derive(Default)]
struct MockObservation {
    inclusion: Option<XmrTxInclusionV1>,
    inclusion_error: bool,
    key_image_spent: bool,
}

impl XmrObservationPortV1 for MockObservation {
    fn transaction_inclusion(
        &mut self,
        _tx_hash: [u8; 32],
    ) -> Result<Option<XmrTxInclusionV1>, XmrActuatorErrorV1> {
        if self.inclusion_error {
            return Err(XmrActuatorErrorV1::ObservationUnavailable);
        }
        Ok(self.inclusion)
    }

    fn key_image_spent(&mut self, _key_image: [u8; 32]) -> Result<bool, XmrActuatorErrorV1> {
        Ok(self.key_image_spent)
    }
}

const NOW: u64 = 1_000_000;
const MIN_CONFIRMATIONS: u64 = 10;

fn lease(fence: u64) -> XmrActuatorLeaseV1 {
    XmrActuatorLeaseV1::new([0x11; 32], [0x22; 32], [0x33; 32], fence, NOW + 60_000)
        .unwrap_or_else(|_| panic!("lease"))
}

fn locator() -> XmrOperationLocatorV1 {
    XmrOperationLocatorV1 {
        settlement_id: [0x55; 32],
        kind: XmrOperationKindV1::Claim,
    }
}

fn raw() -> Vec<u8> {
    vec![0xAB; 512]
}

fn prepared() -> (tempfile::TempDir, DurableXmrActuatorV1) {
    let dir = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let store = XmrOperationStoreV1::open(dir.path().join("xmr-actuator.sqlite"))
        .unwrap_or_else(|_| panic!("open"));
    let actuator = DurableXmrActuatorV1::new(store);
    actuator
        .prepare_signed(&lease(1), locator(), [0x66; 32], [0x67; 32], &raw(), NOW)
        .unwrap_or_else(|_| panic!("prepare"));
    (dir, actuator)
}

#[test]
fn prepare_is_idempotent_and_conflicts_on_divergent_bytes() {
    let (_dir, actuator) = prepared();
    let replay = actuator
        .prepare_signed(&lease(1), locator(), [0x66; 32], [0x67; 32], &raw(), NOW)
        .unwrap_or_else(|_| panic!("replay"));
    assert_eq!(replay.revision, 1);
    assert_eq!(replay.stage, XmrTxStageV1::Signed);
    let mut other = raw();
    other[0] ^= 1;
    assert_eq!(
        actuator.prepare_signed(&lease(1), locator(), [0x66; 32], [0x67; 32], &other, NOW),
        Err(XmrActuatorErrorV1::Conflict)
    );
    assert_eq!(
        actuator.prepare_signed(&lease(1), locator(), [0x68; 32], [0x67; 32], &raw(), NOW),
        Err(XmrActuatorErrorV1::Conflict)
    );
}

#[test]
fn prepare_refuses_zero_fields_oversize_and_expired_lease() {
    let dir = tempfile::tempdir().unwrap_or_else(|_| panic!("tempdir"));
    let store = XmrOperationStoreV1::open(dir.path().join("a.sqlite"))
        .unwrap_or_else(|_| panic!("open"));
    let actuator = DurableXmrActuatorV1::new(store);
    assert_eq!(
        actuator.prepare_signed(&lease(1), locator(), [0; 32], [0x67; 32], &raw(), NOW),
        Err(XmrActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(&lease(1), locator(), [0x66; 32], [0; 32], &raw(), NOW),
        Err(XmrActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(&lease(1), locator(), [0x66; 32], [0x67; 32], &[], NOW),
        Err(XmrActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            [0x66; 32],
            [0x67; 32],
            &vec![0; xmr_actuator::MAX_RAW_TX_BYTES_V1 + 1],
            NOW
        ),
        Err(XmrActuatorErrorV1::InvalidInput)
    );
    assert_eq!(
        actuator.prepare_signed(
            &lease(1),
            locator(),
            [0x66; 32],
            [0x67; 32],
            &raw(),
            NOW + 120_000
        ),
        Err(XmrActuatorErrorV1::LeaseExpired)
    );
}

#[test]
fn broadcast_records_send_attempted_before_offering_exact_bytes() {
    let (_dir, actuator) = prepared();
    let mut port = MockBroadcast {
        accept: Some(BroadcastAcceptance::Accepted),
        submitted: Vec::new(),
    };
    let outcome = actuator
        .broadcast_current(&lease(1), locator(), [0x01; 32], &mut port, NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    assert_eq!(outcome.view.stage, XmrTxStageV1::SendAttempted);
    assert!(outcome.accepted);
    assert_eq!(port.submitted, vec![([0x66; 32], raw())]);
    // AlreadyKnown also counts: bytes live in a pool or chain somewhere.
    let mut known = MockBroadcast {
        accept: Some(BroadcastAcceptance::AlreadyKnown),
        submitted: Vec::new(),
    };
    let outcome = actuator
        .broadcast_current(&lease(1), locator(), [0x02; 32], &mut known, NOW)
        .unwrap_or_else(|_| panic!("rebroadcast"));
    assert!(outcome.accepted);
}

#[test]
fn broadcast_attempt_replay_does_not_advance_revision_twice() {
    let (_dir, actuator) = prepared();
    let mut port = MockBroadcast {
        accept: Some(BroadcastAcceptance::Accepted),
        submitted: Vec::new(),
    };
    let first = actuator
        .broadcast_current(&lease(1), locator(), [0x03; 32], &mut port, NOW)
        .unwrap_or_else(|_| panic!("first"));
    let replay = actuator
        .broadcast_current(&lease(1), locator(), [0x03; 32], &mut port, NOW)
        .unwrap_or_else(|_| panic!("replay"));
    assert_eq!(first.view.revision, replay.view.revision);
    assert_eq!(port.submitted.len(), 2);
}

#[test]
fn observe_promotes_only_at_the_required_depth() {
    let (_dir, actuator) = prepared();
    let mut port = MockObservation {
        inclusion: Some(XmrTxInclusionV1 {
            height: 900,
            block_hash: [0x88; 32],
            confirmations: MIN_CONFIRMATIONS - 1,
        }),
        ..Default::default()
    };
    let observed = actuator
        .observe_current(&lease(1), locator(), [0x04; 32], &mut port, MIN_CONFIRMATIONS, NOW)
        .unwrap_or_else(|_| panic!("observe"));
    assert_eq!(observed.stage, XmrTxStageV1::Observed);
    assert!(observed.finality.is_none());
    port.inclusion = Some(XmrTxInclusionV1 {
        height: 900,
        block_hash: [0x88; 32],
        confirmations: MIN_CONFIRMATIONS,
    });
    let finalized = actuator
        .observe_current(&lease(1), locator(), [0x05; 32], &mut port, MIN_CONFIRMATIONS, NOW)
        .unwrap_or_else(|_| panic!("finalize"));
    assert_eq!(finalized.stage, XmrTxStageV1::Final);
    let facts = finalized.finality.unwrap_or_else(|| panic!("facts"));
    assert_eq!(facts.final_height, 900);
    assert_eq!(facts.final_block_hash, [0x88; 32]);
    assert_ne!(facts.final_evidence_digest, [0; 32]);
}

#[test]
fn observe_refuses_zero_depth_and_absent_changes_nothing() {
    let (_dir, actuator) = prepared();
    let mut port = MockObservation::default();
    assert_eq!(
        actuator.observe_current(&lease(1), locator(), [0x06; 32], &mut port, 0, NOW),
        Err(XmrActuatorErrorV1::InvalidInput)
    );
    let view = actuator
        .observe_current(&lease(1), locator(), [0x07; 32], &mut port, MIN_CONFIRMATIONS, NOW)
        .unwrap_or_else(|_| panic!("observe"));
    assert_eq!(view.stage, XmrTxStageV1::Signed);
    assert_eq!(view.revision, 1);
}

#[test]
fn stale_fence_reads_but_never_writes() {
    let (_dir, actuator) = prepared();
    let mut port = MockBroadcast {
        accept: Some(BroadcastAcceptance::Accepted),
        submitted: Vec::new(),
    };
    actuator
        .broadcast_current(&lease(5), locator(), [0x08; 32], &mut port, NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    assert_eq!(
        actuator.broadcast_current(&lease(4), locator(), [0x09; 32], &mut port, NOW),
        Err(XmrActuatorErrorV1::Conflict)
    );
    assert!(actuator.view(locator()).is_ok());
}

#[test]
fn lease_for_a_different_network_is_refused() {
    let (_dir, actuator) = prepared();
    let foreign = XmrActuatorLeaseV1::new([0x11; 32], [0x22; 32], [0xAA; 32], 9, NOW + 60_000)
        .unwrap_or_else(|_| panic!("lease"));
    let mut port = MockBroadcast {
        accept: Some(BroadcastAcceptance::Accepted),
        submitted: Vec::new(),
    };
    assert_eq!(
        actuator.broadcast_current(&foreign, locator(), [0x0A; 32], &mut port, NOW),
        Err(XmrActuatorErrorV1::Conflict)
    );
}

#[test]
fn reconcile_absent_with_unspent_key_image_records_the_statement() {
    let (_dir, actuator) = prepared();
    let mut broadcast = MockBroadcast {
        accept: Some(BroadcastAcceptance::Accepted),
        submitted: Vec::new(),
    };
    actuator
        .broadcast_current(&lease(1), locator(), [0x0B; 32], &mut broadcast, NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    let mut port = MockObservation::default();
    let outcome = actuator
        .reconcile_takeover(&lease(2), locator(), [0x0C; 32], &mut port, MIN_CONFIRMATIONS, NOW)
        .unwrap_or_else(|_| panic!("reconcile"));
    assert_eq!(outcome.kind, XmrReconciliationKindV1::KeyImageUnspentAbsent);
    assert_eq!(outcome.view.stage, XmrTxStageV1::Reconciled);
    assert_eq!(
        outcome.view.reconciliation_kind,
        Some(XmrReconciliationKindV1::KeyImageUnspentAbsent)
    );
}

#[test]
fn reconcile_spent_key_image_with_absent_txid_stays_unknown_and_writes_nothing() {
    let (_dir, actuator) = prepared();
    let mut broadcast = MockBroadcast {
        accept: Some(BroadcastAcceptance::Accepted),
        submitted: Vec::new(),
    };
    actuator
        .broadcast_current(&lease(1), locator(), [0x0D; 32], &mut broadcast, NOW)
        .unwrap_or_else(|_| panic!("broadcast"));
    let mut port = MockObservation {
        key_image_spent: true,
        ..Default::default()
    };
    let outcome = actuator
        .reconcile_takeover(&lease(2), locator(), [0x0E; 32], &mut port, MIN_CONFIRMATIONS, NOW)
        .unwrap_or_else(|_| panic!("reconcile"));
    assert_eq!(outcome.kind, XmrReconciliationKindV1::Unknown);
    assert_eq!(outcome.view.stage, XmrTxStageV1::SendAttempted);
}

#[test]
fn reconcile_finds_inclusion_and_promotes_to_final_with_facts() {
    let (_dir, actuator) = prepared();
    let mut port = MockObservation {
        inclusion: Some(XmrTxInclusionV1 {
            height: 950,
            block_hash: [0xCC; 32],
            confirmations: MIN_CONFIRMATIONS + 5,
        }),
        ..Default::default()
    };
    let outcome = actuator
        .reconcile_takeover(&lease(2), locator(), [0x0F; 32], &mut port, MIN_CONFIRMATIONS, NOW)
        .unwrap_or_else(|_| panic!("reconcile"));
    assert_eq!(outcome.kind, XmrReconciliationKindV1::Final);
    assert_eq!(outcome.view.stage, XmrTxStageV1::Final);
    assert!(outcome.view.finality.is_some());
    assert_eq!(
        outcome.view.reconciliation_kind,
        Some(XmrReconciliationKindV1::Final)
    );
}

#[test]
fn reconcile_absence_never_downgrades_recorded_evidence() {
    let (_dir, actuator) = prepared();
    let mut port = MockObservation {
        inclusion: Some(XmrTxInclusionV1 {
            height: 960,
            block_hash: [0xDD; 32],
            confirmations: 1,
        }),
        ..Default::default()
    };
    actuator
        .observe_current(&lease(1), locator(), [0x10; 32], &mut port, MIN_CONFIRMATIONS, NOW)
        .unwrap_or_else(|_| panic!("observe"));
    port.inclusion = None;
    assert_eq!(
        actuator
            .reconcile_takeover(&lease(2), locator(), [0x11; 32], &mut port, MIN_CONFIRMATIONS, NOW)
            .map(|outcome| outcome.kind),
        Err(XmrActuatorErrorV1::Conflict)
    );
}

#[test]
fn reconcile_refuses_when_the_boundary_is_dark() {
    let (_dir, actuator) = prepared();
    let mut port = MockObservation {
        inclusion_error: true,
        ..Default::default()
    };
    assert_eq!(
        actuator
            .reconcile_takeover(&lease(2), locator(), [0x12; 32], &mut port, MIN_CONFIRMATIONS, NOW)
            .map(|outcome| outcome.kind),
        Err(XmrActuatorErrorV1::ObservationUnavailable)
    );
}

#[test]
fn retained_bytes_round_trip_and_custody_digest_binds_them() {
    let (_dir, actuator) = prepared();
    let view = actuator.view(locator()).unwrap_or_else(|_| panic!("view"));
    assert_eq!(
        actuator.retained(locator()).unwrap_or_else(|_| panic!("retained")),
        raw()
    );
    assert_eq!(
        view.custody_digest,
        custody_digest_v1(&raw()).unwrap_or_else(|_| panic!("digest"))
    );
    assert!(view.reconciliation_kind.is_none());
}

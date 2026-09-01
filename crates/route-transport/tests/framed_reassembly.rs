//! End-to-end large DSC1 framing through signed Relay envelopes, the shared
//! durable inbox, restart-safe reassembly, and an idempotent Contracts port.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;
use kaystra_core::types::Digest32;
use relay::auth::{RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::server::{AckV1, RelayV1};
use relay::{ParticipantId, SenderRoleV1, TimelockSpec};
use route_transport::{
    ContractsRouteDeliveryEvidenceV2, ContractsRouteDeliveryV1, ContractsTransportPortV1,
    DurableFrameReassemblerConfigV2, DurableFrameReassemblerV2, DurableInboxConfigV1,
    DurablePayloadCommitV1, DurablePayloadDispositionV1, DurableRelayInboxV1,
    FramedContractsTransportV2, RelayQueueV1, RouteFramePlanV2, RouteSenderV1, RouteWireContextV1,
    MAX_FRAMED_DSC1_BYTES_V2,
};

const NETWORK: Digest32 = [0x11; 32];
const SESSION: Digest32 = [0x22; 32];
const ROUTE: Digest32 = [0x33; 32];
const SNAPSHOT: Digest32 = [0x44; 32];
const SENDER: ParticipantId = ParticipantId([0x51; 32]);
const RECIPIENT: ParticipantId = ParticipantId([0x61; 32]);
const SENDER_SECRET: [u8; 32] = [0x71; 32];

fn wire() -> RouteWireContextV1 {
    RouteWireContextV1 {
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        roster_snapshot: SNAPSHOT,
        policy_version: 1,
    }
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    SecpContext::new(&[0x81; 32])
        .sign_bip340(secret, &[0; 32], &[0; 32])
        .unwrap()
        .1
}

fn rosters() -> RosterRegistryV1 {
    RosterRegistryV1::new().with_snapshot(
        SNAPSHOT,
        RosterSnapshotV1::new()
            .with_member(
                SENDER,
                RosterMemberV1 {
                    xonly_key: xonly_of(&SENDER_SECRET),
                    role: SenderRoleV1::Initiator,
                },
            )
            .with_member(
                RECIPIENT,
                RosterMemberV1 {
                    xonly_key: xonly_of(&[0x72; 32]),
                    role: SenderRoleV1::Solver,
                },
            ),
    )
}

fn sender() -> RouteSenderV1 {
    RouteSenderV1::new(
        wire(),
        SENDER,
        RECIPIENT,
        SenderRoleV1::Initiator,
        SENDER_SECRET,
        [0x81; 32],
    )
    .unwrap()
}

fn expiry() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 20_000 }
}

fn now() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

fn inbox_config(id: u8, max_entries: u32) -> DurableInboxConfigV1 {
    DurableInboxConfigV1::new([id; 32], [0x91; 32], wire(), RECIPIENT, max_entries).unwrap()
}

fn frame_config(id: u8) -> DurableFrameReassemblerConfigV2 {
    DurableFrameReassemblerConfigV2::new([id; 32], wire(), RECIPIENT, 16, 4 * 1024 * 1024, 128)
        .unwrap()
}

fn secure_temporary() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temporary
}

fn digest(bytes: &[u8]) -> Digest32 {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(b"DOM-INTEROP/TEST-CONTRACTS-RECEIPT/V1\0");
    hasher.update(bytes);
    let mut digest = [0; 32];
    hasher.finalize_variable(&mut digest).unwrap();
    digest
}

#[derive(Debug, thiserror::Error)]
#[error("test Contracts authority unavailable")]
struct TestContractsError;

#[derive(Default)]
struct RecordingContractsPort {
    messages: BTreeMap<Digest32, Vec<u8>>,
    evidence: BTreeMap<Digest32, ContractsRouteDeliveryEvidenceV2>,
}

impl ContractsTransportPortV1 for RecordingContractsPort {
    type Error = TestContractsError;

    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let receipt = digest(delivery.signed_dsc1());
        let duplicate = self.messages.contains_key(&receipt);
        self.messages
            .entry(receipt)
            .or_insert_with(|| delivery.signed_dsc1().to_vec());
        self.evidence
            .entry(receipt)
            .or_insert_with(|| delivery.delivery_evidence());
        Ok(
            DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, receipt, duplicate)
                .unwrap(),
        )
    }
}

#[test]
fn exact_512k_limit_and_direct_v1_reach_contracts_byte_identical() -> Result<(), Box<dyn Error>> {
    let temporary = secure_temporary();
    let mut relay = RelayV1::new();
    let mut tx = sender();
    let small = b"DSC1-direct-v1".to_vec();
    let prepared = tx.prepare(small.clone(), expiry(), [1; 32])?;
    tx.submit_prepared(&mut relay, &prepared)?;

    let large: Vec<u8> = (0..MAX_FRAMED_DSC1_BYTES_V2)
        .map(|index| (index % 251) as u8)
        .collect();
    let plan = RouteFramePlanV2::new(tx.checkpoint(), &large)?;
    assert_eq!(plan.frame_count(), 33);
    for index in 0..plan.frame_count() {
        let prepared =
            plan.prepare_frame(&tx, index, expiry(), [u8::try_from(index + 2).unwrap(); 32])?;
        tx.submit_prepared(&mut relay, &prepared)?;
    }

    let inbox_root = temporary.path().join("inbox");
    let frames_root = temporary.path().join("frames");
    let rosters = rosters();
    let mut inbox = DurableRelayInboxV1::create(&inbox_root, inbox_config(0x91, 64), &rosters)?;
    let ingest = inbox.ingest_ephemeral_v1(&relay, &rosters, now())?;
    assert_eq!(ingest.accepted, 34);
    assert!(ingest.refused.is_empty());

    let reassembler = DurableFrameReassemblerV2::create(&frames_root, frame_config(0x92))?;
    let contracts = RecordingContractsPort::default();
    let mut framed = FramedContractsTransportV2::new(reassembler, contracts);
    let report = inbox.dispatch_routes(&mut framed)?;
    assert_eq!(report.applied, 34);
    assert_eq!(report.failed_closed, 0);
    let (reassembler, contracts) = framed.into_parts();
    assert_eq!(contracts.messages.len(), 2);
    assert_eq!(contracts.messages.get(&digest(&small)), Some(&small));
    assert_eq!(contracts.messages.get(&digest(&large)), Some(&large));
    assert_eq!(
        contracts.evidence.get(&digest(&small)),
        Some(&ContractsRouteDeliveryEvidenceV2::DirectRelayEnvelopeV1)
    );
    assert_eq!(
        contracts.evidence.get(&digest(&large)),
        Some(&ContractsRouteDeliveryEvidenceV2::ReassembledRouteFramesV2)
    );
    let stats = reassembler.stats()?;
    assert_eq!(stats.delivered_messages, 1);
    assert_eq!(stats.active_reserved_bytes, 0);
    assert_eq!(stats.active_chunks, 0);
    Ok(())
}

#[derive(Default)]
struct DurableContractsState {
    messages: BTreeMap<Digest32, Vec<u8>>,
    calls: usize,
    lose_first_receipt: bool,
}

struct ReceiptLossContractsPort {
    durable: Arc<Mutex<DurableContractsState>>,
}

impl ContractsTransportPortV1 for ReceiptLossContractsPort {
    type Error = TestContractsError;

    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let receipt = digest(delivery.signed_dsc1());
        let mut state = self.durable.lock().unwrap();
        state.calls += 1;
        let duplicate = state.messages.contains_key(&receipt);
        state
            .messages
            .entry(receipt)
            .or_insert_with(|| delivery.signed_dsc1().to_vec());
        if state.lose_first_receipt {
            state.lose_first_receipt = false;
            return Err(TestContractsError);
        }
        Ok(
            DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, receipt, duplicate)
                .unwrap(),
        )
    }
}

#[test]
fn crash_after_contracts_commit_redelivers_one_complete_message() -> Result<(), Box<dyn Error>> {
    let temporary = secure_temporary();
    let mut relay = RelayV1::new();
    let mut tx = sender();
    let large = vec![0xa4; 40_000];
    let plan = RouteFramePlanV2::new(tx.checkpoint(), &large)?;
    for index in 0..plan.frame_count() {
        let prepared =
            plan.prepare_frame(&tx, index, expiry(), [u8::try_from(index + 1).unwrap(); 32])?;
        tx.submit_prepared(&mut relay, &prepared)?;
    }

    let inbox_root = temporary.path().join("inbox-crash");
    let frames_root = temporary.path().join("frames-crash");
    let inbox_cfg = inbox_config(0xa1, 16);
    let frames_cfg = frame_config(0xa2);
    let rosters = rosters();
    let mut inbox = DurableRelayInboxV1::create(&inbox_root, inbox_cfg, &rosters)?;
    assert_eq!(
        inbox.ingest_ephemeral_v1(&relay, &rosters, now())?.accepted,
        plan.frame_count()
    );
    let durable = Arc::new(Mutex::new(DurableContractsState {
        lose_first_receipt: true,
        ..DurableContractsState::default()
    }));
    let reassembler = DurableFrameReassemblerV2::create(&frames_root, frames_cfg)?;
    let mut framed = FramedContractsTransportV2::new(
        reassembler,
        ReceiptLossContractsPort {
            durable: Arc::clone(&durable),
        },
    );
    assert!(inbox.dispatch_routes(&mut framed).is_err());
    drop(framed);
    drop(inbox);

    let mut inbox = DurableRelayInboxV1::open(&inbox_root, inbox_cfg, &rosters)?;
    let reassembler = DurableFrameReassemblerV2::open(&frames_root, frames_cfg)?;
    let mut framed = FramedContractsTransportV2::new(
        reassembler,
        ReceiptLossContractsPort {
            durable: Arc::clone(&durable),
        },
    );
    let report = inbox.dispatch_routes(&mut framed)?;
    assert_eq!(
        report.applied, 1,
        "only the last pending frame is redelivered"
    );
    assert_eq!(report.duplicate_commits, 1);
    assert_eq!(inbox.stats()?.pending_route, 0);
    let state = durable.lock().unwrap();
    assert_eq!(state.calls, 2);
    assert_eq!(state.messages.len(), 1, "one semantic Contracts transition");
    assert_eq!(state.messages.get(&digest(&large)), Some(&large));
    drop(state);
    assert_eq!(framed.stats()?.delivered_messages, 1);
    Ok(())
}

struct ReorderedMailbox {
    raw: Vec<Vec<u8>>,
}

impl RelayQueueV1 for ReorderedMailbox {
    fn queue_submit(&mut self, _raw: &[u8]) -> Result<AckV1, route_transport::BridgeRefusal> {
        Err(route_transport::BridgeRefusal::AckDigestMismatch)
    }

    fn queue_deliver_ephemeral_v1(
        &self,
        recipient: &ParticipantId,
    ) -> Result<Vec<Vec<u8>>, route_transport::BridgeRefusal> {
        assert_eq!(recipient, &RECIPIENT);
        Ok(self.raw.clone())
    }
}

#[test]
fn relay_loss_reorder_and_duplicates_eventually_complete_once() -> Result<(), Box<dyn Error>> {
    let temporary = secure_temporary();
    let mut relay = RelayV1::new();
    let mut tx = sender();
    let large = vec![0xbc; 40_000];
    let plan = RouteFramePlanV2::new(tx.checkpoint(), &large)?;
    assert_eq!(plan.frame_count(), 3);

    // An authenticated peer may send valid frame indices in any order. Outer
    // Relay flow sequences remain contiguous, here mapping 0->2, 1->0, 2->1.
    let mut raw = Vec::new();
    for (sequence, frame_index) in [2_usize, 0, 1].into_iter().enumerate() {
        let prepared = tx.prepare(
            plan.frame_payload(frame_index).unwrap().to_vec(),
            expiry(),
            [u8::try_from(sequence + 1).unwrap(); 32],
        )?;
        raw.push(prepared.canonical_bytes().to_vec());
        tx.submit_prepared(&mut relay, &prepared)?;
    }

    let inbox_root = temporary.path().join("inbox-reordered");
    let frames_root = temporary.path().join("frames-reordered");
    let rosters = rosters();
    let mut inbox = DurableRelayInboxV1::create(&inbox_root, inbox_config(0xb1, 16), &rosters)?;

    // Sequence 1 is lost in round one and higher positions arrive first. Each
    // later pull repeats old bytes plus the missing position.
    let first = ReorderedMailbox {
        raw: vec![raw[2].clone(), raw[0].clone()],
    };
    assert_eq!(
        inbox.ingest_ephemeral_v1(&first, &rosters, now())?.accepted,
        1
    );
    let second = ReorderedMailbox {
        raw: vec![raw[2].clone(), raw[0].clone(), raw[1].clone()],
    };
    assert_eq!(
        inbox
            .ingest_ephemeral_v1(&second, &rosters, now())?
            .accepted,
        1
    );
    let third = ReorderedMailbox {
        raw: vec![raw[2].clone(), raw[1].clone(), raw[0].clone()],
    };
    assert_eq!(
        inbox.ingest_ephemeral_v1(&third, &rosters, now())?.accepted,
        1
    );
    assert_eq!(inbox.stats()?.pending_route, 3);

    let reassembler = DurableFrameReassemblerV2::create(&frames_root, frame_config(0xb2))?;
    let mut framed =
        FramedContractsTransportV2::new(reassembler, RecordingContractsPort::default());
    let report = inbox.dispatch_routes(&mut framed)?;
    assert_eq!(report.applied, 3);
    let (_, contracts) = framed.into_parts();
    assert_eq!(contracts.messages.len(), 1);
    assert_eq!(contracts.messages.get(&digest(&large)), Some(&large));
    Ok(())
}

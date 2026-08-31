//! Adversarial tests for the common durable F6 + route sender/outbox.

#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use btc_crypto::SecpContext;
use kaystra_core::types::Digest32;
use relay::auth::message_type;
use relay::server::{AckV1, RelayV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use route_transport::{
    BridgeRefusal, DurableRelaySenderConfigV1, DurableRelaySenderErrorV1, DurableRelaySenderV1,
    RelayQueueV1, RouteApplicationDispositionV2, RouteApplicationStateV2, RouteFrameV2,
    RouteSenderV1, RouteWireContextV1, MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES,
};
use rusqlite::Connection;

const NETWORK: Digest32 = [0x11; 32];
const SESSION: Digest32 = [0x22; 32];
const ROUTE: Digest32 = [0x33; 32];
const ROSTER: Digest32 = [0x44; 32];
const INITIATOR: ParticipantId = ParticipantId([0x51; 32]);
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR_SECRET: [u8; 32] = [0x71; 32];
const SOLVER_SECRET: [u8; 32] = [0x72; 32];

fn wire() -> RouteWireContextV1 {
    RouteWireContextV1 {
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        roster_snapshot: ROSTER,
        policy_version: 1,
    }
}

fn expiry() -> TimelockSpec {
    TimelockSpec::BlockHeight { value: 10_000 }
}

fn xonly(secret: &[u8; 32]) -> [u8; 32] {
    SecpContext::new(&[0x19; 32])
        .sign_bip340(secret, &[0; 32], &[0; 32])
        .expect("test secret")
        .1
}

fn initiator_config(maximum: u32) -> DurableRelaySenderConfigV1 {
    DurableRelaySenderConfigV1::new(
        [0x81; 32],
        wire(),
        INITIATOR,
        SOLVER,
        SenderRoleV1::Initiator,
        xonly(&INITIATOR_SECRET),
        maximum,
    )
    .expect("valid initiator config")
}

fn solver_config(maximum: u32) -> DurableRelaySenderConfigV1 {
    DurableRelaySenderConfigV1::new(
        [0x82; 32],
        wire(),
        SOLVER,
        INITIATOR,
        SenderRoleV1::Solver,
        xonly(&SOLVER_SECRET),
        maximum,
    )
    .expect("valid solver config")
}

fn secure_tempdir() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let directory = tempfile::Builder::new().prefix("route-sender-").tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

#[derive(Clone, Copy, Default)]
enum QueueMode {
    #[default]
    Normal,
    LoseAckAfterStore,
    ReturnWrongAck,
}

#[derive(Default)]
struct RecordingQueue {
    relay: RelayV1,
    attempts: Vec<Vec<u8>>,
    mode: QueueMode,
}

impl RelayQueueV1 for RecordingQueue {
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
        self.attempts.push(raw.to_vec());
        let ack = self.relay.submit(raw).map_err(BridgeRefusal::Relay)?;
        match self.mode {
            QueueMode::Normal => Ok(ack),
            QueueMode::LoseAckAfterStore => Err(BridgeRefusal::AckDigestMismatch),
            QueueMode::ReturnWrongAck => Ok(AckV1 {
                key: ack.key,
                digest: [0xff; 32],
            }),
        }
    }

    fn queue_deliver(&self, recipient: &ParticipantId) -> Result<Vec<Vec<u8>>, BridgeRefusal> {
        Ok(self.relay.deliver(recipient))
    }
}

fn assert_attempt_chain(raws: &[Vec<u8>], expected_types: &[u16]) {
    assert_eq!(raws.len(), expected_types.len());
    let mut previous = [0; 32];
    for (index, (raw, expected_type)) in raws.iter().zip(expected_types).enumerate() {
        let envelope = RelayEnvelopeV1::decode(raw).expect("canonical retained envelope");
        assert_eq!(envelope.message_type, *expected_type);
        assert_eq!(envelope.sequence, index as u64);
        assert_eq!(envelope.previous_transcript_hash, previous);
        previous = envelope.envelope_digest().expect("envelope digest");
    }
}

#[test]
fn production_resume_recovers_only_pristine_creation_prefixes() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    for name in [
        "absent",
        "empty-root",
        "lock-only",
        "database-file-synced",
        "initialized",
    ] {
        let root = temporary.path().join(name);
        match name {
            "absent" => {}
            "empty-root" => {
                fs::create_dir(&root)?;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            }
            "lock-only" | "database-file-synced" => {
                fs::create_dir(&root)?;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                let lock = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(root.join(".route-sender.lock"))?;
                lock.sync_all()?;
                if name == "database-file-synced" {
                    let database = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(root.join("route-sender-v1.sqlite3"))?;
                    database.sync_all()?;
                }
            }
            "initialized" => {
                drop(DurableRelaySenderV1::create(
                    &root,
                    initiator_config(8),
                    INITIATOR_SECRET,
                    [0xe1; 32],
                )?);
            }
            _ => return Err("unreachable creation prefix".into()),
        }
        let resumed = DurableRelaySenderV1::resume_create_production(
            &root,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xe2; 32],
        )?;
        assert_eq!(resumed.checkpoint()?.next_sequence(), 0);
        assert_eq!(resumed.stats()?.completed, 0);
        assert_eq!(
            fs::metadata(root.join("route-sender-v1.sqlite3"))?
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        drop(resumed);
        drop(DurableRelaySenderV1::open_existing(
            &root,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xe3; 32],
        )?);
    }
    Ok(())
}

#[test]
fn production_resume_refuses_traffic_transplant_and_unknown_root_entry(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let economic = temporary.path().join("economic");
    let mut sender =
        DurableRelaySenderV1::create(&economic, initiator_config(8), INITIATOR_SECRET, [0xe4; 32])?;
    sender.prepare_message(message_type::RFQ, b"economic", expiry(), [1; 32])?;
    drop(sender);
    assert!(matches!(
        DurableRelaySenderV1::resume_create_production(
            &economic,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xe5; 32],
        ),
        Err(DurableRelaySenderErrorV1::UnsupportedFormat)
    ));

    let transplanted = temporary.path().join("transplanted");
    drop(DurableRelaySenderV1::create(
        &transplanted,
        initiator_config(8),
        INITIATOR_SECRET,
        [0xe6; 32],
    )?);
    fs::hard_link(
        transplanted.join("route-sender-v1.sqlite3"),
        temporary.path().join("sender-hardlink.sqlite3"),
    )?;
    assert!(matches!(
        DurableRelaySenderV1::resume_create_production(
            &transplanted,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xe7; 32],
        ),
        Err(DurableRelaySenderErrorV1::InvalidConfiguration)
    ));

    let unknown = temporary.path().join("unknown-entry");
    drop(DurableRelaySenderV1::create(
        &unknown,
        initiator_config(8),
        INITIATOR_SECRET,
        [0xe8; 32],
    )?);
    fs::write(unknown.join("caller-shaped"), b"foreign")?;
    assert!(matches!(
        DurableRelaySenderV1::resume_create_production(
            &unknown,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xe9; 32],
        ),
        Err(DurableRelaySenderErrorV1::InvalidConfiguration)
    ));
    Ok(())
}

#[test]
fn canonical_policy_and_one_transcript_cover_all_f6_kinds_and_route() -> Result<(), Box<dyn Error>>
{
    let temporary = secure_tempdir()?;
    let initiator_root = temporary.path().join("initiator");
    let mut initiator = DurableRelaySenderV1::create(
        &initiator_root,
        initiator_config(16),
        INITIATOR_SECRET,
        [0x91; 32],
    )?;
    let mut queue = RecordingQueue::default();

    assert!(matches!(
        initiator.prepare_message(message_type::QUOTE, b"forbidden", expiry(), [1; 32]),
        Err(DurableRelaySenderErrorV1::MessageTypeNotPermitted)
    ));
    assert!(matches!(
        initiator.prepare_message(0x9000, b"unknown", expiry(), [1; 32]),
        Err(DurableRelaySenderErrorV1::MessageTypeNotPermitted)
    ));
    for (kind, payload, aux) in [
        (message_type::RFQ, b"rfq".as_slice(), [1; 32]),
        (message_type::ACCEPTANCE, b"acceptance".as_slice(), [2; 32]),
        (message_type::SELECTION, b"selection".as_slice(), [3; 32]),
        (
            message_type::ROUTE_TRANSPORT,
            b"signed-dsc1".as_slice(),
            [4; 32],
        ),
    ] {
        let prepared = initiator.prepare_message(kind, payload, expiry(), aux)?;
        assert_eq!(initiator.pending_envelope()?.as_ref(), Some(&prepared));
        initiator.submit_pending(&mut queue)?;
    }
    assert_attempt_chain(
        &queue.attempts,
        &[
            message_type::RFQ,
            message_type::ACCEPTANCE,
            message_type::SELECTION,
            message_type::ROUTE_TRANSPORT,
        ],
    );
    assert_eq!(initiator.checkpoint()?.next_sequence(), 4);

    let solver_root = temporary.path().join("solver");
    let mut solver =
        DurableRelaySenderV1::create(&solver_root, solver_config(4), SOLVER_SECRET, [0x92; 32])?;
    let mut solver_queue = RecordingQueue::default();
    assert!(matches!(
        solver.prepare_message(message_type::RFQ, b"forbidden", expiry(), [5; 32]),
        Err(DurableRelaySenderErrorV1::MessageTypeNotPermitted)
    ));
    solver.prepare_message(message_type::QUOTE, b"quote", expiry(), [6; 32])?;
    solver.submit_pending(&mut solver_queue)?;
    solver.prepare_message(
        message_type::ROUTE_TRANSPORT,
        b"solver-dsc1",
        expiry(),
        [7; 32],
    )?;
    solver.submit_pending(&mut solver_queue)?;
    assert_attempt_chain(
        &solver_queue.attempts,
        &[message_type::QUOTE, message_type::ROUTE_TRANSPORT],
    );
    Ok(())
}

#[test]
fn ack_loss_restart_and_bad_ack_retry_exact_pending_bytes() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("sender");
    let mut sender =
        DurableRelaySenderV1::create(&root, initiator_config(8), INITIATOR_SECRET, [0xa1; 32])?;
    let prepared = sender.prepare_message(message_type::RFQ, b"rfq", expiry(), [1; 32])?;
    let exact = prepared.canonical_bytes().to_vec();
    let mut queue = RecordingQueue {
        mode: QueueMode::LoseAckAfterStore,
        ..RecordingQueue::default()
    };
    assert!(matches!(
        sender.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::Queue(_))
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), 0);
    assert_eq!(sender.pending_envelope()?.unwrap().canonical_bytes(), exact);
    drop(sender);

    let mut sender = DurableRelaySenderV1::open_existing(
        &root,
        initiator_config(8),
        INITIATOR_SECRET,
        [0xa2; 32],
    )?;
    assert_eq!(sender.pending_envelope()?.unwrap().canonical_bytes(), exact);
    queue.mode = QueueMode::Normal;
    sender.submit_pending(&mut queue)?;
    assert_eq!(queue.attempts[0], queue.attempts[1]);
    assert_eq!(sender.checkpoint()?.next_sequence(), 1);
    assert!(sender.pending_envelope()?.is_none());

    sender.prepare_message(message_type::ACCEPTANCE, b"accepted", expiry(), [2; 32])?;
    queue.mode = QueueMode::ReturnWrongAck;
    assert!(matches!(
        sender.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::AckMismatch)
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), 1);
    let second_exact = sender
        .pending_envelope()?
        .unwrap()
        .canonical_bytes()
        .to_vec();
    queue.mode = QueueMode::Normal;
    sender.submit_pending(&mut queue)?;
    assert_eq!(queue.attempts[2], queue.attempts[3]);
    assert_eq!(queue.attempts[3], second_exact);
    assert!(matches!(
        sender.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::NoPendingEnvelope)
    ));
    Ok(())
}

#[test]
fn relay_equivocation_cannot_replace_the_durable_pending_envelope() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("sender");
    let mut durable =
        DurableRelaySenderV1::create(&root, initiator_config(4), INITIATOR_SECRET, [0xb1; 32])?;
    let pending =
        durable.prepare_message(message_type::ROUTE_TRANSPORT, b"durable", expiry(), [1; 32])?;
    let exact = pending.canonical_bytes().to_vec();

    let alternate_sender = RouteSenderV1::new(
        wire(),
        INITIATOR,
        SOLVER,
        SenderRoleV1::Initiator,
        INITIATOR_SECRET,
        [0xb2; 32],
    )?;
    let alternate = alternate_sender.prepare(b"alternate".to_vec(), expiry(), [2; 32])?;
    let mut queue = RecordingQueue::default();
    queue.relay.submit(alternate.canonical_bytes())?;
    assert!(matches!(
        durable.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::Queue(BridgeRefusal::Relay(_)))
    ));
    assert_eq!(durable.checkpoint()?.next_sequence(), 0);
    assert_eq!(
        durable.pending_envelope()?.unwrap().canonical_bytes(),
        exact
    );
    assert!(matches!(
        durable.prepare_message(message_type::RFQ, b"replacement", expiry(), [3; 32]),
        Err(DurableRelaySenderErrorV1::PendingEnvelopeExists)
    ));
    Ok(())
}

#[test]
fn framed_route_is_contiguous_restartable_and_shares_the_f6_checkpoint(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("sender");
    let config = initiator_config(16);
    let mut sender = DurableRelaySenderV1::create(&root, config, INITIATOR_SECRET, [0xc1; 32])?;
    let mut queue = RecordingQueue::default();
    sender.prepare_message(message_type::RFQ, b"rfq", expiry(), [1; 32])?;
    sender.submit_pending(&mut queue)?;

    let large = vec![0x5a; MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES + 1];
    let first = sender.begin_framed_route(&large, expiry(), [2; 32])?;
    assert_eq!((first.sequence(), first.frame_index()), (1, Some(0)));
    let frame_count = first.frame_count().expect("framed envelope");
    assert_eq!(frame_count, 2);
    let exact_first_frame = first.canonical_bytes().to_vec();
    queue.mode = QueueMode::LoseAckAfterStore;
    assert!(matches!(
        sender.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::Queue(_))
    ));
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0xc2; 32])?;
    let status = sender.frame_transfer_status()?.expect("active frame job");
    assert_eq!((status.next_frame(), status.frame_count()), (0, 2));
    assert_eq!(
        sender.pending_envelope()?.unwrap().canonical_bytes(),
        exact_first_frame
    );
    queue.mode = QueueMode::Normal;
    sender.submit_pending(&mut queue)?;
    assert_eq!(queue.attempts[1], queue.attempts[2]);
    assert!(matches!(
        sender.prepare_message(message_type::SELECTION, b"interleave", expiry(), [3; 32]),
        Err(DurableRelaySenderErrorV1::FramedTransferActive)
    ));
    let second = sender.prepare_next_frame([4; 32])?;
    assert_eq!((second.sequence(), second.frame_index()), (2, Some(1)));
    sender.submit_pending(&mut queue)?;
    assert!(sender.frame_transfer_status()?.is_none());

    sender.prepare_message(message_type::SELECTION, b"selection", expiry(), [5; 32])?;
    sender.submit_pending(&mut queue)?;
    let accepted_attempts = vec![
        queue.attempts[0].clone(),
        queue.attempts[1].clone(),
        queue.attempts[3].clone(),
        queue.attempts[4].clone(),
    ];
    assert_attempt_chain(
        &accepted_attempts,
        &[
            message_type::RFQ,
            message_type::ROUTE_TRANSPORT,
            message_type::ROUTE_TRANSPORT,
            message_type::SELECTION,
        ],
    );
    for (expected_index, raw) in [queue.attempts[1].as_slice(), queue.attempts[3].as_slice()]
        .iter()
        .enumerate()
    {
        let envelope = RelayEnvelopeV1::decode(raw)?;
        let frame = RouteFrameV2::decode_for_flow(&envelope.payload, wire(), INITIATOR, SOLVER)?;
        assert_eq!(frame.index(), expected_index as u16);
        assert_eq!(frame.count(), 2);
        assert_eq!(frame.total_len(), large.len() as u32);
    }
    assert_eq!(sender.stats()?.completed, 4);
    Ok(())
}

#[test]
fn direct_route_application_is_idempotent_across_every_handoff_cut() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("application-direct");
    let config = initiator_config(8);
    let application_id = [0xa1; 32];
    let signed_dsc1 = b"store-committed-signed-dsc1";
    let mut sender = DurableRelaySenderV1::create(&root, config, INITIATOR_SECRET, [0x31; 32])?;

    assert_eq!(sender.route_application_status(application_id)?, None);
    let first =
        sender.prepare_route_application(application_id, signed_dsc1, expiry(), [0x32; 32])?;
    let first_status = match first {
        RouteApplicationDispositionV2::Pending(status) => status,
        RouteApplicationDispositionV2::AlreadyAcked(_) => panic!("new application was ACKed"),
    };
    assert_eq!(first_status.application_id(), &application_id);
    assert_eq!(first_status.state(), RouteApplicationStateV2::Pending);
    assert_eq!(
        (
            first_status.first_sequence(),
            first_status.final_sequence(),
            first_status.frame_count(),
            first_status.acknowledged_frames(),
            first_status.is_framed(),
        ),
        (0, 0, 1, 0, false)
    );
    let exact = sender
        .pending_envelope()?
        .expect("application envelope")
        .canonical_bytes()
        .to_vec();
    assert_eq!(
        sender.pending_envelope()?.unwrap().application_id(),
        Some(&application_id)
    );

    let repeated = sender.prepare_route_application(
        application_id,
        signed_dsc1,
        TimelockSpec::BlockHeight { value: 99_999 },
        [0x33; 32],
    )?;
    assert!(matches!(
        repeated,
        RouteApplicationDispositionV2::Pending(status) if status == first_status
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), 0);
    assert_eq!(sender.pending_envelope()?.unwrap().canonical_bytes(), exact);
    assert!(matches!(
        sender.prepare_route_application(
            application_id,
            b"different-signed-dsc1",
            expiry(),
            [0x34; 32]
        ),
        Err(DurableRelaySenderErrorV1::ApplicationConflict)
    ));
    assert!(matches!(
        sender.prepare_route_application([0xa2; 32], signed_dsc1, expiry(), [0x35; 32]),
        Err(DurableRelaySenderErrorV1::ApplicationConflict)
    ));
    let mut queue = RecordingQueue {
        mode: QueueMode::LoseAckAfterStore,
        ..RecordingQueue::default()
    };
    assert!(matches!(
        sender.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::Queue(_))
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), 0);
    assert_eq!(sender.pending_envelope()?.unwrap().canonical_bytes(), exact);
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0x36; 32])?;
    assert_eq!(sender.pending_envelope()?.unwrap().canonical_bytes(), exact);
    queue.mode = QueueMode::Normal;
    let committed = sender.submit_pending(&mut queue)?;
    assert_eq!(queue.attempts[0], queue.attempts[1]);
    assert_eq!(committed.application_id(), Some(&application_id));
    assert_eq!(committed.checkpoint().next_sequence(), 1);
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0x37; 32])?;
    let status = sender
        .route_application_status(application_id)?
        .expect("ACKed application history");
    assert_eq!(status.state(), RouteApplicationStateV2::Acked);
    assert_eq!(status.acknowledged_frames(), 1);
    assert!(sender.pending_envelope()?.is_none());
    let checkpoint_before = sender.checkpoint()?;
    assert!(matches!(
        sender.prepare_route_application(application_id, signed_dsc1, expiry(), [0x38; 32])?,
        RouteApplicationDispositionV2::AlreadyAcked(retained) if retained == status
    ));
    assert_eq!(sender.checkpoint()?, checkpoint_before);
    assert!(sender.pending_envelope()?.is_none());

    sender.prepare_message(
        message_type::ACCEPTANCE,
        b"f6-after-application",
        expiry(),
        [0x39; 32],
    )?;
    sender.submit_pending(&mut queue)?;
    assert_eq!(sender.checkpoint()?.next_sequence(), 2);
    let accepted_attempts = vec![queue.attempts[0].clone(), queue.attempts[2].clone()];
    assert_attempt_chain(
        &accepted_attempts,
        &[message_type::ROUTE_TRANSPORT, message_type::ACCEPTANCE],
    );
    Ok(())
}

#[test]
fn framed_route_application_reserves_one_range_and_acks_atomically() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("application-framed");
    let config = initiator_config(16);
    let application_id = [0xb1; 32];
    let signed_dsc1 = vec![0x5c; MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES + 1];
    let mut sender = DurableRelaySenderV1::create(&root, config, INITIATOR_SECRET, [0x41; 32])?;
    let mut queue = RecordingQueue::default();
    sender.prepare_message(message_type::RFQ, b"rfq", expiry(), [0x42; 32])?;
    sender.submit_pending(&mut queue)?;

    let disposition =
        sender.prepare_route_application(application_id, &signed_dsc1, expiry(), [0x43; 32])?;
    let initial = disposition.status();
    assert!(matches!(
        disposition,
        RouteApplicationDispositionV2::Pending(_)
    ));
    assert_eq!(initial.state(), RouteApplicationStateV2::Pending);
    assert_eq!(
        (
            initial.first_sequence(),
            initial.final_sequence(),
            initial.frame_count(),
            initial.acknowledged_frames(),
            initial.is_framed(),
        ),
        (1, 2, 2, 0, true)
    );
    let first_exact = sender
        .pending_envelope()?
        .expect("first frame")
        .canonical_bytes()
        .to_vec();
    assert!(matches!(
        sender.prepare_next_frame([0x44; 32]),
        Err(DurableRelaySenderErrorV1::ApplicationConflict)
    ));
    assert!(matches!(
        sender.prepare_message(message_type::SELECTION, b"interleave", expiry(), [0x45; 32]),
        Err(DurableRelaySenderErrorV1::PendingEnvelopeExists)
    ));
    let repeated =
        sender.prepare_route_application(application_id, &signed_dsc1, expiry(), [0x46; 32])?;
    assert_eq!(repeated.status(), initial);
    assert_eq!(
        sender.pending_envelope()?.unwrap().canonical_bytes(),
        first_exact
    );

    queue.mode = QueueMode::LoseAckAfterStore;
    assert!(matches!(
        sender.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::Queue(_))
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), 1);
    assert_eq!(
        sender.pending_envelope()?.unwrap().canonical_bytes(),
        first_exact
    );
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0x47; 32])?;
    assert_eq!(
        sender.pending_envelope()?.unwrap().canonical_bytes(),
        first_exact
    );
    queue.mode = QueueMode::Normal;
    sender.submit_pending(&mut queue)?;
    assert_eq!(queue.attempts[1], queue.attempts[2]);
    assert!(sender.pending_envelope()?.is_none());
    let after_first = sender
        .route_application_status(application_id)?
        .expect("pending framed application");
    assert_eq!(after_first.state(), RouteApplicationStateV2::Pending);
    assert_eq!(after_first.acknowledged_frames(), 1);
    assert_eq!(sender.checkpoint()?.next_sequence(), 2);
    assert!(matches!(
        sender.prepare_message(
            message_type::SELECTION,
            b"interleave-between-frames",
            expiry(),
            [0x47; 32]
        ),
        Err(DurableRelaySenderErrorV1::FramedTransferActive)
    ));
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0x48; 32])?;
    assert!(sender.pending_envelope()?.is_none());
    assert_eq!(
        sender.route_application_status(application_id)?.unwrap(),
        after_first
    );
    let next = sender.prepare_route_application(
        application_id,
        &signed_dsc1,
        TimelockSpec::TimestampSeconds { value: 1 },
        [0x49; 32],
    )?;
    assert!(
        matches!(next, RouteApplicationDispositionV2::Pending(status) if status == after_first)
    );
    let second_exact = sender
        .pending_envelope()?
        .expect("second frame")
        .canonical_bytes()
        .to_vec();
    assert_ne!(first_exact, second_exact);
    let checkpoint_before_retry = sender.checkpoint()?;
    assert!(matches!(
        sender.prepare_route_application(application_id, &signed_dsc1, expiry(), [0x4a; 32])?,
        RouteApplicationDispositionV2::Pending(status) if status == after_first
    ));
    assert_eq!(sender.checkpoint()?, checkpoint_before_retry);
    assert_eq!(
        sender.pending_envelope()?.unwrap().canonical_bytes(),
        second_exact
    );
    queue.mode = QueueMode::LoseAckAfterStore;
    assert!(matches!(
        sender.submit_pending(&mut queue),
        Err(DurableRelaySenderErrorV1::Queue(_))
    ));
    assert_eq!(sender.checkpoint()?, checkpoint_before_retry);
    assert_eq!(
        sender.pending_envelope()?.unwrap().canonical_bytes(),
        second_exact
    );
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0x4b; 32])?;
    assert_eq!(
        sender.pending_envelope()?.unwrap().canonical_bytes(),
        second_exact
    );
    queue.mode = QueueMode::Normal;
    sender.submit_pending(&mut queue)?;
    assert_eq!(queue.attempts[3], queue.attempts[4]);

    let database = root.join("route-sender-v1.sqlite3");
    let connection = Connection::open(&database)?;
    let (status, acknowledged, pending_count, frame_count, completed, history_count): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = connection.query_row(
        "SELECT
                (SELECT delivery_status FROM route_application WHERE application_id = ?1),
                (SELECT acknowledged_frames FROM route_application WHERE application_id = ?1),
                (SELECT COUNT(*) FROM sender_pending),
                (SELECT COUNT(*) FROM frame_transfer),
                (SELECT completed_count FROM sender_meta WHERE singleton = 1),
                (SELECT COUNT(*) FROM sender_history)",
        [application_id.as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    assert_eq!(
        (
            status,
            acknowledged,
            pending_count,
            frame_count,
            completed,
            history_count,
        ),
        (2, 2, 0, 0, 3, 3)
    );
    drop(connection);
    drop(sender);

    let mut sender =
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0x4c; 32])?;
    let acked = sender
        .route_application_status(application_id)?
        .expect("terminal application");
    assert_eq!(acked.state(), RouteApplicationStateV2::Acked);
    assert_eq!(acked.acknowledged_frames(), 2);
    let sequence_before = sender.checkpoint()?.next_sequence();
    assert!(matches!(
        sender.prepare_route_application(application_id, &signed_dsc1, expiry(), [0x4d; 32])?,
        RouteApplicationDispositionV2::AlreadyAcked(status) if status == acked
    ));
    assert_eq!(sender.checkpoint()?.next_sequence(), sequence_before);

    let accepted_attempts = vec![
        queue.attempts[0].clone(),
        queue.attempts[1].clone(),
        queue.attempts[3].clone(),
    ];
    assert_attempt_chain(
        &accepted_attempts,
        &[
            message_type::RFQ,
            message_type::ROUTE_TRANSPORT,
            message_type::ROUTE_TRANSPORT,
        ],
    );
    Ok(())
}

#[test]
fn schema_v2_rejects_v1_without_migration_or_side_effects() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let v2_root = temporary.path().join("created-v2");
    let v2 =
        DurableRelaySenderV1::create(&v2_root, initiator_config(8), INITIATOR_SECRET, [0x50; 32])?;
    drop(v2);
    let v2_database = v2_root.join("route-sender-v1.sqlite3");
    let v2 = Connection::open_with_flags(&v2_database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: i64 = v2.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let applications: i64 = v2.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE type = 'table' AND name = 'route_application'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!((version, applications), (2, 1));
    drop(v2);

    let root = temporary.path().join("legacy-v1");
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(".route-sender.lock"))?;
    let database = root.join("route-sender-v1.sqlite3");
    let legacy = Connection::open(&database)?;
    legacy.pragma_update(None, "application_id", 0x444f_4d53_i64)?;
    legacy.pragma_update(None, "user_version", 1_i64)?;
    legacy.execute("CREATE TABLE legacy_marker(value BLOB) STRICT", [])?;
    drop(legacy);
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
    let before = fs::read(&database)?;

    assert!(matches!(
        DurableRelaySenderV1::open_existing(
            &root,
            initiator_config(8),
            INITIATOR_SECRET,
            [0x51; 32]
        ),
        Err(DurableRelaySenderErrorV1::LegacyFormatRequiresOfflineMigration)
    ));
    assert_eq!(fs::read(&database)?, before);
    assert!(!root.join("route-sender-v1.sqlite3-wal").exists());
    assert!(!root.join("route-sender-v1.sqlite3-shm").exists());
    let legacy =
        Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: i64 = legacy.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 1);
    Ok(())
}

#[test]
fn route_application_tamper_and_invalid_ids_fail_closed() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("application-tamper");
    let config = initiator_config(8);
    let application_id = [0xc1; 32];
    let mut sender = DurableRelaySenderV1::create(&root, config, INITIATOR_SECRET, [0x61; 32])?;
    assert!(matches!(
        sender.prepare_route_application([0; 32], b"signed", expiry(), [0x62; 32]),
        Err(DurableRelaySenderErrorV1::InvalidApplicationId)
    ));
    assert!(matches!(
        sender.route_application_status([0; 32]),
        Err(DurableRelaySenderErrorV1::InvalidApplicationId)
    ));
    sender.prepare_route_application(
        application_id,
        b"store-signed-application",
        expiry(),
        [0x63; 32],
    )?;
    drop(sender);

    let database = root.join("route-sender-v1.sqlite3");
    let connection = Connection::open(&database)?;
    let mut bytes: Vec<u8> = connection.query_row(
        "SELECT signed_dsc1 FROM route_application WHERE application_id = ?1",
        [application_id.as_slice()],
        |row| row.get(0),
    )?;
    bytes[0] ^= 1;
    connection.execute(
        "UPDATE route_application SET signed_dsc1 = ?1 WHERE application_id = ?2",
        rusqlite::params![bytes, application_id.as_slice()],
    )?;
    drop(connection);
    assert!(matches!(
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0x64; 32]),
        Err(DurableRelaySenderErrorV1::CorruptState)
    ));
    Ok(())
}

#[test]
fn storage_is_owner_only_exact_schema_and_contains_no_signing_secret() -> Result<(), Box<dyn Error>>
{
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("sender");
    let config = initiator_config(8);
    let mut sender = DurableRelaySenderV1::create(&root, config, INITIATOR_SECRET, [0xd1; 32])?;
    sender.prepare_message(message_type::RFQ, b"rfq", expiry(), [1; 32])?;
    assert!(matches!(
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0xd2; 32]),
        Err(DurableRelaySenderErrorV1::StorageUnavailable)
    ));
    let debug = format!("{sender:?}");
    assert!(!debug.contains(&root.display().to_string()));
    assert!(!debug.contains("71717171"));
    for entry in fs::read_dir(&root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        let bytes = fs::read(&path)?;
        assert!(!bytes.windows(32).any(|window| window == INITIATOR_SECRET));
    }
    drop(sender);
    assert!(matches!(
        DurableRelaySenderV1::open_existing(&root, config, SOLVER_SECRET, [0xd3; 32]),
        Err(DurableRelaySenderErrorV1::WrongSigningAuthority)
    ));

    let schema_root = temporary.path().join("schema");
    let schema = DurableRelaySenderV1::create(
        &schema_root,
        initiator_config(8),
        INITIATOR_SECRET,
        [0xd4; 32],
    )?;
    drop(schema);
    let database = schema_root.join("route-sender-v1.sqlite3");
    Connection::open(&database)?.execute("CREATE TABLE injected(value BLOB) STRICT", [])?;
    assert!(matches!(
        DurableRelaySenderV1::open_existing(
            &schema_root,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xd5; 32]
        ),
        Err(DurableRelaySenderErrorV1::UnsupportedFormat)
    ));

    let missing_root = temporary.path().join("missing-db");
    fs::create_dir(&missing_root)?;
    fs::set_permissions(&missing_root, fs::Permissions::from_mode(0o700))?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(missing_root.join(".route-sender.lock"))?;
    assert!(matches!(
        DurableRelaySenderV1::open_existing(
            &missing_root,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xd6; 32]
        ),
        Err(DurableRelaySenderErrorV1::DatabaseMissing)
    ));
    assert!(!missing_root.join("route-sender-v1.sqlite3").exists());
    Ok(())
}

#[test]
fn retained_pending_and_checkpoint_tamper_fail_closed_on_reopen() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("pending-tamper");
    let config = initiator_config(8);
    let mut sender = DurableRelaySenderV1::create(&root, config, INITIATOR_SECRET, [0xe1; 32])?;
    sender.prepare_message(message_type::RFQ, b"rfq", expiry(), [1; 32])?;
    drop(sender);
    let database = root.join("route-sender-v1.sqlite3");
    let connection = Connection::open(&database)?;
    let mut raw: Vec<u8> = connection.query_row(
        "SELECT canonical_bytes FROM sender_pending WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    raw[0] ^= 1;
    connection.execute(
        "UPDATE sender_pending SET canonical_bytes = ?1 WHERE singleton = 1",
        [raw],
    )?;
    drop(connection);
    assert!(matches!(
        DurableRelaySenderV1::open_existing(&root, config, INITIATOR_SECRET, [0xe2; 32]),
        Err(DurableRelaySenderErrorV1::CorruptState)
    ));

    let checkpoint_root = temporary.path().join("checkpoint-tamper");
    let checkpoint = DurableRelaySenderV1::create(
        &checkpoint_root,
        initiator_config(8),
        INITIATOR_SECRET,
        [0xe3; 32],
    )?;
    drop(checkpoint);
    let connection = Connection::open(checkpoint_root.join("route-sender-v1.sqlite3"))?;
    let mut bytes: Vec<u8> = connection.query_row(
        "SELECT checkpoint_bytes FROM sender_meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    bytes[218] ^= 1;
    connection.execute(
        "UPDATE sender_meta SET checkpoint_bytes = ?1 WHERE singleton = 1",
        [bytes],
    )?;
    drop(connection);
    assert!(matches!(
        DurableRelaySenderV1::open_existing(
            &checkpoint_root,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xe4; 32]
        ),
        Err(DurableRelaySenderErrorV1::CorruptState)
    ));

    let history_root = temporary.path().join("history-tamper");
    let mut history = DurableRelaySenderV1::create(
        &history_root,
        initiator_config(8),
        INITIATOR_SECRET,
        [0xe5; 32],
    )?;
    let mut queue = RecordingQueue::default();
    history.prepare_message(message_type::RFQ, b"rfq", expiry(), [1; 32])?;
    history.submit_pending(&mut queue)?;
    history.prepare_message(message_type::ACCEPTANCE, b"acceptance", expiry(), [2; 32])?;
    history.submit_pending(&mut queue)?;
    drop(history);
    let connection = Connection::open(history_root.join("route-sender-v1.sqlite3"))?;
    connection.execute(
        "UPDATE sender_history SET sequence_be = ?1 WHERE ordinal = 2",
        [9_u64.to_be_bytes().as_slice()],
    )?;
    drop(connection);
    assert!(matches!(
        DurableRelaySenderV1::open_existing(
            &history_root,
            initiator_config(8),
            INITIATOR_SECRET,
            [0xe6; 32]
        ),
        Err(DurableRelaySenderErrorV1::CorruptState)
    ));
    Ok(())
}

#[test]
fn invalid_configuration_and_bounds_are_refused_before_writes() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        DurableRelaySenderConfigV1::new(
            [0; 32],
            wire(),
            INITIATOR,
            SOLVER,
            SenderRoleV1::Initiator,
            xonly(&INITIATOR_SECRET),
            8,
        ),
        Err(DurableRelaySenderErrorV1::InvalidConfiguration)
    ));
    assert!(matches!(
        DurableRelaySenderConfigV1::new(
            [1; 32],
            wire(),
            INITIATOR,
            SOLVER,
            SenderRoleV1::Observer,
            xonly(&INITIATOR_SECRET),
            8,
        ),
        Err(DurableRelaySenderErrorV1::InvalidConfiguration)
    ));

    let temporary = secure_tempdir()?;
    let root = temporary.path().join("sender");
    let mut sender =
        DurableRelaySenderV1::create(&root, initiator_config(1), INITIATOR_SECRET, [0xf1; 32])?;
    assert!(matches!(
        sender.prepare_message(message_type::RFQ, b"", expiry(), [1; 32]),
        Err(DurableRelaySenderErrorV1::EmptyPayload)
    ));
    assert!(matches!(
        sender.begin_framed_route(b"too-small", expiry(), [2; 32]),
        Err(DurableRelaySenderErrorV1::PayloadOutOfBounds)
    ));
    sender.prepare_message(message_type::RFQ, b"rfq", expiry(), [3; 32])?;
    sender.submit_pending(&mut RecordingQueue::default())?;
    assert!(matches!(
        sender.prepare_message(message_type::ACCEPTANCE, b"full", expiry(), [4; 32]),
        Err(DurableRelaySenderErrorV1::CapacityExceeded)
    ));
    assert!(matches!(
        DurableRelaySenderV1::create(
            Path::new("relative"),
            initiator_config(8),
            INITIATOR_SECRET,
            [0xf2; 32]
        ),
        Err(DurableRelaySenderErrorV1::InvalidConfiguration)
    ));
    Ok(())
}

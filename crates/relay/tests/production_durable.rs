//! Production Relay durability, loss and authenticated-reconstruction tests.

#![cfg(all(
    feature = "real-bip340",
    feature = "production-durable",
    target_os = "linux"
))]

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

use btc_crypto::SecpContext;
use relay::auth::{
    message_type, RecipientContextV1, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1,
};
use relay::production::{
    DeliveryAckV3, DeliveryCursorV3, DeliveryPageLimitsV2, DeliveryPageLimitsV3, DeliveryPageV3,
    DeliveryScopeV3, ProductionRelayError, ProductionRelayV1, RelayDatabaseConfigV1,
    RelayDatabaseIdV1, MAX_DELIVERY_PAGE_BYTES_V2, MAX_DELIVERY_PAGE_ITEMS_V2,
    RELAY_DATABASE_FILE_NAME,
};
use relay::recovery::{
    authenticate_recovery_sources_v1, RecoveryCandidateV1, RecoveryError, RecoveryScopeV1,
};
use relay::server::{AckV1, IdempotencyKeyV1, ACK_V1_LEN};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];
const SOLVER_SECRET: [u8; 32] = [0x51; 32];
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);

fn crypto() -> SecpContext {
    SecpContext::new(&[0x99; 32])
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    crypto()
        .sign_bip340(secret, &[0_u8; 32], &[0_u8; 32])
        .expect("fixture public key")
        .1
}

fn signed(sequence: u64, previous: [u8; 32], payload: &[u8]) -> RelayEnvelopeV1 {
    signed_in_scope(SESSION, ROUTE, sequence, previous, payload)
}

fn signed_in_scope(
    session_id: [u8; 32],
    route_id: [u8; 32],
    sequence: u64,
    previous: [u8; 32],
    payload: &[u8],
) -> RelayEnvelopeV1 {
    let mut envelope = RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: message_type::QUOTE,
        session_id,
        route_id,
        sender_id: SOLVER,
        recipient_id: INITIATOR,
        sender_role: SenderRoleV1::Solver,
        sequence,
        previous_transcript_hash: previous,
        payload: payload.to_vec(),
        expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0_u8; 64],
    };
    let digest = envelope.envelope_digest().expect("fixture digest");
    envelope.signature = crypto()
        .sign_bip340(&SOLVER_SECRET, &digest, &[0x01; 32])
        .expect("fixture signature")
        .0;
    envelope
}

#[test]
fn delivery_v3_interleaved_sessions_restart_and_transplants_are_strictly_scoped() {
    let parent = owner_root();
    let root = parent.path().join("relay-v3-scoped");
    let other_root = parent.path().join("relay-v3-other-database");
    let session_a = [0x24; 32];
    let session_b = [0x25; 32];
    let route_a = [0x34; 32];
    let route_b = [0x35; 32];
    let scope_a = DeliveryScopeV3::new(INITIATOR, route_a, session_a).expect("scope A");
    let scope_b = DeliveryScopeV3::new(INITIATOR, route_b, session_b).expect("scope B");
    let a0 = signed_in_scope(session_a, route_a, 0, [0; 32], &[0xa0]);
    let a0_digest = a0.envelope_digest().expect("A0 digest");
    let a1 = signed_in_scope(session_a, route_a, 1, a0_digest, &[0xa1]);
    let b0 = signed_in_scope(session_b, route_b, 0, [0; 32], &[0xb0]);
    let a0_raw = a0.canonical_bytes().expect("A0 bytes");
    let a1_raw = a1.canonical_bytes().expect("A1 bytes");
    let b0_raw = b0.canonical_bytes().expect("B0 bytes");
    let limits =
        DeliveryPageLimitsV3::new(1, relay::MAX_ENVELOPE_BYTES as u32).expect("one-envelope limit");

    let mut relay = ProductionRelayV1::create(&root, config()).expect("create relay");
    relay.submit(&a0_raw).expect("submit A0");
    relay.submit(&b0_raw).expect("submit B0 interleaved");
    relay.submit(&a1_raw).expect("submit A1 interleaved");

    let cursor_a = relay
        .acknowledged_delivery_cursor_v3(&scope_a)
        .expect("cursor A");
    let cursor_a_bytes = cursor_a.canonical_bytes();
    assert_eq!(
        DeliveryCursorV3::decode(&cursor_a_bytes).expect("cursor V3 codec"),
        cursor_a
    );
    assert!(DeliveryCursorV3::decode(&cursor_a_bytes[..cursor_a_bytes.len() - 1]).is_err());
    let page_a = relay
        .delivery_page_v3(&scope_a, &cursor_a, limits)
        .expect("page A");
    assert_eq!(page_a.envelopes(), std::slice::from_ref(&a0_raw));
    assert!(page_a.has_more());
    let page_a_bytes = page_a.canonical_bytes().expect("canonical A page");
    assert_eq!(
        DeliveryPageV3::decode(&page_a_bytes, limits).expect("decode A page"),
        page_a
    );
    let mut trailing = page_a_bytes.clone();
    trailing.push(0);
    assert!(DeliveryPageV3::decode(&trailing, limits).is_err());

    let cursor_b = relay
        .acknowledged_delivery_cursor_v3(&scope_b)
        .expect("cursor B");
    let page_b = relay
        .delivery_page_v3(&scope_b, &cursor_b, limits)
        .expect("page B while A pending");
    assert_eq!(page_b.envelopes(), std::slice::from_ref(&b0_raw));
    let page_b_bytes = page_b.canonical_bytes().expect("canonical B page");

    assert!(matches!(
        relay.acknowledge_delivery_page_v3(&scope_b, page_a.next_cursor()),
        Err(ProductionRelayError::InvalidDeliveryCursor)
    ));
    let wrong_route = DeliveryScopeV3::new(INITIATOR, [0x36; 32], session_a).expect("wrong route");
    assert!(matches!(
        relay.acknowledge_delivery_page_v3(&wrong_route, page_a.next_cursor()),
        Err(ProductionRelayError::InvalidDeliveryCursor)
    ));
    let wrong_session =
        DeliveryScopeV3::new(INITIATOR, route_a, [0x26; 32]).expect("wrong session");
    assert!(matches!(
        relay.acknowledge_delivery_page_v3(&wrong_session, page_a.next_cursor()),
        Err(ProductionRelayError::InvalidDeliveryCursor)
    ));
    let wrong_recipient = DeliveryScopeV3::new(ParticipantId([0x32; 32]), route_a, session_a)
        .expect("wrong recipient");
    assert!(matches!(
        relay.acknowledge_delivery_page_v3(&wrong_recipient, page_a.next_cursor()),
        Err(ProductionRelayError::InvalidDeliveryCursor)
    ));

    let other_config = RelayDatabaseConfigV1::new(
        RelayDatabaseIdV1::new([0xa6; 32]).expect("other database id"),
        64,
    )
    .expect("other config");
    let other = ProductionRelayV1::create(&other_root, other_config).expect("other relay");
    let other_cursor = other
        .acknowledged_delivery_cursor_v3(&scope_a)
        .expect("other database cursor");
    drop(other);
    assert!(matches!(
        relay.delivery_page_v3(&scope_a, &other_cursor, limits),
        Err(ProductionRelayError::InvalidDeliveryCursor)
    ));

    let next_a = *page_a.next_cursor();
    let ack_a = relay
        .acknowledge_delivery_page_v3(&scope_a, &next_a)
        .expect("ACK only A0");
    assert_eq!(
        DeliveryAckV3::decode(&ack_a.canonical_bytes()).expect("ACK V3 codec"),
        ack_a
    );
    assert_eq!(relay.len().expect("only A0 collected"), 2);
    drop(relay);

    let mut relay = ProductionRelayV1::open(&root, config()).expect("restart relay");
    assert_eq!(
        relay
            .delivery_page_v3(&scope_b, &cursor_b, limits)
            .expect("exact B redelivery after restart")
            .canonical_bytes()
            .expect("B bytes after restart"),
        page_b_bytes
    );
    relay
        .acknowledge_delivery_page_v3(&scope_b, page_b.next_cursor())
        .expect("ACK B only");
    assert_eq!(relay.len().expect("A1 remains"), 1);
    let next_page_a = relay
        .delivery_page_v3(&scope_a, &next_a, limits)
        .expect("A1 after independent B ACK");
    assert_eq!(next_page_a.envelopes(), &[a1_raw]);
}

fn rosters() -> RosterRegistryV1 {
    RosterRegistryV1::new().with_snapshot(
        SNAPSHOT,
        RosterSnapshotV1::new().with_member(
            SOLVER,
            RosterMemberV1 {
                xonly_key: xonly_of(&SOLVER_SECRET),
                role: SenderRoleV1::Solver,
            },
        ),
    )
}

fn scope() -> RecoveryScopeV1 {
    RecoveryScopeV1::new(
        RecipientContextV1 {
            recipient_id: INITIATOR,
            network_id: NETWORK,
            session_id: SESSION,
            route_id: ROUTE,
        },
        TimelockSpec::TimestampSeconds { value: 1_000 },
    )
}

fn config() -> RelayDatabaseConfigV1 {
    RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0xa5; 32]).expect("database id"), 64)
        .expect("database config")
}

/// A temporary root the production relay will accept.
///
/// `tempfile::tempdir()` honours the process umask, so on a host with a
/// permissive one it yields `0775` and the relay rejects it with
/// `InvalidConfiguration` — correctly, because it requires an owner-only
/// parent. These tests are named for an "owner root" and have always meant to
/// provide one; they were relying on the developer's umask to get it. This
/// makes the fixture provide what the production check demands instead of
/// depending on ambient state. The check itself is untouched.
fn owner_root() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary owner root");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("owner-only temporary root");
    directory
}

fn pending_page_bytes(relay: &mut ProductionRelayV1, recipient: ParticipantId) -> Vec<Vec<u8>> {
    let current = relay
        .acknowledged_delivery_cursor_v2(&recipient)
        .expect("delivery cursor");
    relay
        .delivery_page_v2(
            &recipient,
            &current,
            DeliveryPageLimitsV2::new(MAX_DELIVERY_PAGE_ITEMS_V2, MAX_DELIVERY_PAGE_BYTES_V2)
                .expect("delivery limits"),
        )
        .expect("bounded delivery page")
        .envelopes()
        .to_vec()
}

#[test]
fn ack_loss_resend_and_process_restart_preserve_exact_bytes() {
    let parent = owner_root();
    let root = parent.path().join("relay");
    let envelope = signed(0, [0_u8; 32], &[0xd0, 0xd1]);
    let raw = envelope.canonical_bytes().expect("canonical envelope");
    let key = IdempotencyKeyV1::of(&envelope);

    let mut relay = ProductionRelayV1::create(&root, config()).expect("create relay");
    let first = relay.submit(&raw).expect("durable first submit");
    let first_bytes = first.canonical_bytes();
    assert_eq!(first_bytes.len(), ACK_V1_LEN);
    assert_eq!(AckV1::decode(&first_bytes).expect("ACK codec"), first);
    drop(relay); // Simulates losing the returned ACK with process state.

    let mut reopened = ProductionRelayV1::open(&root, config()).expect("process restart");
    let retry = reopened.submit(&raw).expect("exact resend");
    assert_eq!(retry.canonical_bytes(), first_bytes);
    assert_eq!(
        reopened.stored_bytes(&key).expect("stored row"),
        Some(raw.clone())
    );
    assert_eq!(pending_page_bytes(&mut reopened, INITIATOR), vec![raw]);
    assert_eq!(reopened.len().expect("row count"), 1);

    let mut bad_domain = first_bytes;
    bad_domain[0] ^= 1;
    assert!(matches!(
        AckV1::decode(&bad_domain),
        Err(relay::server::AckCodecError::WrongDomain)
    ));
    assert!(matches!(
        AckV1::decode(&first_bytes[..ACK_V1_LEN - 1]),
        Err(relay::server::AckCodecError::WrongLength)
    ));
}

#[test]
fn owner_only_database_and_single_writer_are_refused_without_repair() {
    let parent = owner_root();
    let root = parent.path().join("relay");
    let relay = ProductionRelayV1::create(&root, config()).expect("create relay");
    assert!(matches!(
        ProductionRelayV1::open(&root, config()),
        Err(ProductionRelayError::StorageUnavailable)
    ));
    drop(relay);

    let database = root.join(RELAY_DATABASE_FILE_NAME);
    fs::set_permissions(&database, fs::Permissions::from_mode(0o640))
        .expect("make database mode invalid");
    assert!(matches!(
        ProductionRelayV1::open(&root, config()),
        Err(ProductionRelayError::InvalidConfiguration)
    ));
    assert_eq!(
        fs::symlink_metadata(&database)
            .expect("database metadata")
            .mode()
            & 0o777,
        0o640,
        "open repaired an existing wrong-mode database"
    );
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("restore fixture mode");
    let alias = root.join("database-hardlink");
    fs::hard_link(&database, &alias).expect("fixture hardlink");
    assert!(matches!(
        ProductionRelayV1::open(&root, config()),
        Err(ProductionRelayError::InvalidConfiguration)
    ));
    assert_eq!(
        fs::symlink_metadata(&database)
            .expect("database metadata")
            .nlink(),
        2,
        "open repaired a pre-existing hardlink"
    );
    fs::remove_file(&alias).expect("remove fixture hardlink");
    let real_database = root.join("database-real");
    fs::rename(&database, &real_database).expect("move fixture database");
    symlink(&real_database, &database).expect("fixture database symlink");
    assert!(matches!(
        ProductionRelayV1::open(&root, config()),
        Err(ProductionRelayError::InvalidConfiguration)
    ));
    assert!(
        fs::symlink_metadata(&database)
            .expect("database symlink metadata")
            .file_type()
            .is_symlink(),
        "open repaired a pre-existing symlink"
    );
}

#[test]
fn durable_equivocation_is_fail_closed_and_survives_restart() {
    let parent = owner_root();
    let root = parent.path().join("relay");
    let first = signed(0, [0_u8; 32], &[0x01]);
    let second = signed(0, [0_u8; 32], &[0x02]);
    let first_raw = first.canonical_bytes().expect("first bytes");
    let second_raw = second.canonical_bytes().expect("second bytes");
    let key = IdempotencyKeyV1::of(&first);

    let mut relay = ProductionRelayV1::create(&root, config()).expect("create relay");
    relay.submit(&first_raw).expect("first submit");
    assert!(matches!(
        relay.submit(&second_raw),
        Err(ProductionRelayError::Equivocation)
    ));
    drop(relay);

    let reopened = ProductionRelayV1::open(&root, config()).expect("restart");
    let proof = reopened
        .equivocation_proof(&key)
        .expect("proof lookup")
        .expect("durable proof");
    assert_eq!(proof.first, first_raw);
    assert_eq!(proof.second, second_raw);
}

#[test]
fn database_loss_never_opens_empty_and_only_authenticated_batch_reconstructs() {
    let parent = owner_root();
    let root = parent.path().join("relay");
    let envelope = signed(0, [0_u8; 32], &[0x31, 0x32]);
    let raw = envelope.canonical_bytes().expect("canonical bytes");

    let mut relay = ProductionRelayV1::create(&root, config()).expect("create relay");
    relay.submit(&raw).expect("durable submit");
    drop(relay);
    for name in [
        RELAY_DATABASE_FILE_NAME.to_owned(),
        format!("{RELAY_DATABASE_FILE_NAME}-wal"),
        format!("{RELAY_DATABASE_FILE_NAME}-shm"),
    ] {
        let path = root.join(name);
        if path.try_exists().expect("database object metadata") {
            fs::remove_file(path).expect("explicit database loss");
        }
    }

    assert!(matches!(
        ProductionRelayV1::open(&root, config()),
        Err(ProductionRelayError::DatabaseMissing)
    ));

    let store = RecoveryCandidateV1::participant_store_outbox([0xb1; 32], raw.clone())
        .expect("Store candidate");
    let chain =
        RecoveryCandidateV1::public_chain([0xb2; 32], raw.clone()).expect("chain candidate");
    let batch = authenticate_recovery_sources_v1(vec![chain, store], &[scope()], &rosters())
        .expect("authenticated recovery batch");
    assert_eq!(batch.len(), 1, "exact duplicate sources must collapse");
    let mut recovered =
        ProductionRelayV1::reconstruct(&root, config(), batch).expect("reconstruct database");
    assert_eq!(pending_page_bytes(&mut recovered, INITIATOR), vec![raw]);
}

#[test]
fn recovery_rejects_substitution_foreign_scope_gap_and_null_source_binding() {
    let first = signed(0, [0_u8; 32], &[0x41]);
    let first_raw = first.canonical_bytes().expect("first bytes");
    assert!(matches!(
        authenticate_recovery_sources_v1(Vec::new(), &[scope()], &rosters()),
        Err(RecoveryError::EmptySourceSet)
    ));
    assert!(matches!(
        RecoveryCandidateV1::participant_store_outbox([0_u8; 32], first_raw.clone()),
        Err(RecoveryError::InvalidSourceBinding)
    ));

    let mut substituted = first_raw.clone();
    let payload_offset = substituted.len() - 64 - 1;
    substituted[payload_offset] ^= 1;
    let tampered = RecoveryCandidateV1::public_chain([0xc1; 32], substituted)
        .expect("bound tampered candidate");
    assert!(authenticate_recovery_sources_v1(vec![tampered], &[scope()], &rosters()).is_err());

    let foreign = RecoveryScopeV1::new(
        RecipientContextV1 {
            recipient_id: INITIATOR,
            network_id: NETWORK,
            session_id: SESSION,
            route_id: [0xee; 32],
        },
        TimelockSpec::TimestampSeconds { value: 1_000 },
    );
    let candidate = RecoveryCandidateV1::participant_store_outbox([0xc2; 32], first_raw.clone())
        .expect("Store candidate");
    assert!(matches!(
        authenticate_recovery_sources_v1(vec![candidate], &[foreign], &rosters()),
        Err(RecoveryError::UnknownScope)
    ));

    let conflict_a = signed(0, [0_u8; 32], &[0x44])
        .canonical_bytes()
        .expect("conflict A");
    let conflict_b = signed(0, [0_u8; 32], &[0x45])
        .canonical_bytes()
        .expect("conflict B");
    let conflict_inputs = vec![
        RecoveryCandidateV1::participant_store_outbox([0xc4; 32], conflict_a)
            .expect("conflict candidate A"),
        RecoveryCandidateV1::public_chain([0xc5; 32], conflict_b).expect("conflict candidate B"),
    ];
    assert!(matches!(
        authenticate_recovery_sources_v1(conflict_inputs, &[scope()], &rosters()),
        Err(RecoveryError::ConflictingCandidate)
    ));

    let gap = signed(1, [0_u8; 32], &[0x42]);
    let candidate = RecoveryCandidateV1::participant_store_outbox(
        [0xc3; 32],
        gap.canonical_bytes().expect("gap bytes"),
    )
    .expect("gap candidate");
    assert!(matches!(
        authenticate_recovery_sources_v1(vec![candidate], &[scope()], &rosters()),
        Err(RecoveryError::Authentication(_))
    ));

    let mut impostor = signed(0, [0_u8; 32], &[0x46]);
    let digest = impostor.envelope_digest().expect("impostor digest");
    impostor.signature = crypto()
        .sign_bip340(&[0x53; 32], &digest, &[0x02; 32])
        .expect("impostor signature")
        .0;
    let candidate = RecoveryCandidateV1::public_chain(
        [0xc6; 32],
        impostor.canonical_bytes().expect("impostor bytes"),
    )
    .expect("impostor candidate");
    assert!(matches!(
        authenticate_recovery_sources_v1(vec![candidate], &[scope()], &rosters()),
        Err(RecoveryError::Authentication(_))
    ));
}

#[test]
fn recovery_sorts_a_complete_transcript_and_binds_source_provenance() {
    let first = signed(0, [0_u8; 32], &[0x81]);
    let first_digest = first.envelope_digest().expect("first digest");
    let second = signed(1, first_digest, &[0x82]);
    let first_raw = first.canonical_bytes().expect("first bytes");
    let second_raw = second.canonical_bytes().expect("second bytes");
    let reversed = vec![
        RecoveryCandidateV1::public_chain([0xe1; 32], second_raw).expect("second candidate"),
        RecoveryCandidateV1::participant_store_outbox([0xe2; 32], first_raw.clone())
            .expect("first candidate"),
    ];
    let first_batch = authenticate_recovery_sources_v1(reversed, &[scope()], &rosters())
        .expect("sorted authenticated batch");
    assert_eq!(first_batch.len(), 2);

    let changed_provenance =
        vec![
            RecoveryCandidateV1::participant_store_outbox([0xe3; 32], first_raw)
                .expect("changed provenance candidate"),
        ];
    let second_batch = authenticate_recovery_sources_v1(changed_provenance, &[scope()], &rosters())
        .expect("second authenticated batch");
    assert_ne!(
        first_batch.digest(),
        second_batch.digest(),
        "recovery digest did not bind source provenance and exact row set"
    );
}

#[test]
fn on_disk_row_tamper_is_rejected_without_payload_logging() {
    let parent = owner_root();
    let root = parent.path().join("relay");
    let raw = signed(0, [0_u8; 32], &[0x51])
        .canonical_bytes()
        .expect("canonical bytes");
    let mut relay = ProductionRelayV1::create(&root, config()).expect("create relay");
    relay.submit(&raw).expect("submit");
    drop(relay);

    let database = root.join(RELAY_DATABASE_FILE_NAME);
    let connection = rusqlite::Connection::open(&database).expect("diagnostic tamper handle");
    connection
        .execute(
            "UPDATE relay_envelopes SET row_digest = zeroblob(32) WHERE ordinal = 1",
            [],
        )
        .expect("tamper row digest");
    drop(connection);

    let error = ProductionRelayV1::open(&root, config()).expect_err("tamper must fail closed");
    assert!(matches!(&error, ProductionRelayError::CorruptState));
    let debug = format!("{error:?}");
    assert!(
        !debug.contains("51"),
        "error Debug exposed payload material"
    );
}

#[test]
fn on_disk_schema_drift_is_rejected_even_when_sqlite_is_well_formed() {
    let parent = owner_root();
    let root = parent.path().join("relay");
    drop(ProductionRelayV1::create(&root, config()).expect("create relay"));

    let database = root.join(RELAY_DATABASE_FILE_NAME);
    let connection = rusqlite::Connection::open(&database).expect("diagnostic tamper handle");
    connection
        .execute_batch(
            "PRAGMA writable_schema=ON;
             UPDATE sqlite_schema SET sql = sql || ' '
             WHERE type = 'table' AND name = 'relay_envelopes';
             PRAGMA writable_schema=OFF;",
        )
        .expect("tamper persisted schema SQL");
    drop(connection);

    assert!(matches!(
        ProductionRelayV1::open(&root, config()),
        Err(ProductionRelayError::UnsupportedFormat)
    ));
}

#[test]
fn incomplete_reconstruction_database_never_opens() {
    let parent = owner_root();
    let root = parent.path().join("relay");
    drop(ProductionRelayV1::create(&root, config()).expect("create relay"));

    let database = root.join(RELAY_DATABASE_FILE_NAME);
    let connection = rusqlite::Connection::open(&database).expect("diagnostic tamper handle");
    connection
        .execute(
            "UPDATE relay_meta
             SET creation_kind = 2, recovery_digest = ?1, reconstruction_complete = 0
             WHERE singleton = 1",
            rusqlite::params![[0x93_u8; 32].as_slice()],
        )
        .expect("mark reconstruction incomplete");
    drop(connection);

    assert!(matches!(
        ProductionRelayV1::open(&root, config()),
        Err(ProductionRelayError::CorruptState)
    ));
}

#[cfg(feature = "relay-fault-injection")]
mod fault_tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    use relay::fault::{
        verify_database_loss_marker_v1, verify_process_loss_marker_v1, RelayDatabaseLossFaultV1,
        RelayProcessLossFaultV1,
    };

    use super::*;

    const CHILD_ENV: &str = "DOM_INTEROP_RELAY_PROCESS_LOSS_CHILD_V1";
    const ROOT_ENV: &str = "DOM_INTEROP_RELAY_PROCESS_LOSS_ROOT_V1";

    #[test]
    fn process_loss_after_commit_resends_exact_ack_after_restart() {
        if std::env::var_os(CHILD_ENV).is_some() {
            return;
        }
        let parent = owner_root();
        let root = parent.path().join("relay");
        ProductionRelayV1::create(&root, config()).expect("create relay");
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("fault_tests::production_process_loss_child")
            .arg("--nocapture")
            .env_clear()
            .env(CHILD_ENV, "1")
            .env(ROOT_ENV, &root)
            .current_dir(&root)
            .status()
            .expect("spawn fault child");
        assert_eq!(status.signal(), Some(6), "child did not die by SIGABRT");

        let envelope = signed(0, [0_u8; 32], &[0x61]);
        let raw = envelope.canonical_bytes().expect("canonical bytes");
        let key = IdempotencyKeyV1::of(&envelope);
        let digest = envelope.envelope_digest().expect("envelope digest");
        assert!(
            verify_process_loss_marker_v1(&root, config().database_id(), &key, &digest)
                .expect("verify fired marker")
        );
        assert!(
            !verify_process_loss_marker_v1(&root, config().database_id(), &key, &[0xf1; 32])
                .expect("reject wrong fired-marker digest")
        );
        let mut relay = ProductionRelayV1::open(&root, config()).expect("restart");
        let retry = relay.submit(&raw).expect("persisted retry ACK");
        assert_eq!(retry.key, key);
        assert_eq!(relay.len().expect("row count"), 1);
    }

    #[test]
    fn production_process_loss_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let root = std::path::PathBuf::from(std::env::var_os(ROOT_ENV).expect("child root"));
        let envelope = signed(0, [0_u8; 32], &[0x61]);
        let raw = envelope.canonical_bytes().expect("canonical bytes");
        let key = IdempotencyKeyV1::of(&envelope);
        let digest = envelope.envelope_digest().expect("envelope digest");
        let mut relay = ProductionRelayV1::open(&root, config()).expect("child open");
        let _ = relay.submit_with_process_loss_fault(
            &raw,
            RelayProcessLossFaultV1::new(config().database_id(), key, digest),
        );
        panic!("process-loss fault returned after a new durable commit");
    }

    #[test]
    fn process_loss_fault_rejects_wrong_digest_before_storage() {
        let parent = owner_root();
        let root = parent.path().join("relay");
        let envelope = signed(0, [0_u8; 32], &[0x62]);
        let raw = envelope.canonical_bytes().expect("canonical bytes");
        let key = IdempotencyKeyV1::of(&envelope);
        let mut relay = ProductionRelayV1::create(&root, config()).expect("create relay");
        assert!(matches!(
            relay.submit_with_process_loss_fault(
                &raw,
                RelayProcessLossFaultV1::new(config().database_id(), key, [0xf2; 32]),
            ),
            Err(ProductionRelayError::InvalidConfiguration)
        ));
        assert_eq!(relay.len().expect("row count"), 0);
    }

    #[test]
    fn database_loss_hook_is_exact_and_requires_authenticated_reconstruction() {
        let parent = owner_root();
        let root = parent.path().join("relay");
        let envelope = signed(0, [0_u8; 32], &[0x71]);
        let raw = envelope.canonical_bytes().expect("canonical bytes");
        let mut relay = ProductionRelayV1::create(&root, config()).expect("create relay");
        relay.submit(&raw).expect("submit");
        let receipt = relay
            .destroy_database_with_fault(RelayDatabaseLossFaultV1::new(config().database_id()))
            .expect("database loss cut");
        assert_eq!(receipt.database_id(), config().database_id());
        assert!(
            verify_database_loss_marker_v1(&root, config().database_id())
                .expect("verify database-loss marker")
        );
        assert!(matches!(
            ProductionRelayV1::open(&root, config()),
            Err(ProductionRelayError::DatabaseMissing)
        ));
        let batch = authenticate_recovery_sources_v1(
            vec![
                RecoveryCandidateV1::participant_store_outbox([0xd1; 32], raw.clone())
                    .expect("candidate"),
            ],
            &[scope()],
            &rosters(),
        )
        .expect("authenticated batch");
        let mut recovered =
            ProductionRelayV1::reconstruct(&root, config(), batch).expect("reconstruct");
        assert_eq!(pending_page_bytes(&mut recovered, INITIATOR), vec![raw]);
    }
}

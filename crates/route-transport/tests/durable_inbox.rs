//! Durable relay-to-consumer boundary: restart, receipt loss, duplicate Relay
//! delivery, production queue parity, and one transcript across F6/route.

#![cfg(target_os = "linux")]
#![allow(deprecated)] // Sender convenience is used only to seed test mailboxes.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Arc;

use btc_crypto::SecpContext;
use cap_std::fs::Dir;
use dom_crypto::{schnorr_sign, SecretKey};
use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};
use dom_scriptless_store::{
    BudgetPolicyProfileV1, BudgetPolicyV1, ContractsSessionStoreV1, DirectionV1,
    DurableTransportOutcomeV1, SessionChainProjectionV1, SessionIrreversibleV1, SessionPhaseV1,
    SessionRecordFieldsV1, SessionRecordV1, SessionStoreError, SessionTransportIdentityReferenceV1,
    SessionTransportParticipantV1, SessionTxObservationV1, BUDGET_POLICY_LEN,
};
use kaystra_core::types::Digest32;
use relay::auth::{message_type, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
use relay::server::RelayV1;
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use route_transport::{
    ContractsRouteDeliveryV1, ContractsTransportPortV1, DurableInboxConfigV1, DurableInboxError,
    DurablePayloadCommitV1, DurablePayloadDispositionV1, DurableRelayInboxV1, F6PayloadDeliveryV1,
    F6TransportPortV1, RouteSenderV1, RouteWireContextV1,
};

const NETWORK: Digest32 = [0x11; 32];
const SESSION: Digest32 = [0x22; 32];
const ROUTE: Digest32 = [0x33; 32];
const SNAPSHOT: Digest32 = [0x77; 32];
const INBOX: Digest32 = [0x88; 32];
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR_SECRET: [u8; 32] = [0x52; 32];

fn wire() -> RouteWireContextV1 {
    RouteWireContextV1 {
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        roster_snapshot: SNAPSHOT,
        policy_version: 1,
    }
}

fn config() -> Result<DurableInboxConfigV1, Box<dyn Error>> {
    Ok(DurableInboxConfigV1::new(
        INBOX,
        [0x91; 32],
        wire(),
        SOLVER,
        64,
    )?)
}

fn expiry() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 10_000 }
}

fn now() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

fn secure_tempdir() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(temporary)
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    SecpContext::new(&[0x99; 32])
        .sign_bip340(secret, &[0u8; 32], &[0u8; 32])
        .expect("public test key is valid")
        .1
}

fn rosters() -> RosterRegistryV1 {
    let snapshot = RosterSnapshotV1::new()
        .with_member(
            INITIATOR,
            RosterMemberV1 {
                xonly_key: xonly_of(&INITIATOR_SECRET),
                role: SenderRoleV1::Initiator,
            },
        )
        .with_member(
            SOLVER,
            RosterMemberV1 {
                xonly_key: xonly_of(&[0x51; 32]),
                role: SenderRoleV1::Solver,
            },
        );
    RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot)
}

fn sender() -> Result<RouteSenderV1, Box<dyn Error>> {
    Ok(RouteSenderV1::new(
        wire(),
        INITIATOR,
        SOLVER,
        SenderRoleV1::Initiator,
        INITIATOR_SECRET,
        [0x99; 32],
    )?)
}

#[test]
fn production_resume_recovers_only_pristine_inbox_prefixes() -> Result<(), Box<dyn Error>> {
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
                    .open(root.join(".route-inbox.lock"))?;
                lock.sync_all()?;
                if name == "database-file-synced" {
                    let database = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(root.join("route-inbox-v1.sqlite3"))?;
                    database.sync_all()?;
                }
            }
            "initialized" => {
                drop(DurableRelayInboxV1::create(&root, config()?, &rosters())?);
            }
            _ => return Err("unreachable inbox prefix".into()),
        }
        let resumed = DurableRelayInboxV1::resume_create_production(&root, config()?, &rosters())?;
        assert_eq!(resumed.stats()?, Default::default());
        assert_eq!(
            fs::metadata(root.join("route-inbox-v1.sqlite3"))?
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        drop(resumed);
        drop(DurableRelayInboxV1::open(&root, config()?, &rosters())?);
    }
    Ok(())
}

#[test]
fn production_resume_refuses_inbox_traffic_transplant_and_unknown_entry(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let economic = temporary.path().join("economic");
    let mut relay = RelayV1::new();
    sender()?.send(&mut relay, b"economic".to_vec(), expiry(), [3; 32])?;
    let mut inbox = DurableRelayInboxV1::create(&economic, config()?, &rosters())?;
    assert_eq!(
        inbox
            .ingest_ephemeral_v1(&relay, &rosters(), now())?
            .accepted,
        1
    );
    drop(inbox);
    assert!(matches!(
        DurableRelayInboxV1::resume_create_production(&economic, config()?, &rosters()),
        Err(DurableInboxError::UnsupportedFormat)
    ));

    let transplanted = temporary.path().join("transplanted");
    drop(DurableRelayInboxV1::create(
        &transplanted,
        config()?,
        &rosters(),
    )?);
    fs::hard_link(
        transplanted.join("route-inbox-v1.sqlite3"),
        temporary.path().join("inbox-hardlink.sqlite3"),
    )?;
    assert!(matches!(
        DurableRelayInboxV1::resume_create_production(&transplanted, config()?, &rosters()),
        Err(DurableInboxError::InvalidConfiguration)
    ));

    let unknown = temporary.path().join("unknown");
    drop(DurableRelayInboxV1::create(
        &unknown,
        config()?,
        &rosters(),
    )?);
    fs::write(unknown.join("caller-shaped"), b"foreign")?;
    assert!(matches!(
        DurableRelayInboxV1::resume_create_production(&unknown, config()?, &rosters()),
        Err(DurableInboxError::InvalidConfiguration)
    ));

    let special_database = temporary.path().join("special-database-mode");
    drop(DurableRelayInboxV1::create(
        &special_database,
        config()?,
        &rosters(),
    )?);
    fs::set_permissions(
        special_database.join("route-inbox-v1.sqlite3"),
        fs::Permissions::from_mode(0o4600),
    )?;
    assert!(matches!(
        DurableRelayInboxV1::production_creation_state(&special_database, config()?),
        Err(DurableInboxError::InvalidConfiguration)
    ));

    let special_root = temporary.path().join("special-root-mode");
    drop(DurableRelayInboxV1::create(
        &special_root,
        config()?,
        &rosters(),
    )?);
    fs::set_permissions(&special_root, fs::Permissions::from_mode(0o1700))?;
    assert!(matches!(
        DurableRelayInboxV1::production_creation_state(&special_root, config()?),
        Err(DurableInboxError::InvalidConfiguration)
    ));

    let oversized_schema = temporary.path().join("oversized-schema");
    drop(DurableRelayInboxV1::create(
        &oversized_schema,
        config()?,
        &rosters(),
    )?);
    let connection = rusqlite::Connection::open(oversized_schema.join("route-inbox-v1.sqlite3"))?;
    for index in 0..8 {
        connection.execute(
            &format!("CREATE TABLE injected_{index}(value INTEGER) STRICT"),
            [],
        )?;
    }
    drop(connection);
    assert!(matches!(
        DurableRelayInboxV1::production_creation_state(&oversized_schema, config()?),
        Err(DurableInboxError::UnsupportedFormat)
    ));
    Ok(())
}

fn signed_outer(
    message_type: u16,
    sequence: u64,
    previous: Digest32,
    payload: &[u8],
    aux: u8,
) -> Result<(Vec<u8>, Digest32), Box<dyn Error>> {
    let mut envelope = RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type,
        session_id: SESSION,
        route_id: ROUTE,
        sender_id: INITIATOR,
        recipient_id: SOLVER,
        sender_role: SenderRoleV1::Initiator,
        sequence,
        previous_transcript_hash: previous,
        payload: payload.to_vec(),
        expiry: expiry(),
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0; 64],
    };
    let digest = envelope.envelope_digest()?;
    envelope.signature = SecpContext::new(&[0x99; 32])
        .sign_bip340(&INITIATOR_SECRET, &digest, &[aux; 32])?
        .0;
    Ok((envelope.canonical_bytes()?, digest))
}

fn evidence_policy() -> Result<BudgetPolicyV1, Box<dyn Error>> {
    let mut bytes = [0; BUDGET_POLICY_LEN];
    bytes[..8].copy_from_slice(b"DOMNVBP1");
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10] = BudgetPolicyProfileV1::EvidenceOnly as u8;
    bytes[11] = 1;
    bytes[16..48].fill(0x41);
    bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
    bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
    bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
    let digest = authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
    bytes[112..].copy_from_slice(&digest);
    Ok(BudgetPolicyV1::from_bytes(&bytes)?)
}

fn initial_contracts_record() -> Result<SessionRecordV1, Box<dyn Error>> {
    Ok(SessionRecordV1::new(
        SessionRecordFieldsV1 {
            session_id: SESSION,
            revision: 0,
            phase: SessionPhaseV1::Created,
            terms_hash: [0xa2; 32],
            transcript_hash: [0xa3; 32],
            irreversible: SessionIrreversibleV1 {
                any_signing_share_sent: true,
                funding_authorized: false,
                adaptor_secret_exposed: false,
                nonce_epoch: 1,
            },
            chain: SessionChainProjectionV1 {
                tip_id: [0xa4; 32],
                tip_height: 100,
                funding: SessionTxObservationV1::Unknown,
                claim: SessionTxObservationV1::Unknown,
                refund: SessionTxObservationV1::Unknown,
            },
        },
        b"sealed-test-session",
    )?)
}

fn dsc1_signed_bytes(
    key: &SecretKey,
    chain_id: Digest32,
    initial: &SessionRecordV1,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let payload = b"contracts-offer";
    let mut unsigned = vec![0; 148 + payload.len()];
    unsigned[..4].copy_from_slice(b"DSC1");
    unsigned[4..6].copy_from_slice(&1_u16.to_le_bytes());
    unsigned[6] = 0x01;
    unsigned[8..40].copy_from_slice(&chain_id);
    unsigned[40..72].copy_from_slice(&SESSION);
    unsigned[72..104].copy_from_slice(&INITIATOR.0);
    unsigned[104..112].copy_from_slice(&0_u64.to_le_bytes());
    unsigned[112..144].copy_from_slice(&initial.transcript_hash());
    unsigned[144..148].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    unsigned[148..].copy_from_slice(payload);
    let digest = tagged_hash("DOM:scriptless-message:v1", &unsigned);
    let signature = schnorr_sign(key, &digest, &chain_id)?;
    unsigned.extend_from_slice(&signature.to_bytes());
    Ok(unsigned)
}

fn tagged_hash(tag: &str, bytes: &[u8]) -> Digest32 {
    *dom_crypto::blake2b_256_tagged(tag, bytes).as_bytes()
}

fn create_contracts_store(
    temporary: &tempfile::TempDir,
) -> Result<(ContractsSessionStoreV1, Vec<u8>), Box<dyn Error>> {
    let parent = Arc::new(Dir::from_std_file(File::open(temporary.path())?));
    let policy = evidence_policy()?;
    let store = ContractsSessionStoreV1::create_evidence_only(parent, "contracts", policy)?;
    let initial = initial_contracts_record()?;
    store.create_session(&initial)?;
    let alice = SecretKey::from_bytes(&[0x11; 32])?;
    let bob = SecretKey::from_bytes(&[0x12; 32])?;
    let chain_id = [0xc3; 32];
    store.bind_transport_roster(
        SESSION,
        chain_id,
        [
            SessionTransportParticipantV1::new(
                INITIATOR.0,
                alice.public_key(),
                DirectionV1::Initiator,
            )?,
            SessionTransportParticipantV1::new(SOLVER.0, bob.public_key(), DirectionV1::Responder)?,
        ],
    )?;
    store.bind_transport_identity_references(
        SESSION,
        [
            SessionTransportIdentityReferenceV1::new(
                INITIATOR.0,
                [0xd1; 32],
                [0xe1; 32],
                alice.public_key(),
            )?,
            SessionTransportIdentityReferenceV1::new(
                SOLVER.0,
                [0xd2; 32],
                [0xe2; 32],
                bob.public_key(),
            )?,
        ],
    )?;
    let signed = dsc1_signed_bytes(&alice, chain_id, &initial)?;
    // This evidence-only fixture stands in for the narrow phase authority
    // which validated and prepared the Offer.  The production bridge below
    // cannot manufacture this successor and only redelivers through the
    // Store's derived boundary.
    let unsigned_len = signed.len().checked_sub(65).ok_or("malformed fixture")?;
    let message_digest = tagged_hash("DOM:scriptless-message:v1", &signed[..unsigned_len]);
    let mut transcript_body = [0; 67];
    transcript_body[..32].copy_from_slice(&initial.transcript_hash());
    transcript_body[32..64].copy_from_slice(&message_digest);
    transcript_body[64] = DirectionV1::Initiator.to_byte();
    transcript_body[65..].copy_from_slice(&(initial.phase() as u16).to_le_bytes());
    let successor = initial.advance(
        initial.revision(),
        initial.phase(),
        tagged_hash("DOM:scriptless-transcript:v1", &transcript_body),
        initial.irreversible(),
        initial.chain(),
        initial.encrypted_payload(),
    )?;
    assert!(matches!(
        store.accept_transport_message(&signed, &successor, None)?,
        DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate
    ));
    Ok((store, signed))
}

fn reopen_contracts_store(
    temporary: &tempfile::TempDir,
) -> Result<ContractsSessionStoreV1, Box<dyn Error>> {
    let parent = Arc::new(Dir::from_std_file(File::open(temporary.path())?));
    Ok(ContractsSessionStoreV1::open_evidence_only(
        parent,
        "contracts",
        evidence_policy()?,
    )?)
}

#[derive(Debug, thiserror::Error)]
enum RealContractsPortError {
    #[error("Contracts Store: {0}")]
    Store(#[from] SessionStoreError),
    #[error("malformed DSC1 payload")]
    Malformed,
    #[error("Contracts failed closed without a receipt")]
    FailedClosedWithoutReceipt,
    #[error("receipt lost after Contracts commit")]
    ReceiptLost,
}

struct RealContractsStorePort {
    store: ContractsSessionStoreV1,
    lose_next_receipt: bool,
}

impl ContractsTransportPortV1 for RealContractsStorePort {
    type Error = RealContractsPortError;

    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let bytes = delivery.signed_dsc1();
        if bytes.len() < 148 + 65 || &bytes[..4] != b"DSC1" {
            return Err(RealContractsPortError::Malformed);
        }
        let outcome = self.store.accept_transport_message_derived(bytes)?;
        let receipt = match outcome {
            DurableTransportOutcomeV1::Accepted(receipt) => receipt,
            DurableTransportOutcomeV1::EquivocationPersisted => {
                return Err(RealContractsPortError::FailedClosedWithoutReceipt)
            }
        };
        if self.lose_next_receipt {
            self.lose_next_receipt = false;
            return Err(RealContractsPortError::ReceiptLost);
        }
        DurablePayloadCommitV1::new(
            DurablePayloadDispositionV1::Applied,
            receipt.message_digest,
            receipt.duplicate,
        )
        .map_err(|_| RealContractsPortError::Malformed)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("contracts receipt was lost after durable commit")]
struct LostContractsReceipt;

#[derive(Default)]
struct RestartSafeContractsPort {
    durable: BTreeSet<Digest32>,
    payloads: Vec<Vec<u8>>,
    lose_first_receipt: bool,
}

impl ContractsTransportPortV1 for RestartSafeContractsPort {
    type Error = LostContractsReceipt;

    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let receipt = *delivery.envelope_digest();
        let duplicate = !self.durable.insert(receipt);
        if !duplicate {
            self.payloads.push(delivery.signed_dsc1().to_vec());
            if self.lose_first_receipt {
                self.lose_first_receipt = false;
                // The downstream commit above is durable; only the response
                // is lost.  The inbox must leave the row pending.
                return Err(LostContractsReceipt);
            }
        }
        DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, receipt, duplicate)
            .map_err(|_| LostContractsReceipt)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("F6 consumer refused")]
struct F6ConsumerError;

#[derive(Default)]
struct CollectingF6Port {
    durable: BTreeSet<Digest32>,
    kinds: Vec<u16>,
    payloads: Vec<Vec<u8>>,
}

impl F6TransportPortV1 for CollectingF6Port {
    type Error = F6ConsumerError;

    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let receipt = *delivery.envelope_digest();
        let duplicate = !self.durable.insert(receipt);
        if !duplicate {
            self.kinds.push(delivery.message_type());
            self.payloads.push(delivery.payload().to_vec());
        }
        DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, receipt, duplicate)
            .map_err(|_| F6ConsumerError)
    }
}

#[test]
fn accepted_envelope_survives_restart_and_contracts_receipt_loss() -> Result<(), Box<dyn Error>> {
    let mut relay = RelayV1::new();
    sender()?.send(&mut relay, b"exact-signed-dsc1".to_vec(), expiry(), [1; 32])?;

    let temporary = secure_tempdir()?;
    let root = temporary.path().join("inbox");
    let mut inbox = DurableRelayInboxV1::create(&root, config()?, &rosters())?;
    let first = inbox.ingest_ephemeral_v1(&relay, &rosters(), now())?;
    assert_eq!(
        (first.accepted, first.duplicates, first.refused.len()),
        (1, 0, 0)
    );
    assert_eq!(inbox.stats()?.pending_route, 1);

    // Crash after Relay acceptance and inbox commit, before Contracts.
    drop(inbox);
    let mut reopened = DurableRelayInboxV1::open(&root, config()?, &rosters())?;
    let mut contracts = RestartSafeContractsPort {
        lose_first_receipt: true,
        ..RestartSafeContractsPort::default()
    };

    // Contracts commits, then its response is lost: inbox still says pending.
    assert!(reopened.dispatch_routes(&mut contracts).is_err());
    assert_eq!(reopened.stats()?.pending_route, 1);
    assert_eq!(contracts.payloads, vec![b"exact-signed-dsc1".to_vec()]);

    // Another crash.  The exact payload is redelivered; Contracts recognizes
    // its durable duplicate and only then can the inbox mark it delivered.
    drop(reopened);
    let mut recovered = DurableRelayInboxV1::open(&root, config()?, &rosters())?;
    let report = recovered.dispatch_routes(&mut contracts)?;
    assert_eq!((report.applied, report.duplicate_commits), (1, 1));
    assert_eq!(
        contracts.payloads.len(),
        1,
        "economic processing happened once"
    );
    assert_eq!(recovered.stats()?.delivered, 1);

    // Relay remains at-least-once forever; another pull is an inbox duplicate,
    // not a second Contracts delivery.
    let duplicate = recovered.ingest_ephemeral_v1(&relay, &rosters(), now())?;
    assert_eq!((duplicate.accepted, duplicate.duplicates), (0, 1));
    assert_eq!(recovered.dispatch_routes(&mut contracts)?.applied, 0);
    Ok(())
}

#[test]
fn one_transcript_orders_interleaved_f6_and_route_consumers() -> Result<(), Box<dyn Error>> {
    let mut relay = RelayV1::new();
    let (rfq, digest0) = signed_outer(message_type::RFQ, 0, [0; 32], b"rfq", 1)?;
    let (route, digest1) =
        signed_outer(message_type::ROUTE_TRANSPORT, 1, digest0, b"signed-dsc1", 2)?;
    let (acceptance, _) = signed_outer(message_type::ACCEPTANCE, 2, digest1, b"acceptance", 3)?;
    relay.submit(&rfq)?;
    relay.submit(&route)?;
    relay.submit(&acceptance)?;

    let temporary = secure_tempdir()?;
    let root = temporary.path().join("inbox");
    let mut inbox = DurableRelayInboxV1::create(&root, config()?, &rosters())
        .map_err(|error| format!("create inbox: {error:?}"))?;
    let ingested = inbox.ingest_ephemeral_v1(&relay, &rosters(), now())?;
    assert_eq!(ingested.accepted, 3);
    assert!(ingested.refused.is_empty());
    assert_eq!(
        (inbox.stats()?.pending_f6, inbox.stats()?.pending_route),
        (2, 1)
    );

    // Reopen reconstructs the chain 0/F6 -> 1/route -> 2/F6 from durable
    // acceptance times.  A kind-specific worker may not jump over another
    // kind in the same flow.
    drop(inbox);
    let mut inbox = DurableRelayInboxV1::open(&root, config()?, &rosters())?;
    let mut contracts = RestartSafeContractsPort::default();
    let mut f6 = CollectingF6Port::default();
    let route_blocked = inbox.dispatch_routes(&mut contracts)?;
    assert_eq!((route_blocked.applied, route_blocked.blocked_by_f6), (0, 1));

    let first_f6 = inbox.dispatch_f6(&mut f6)?;
    assert_eq!((first_f6.applied, first_f6.blocked_by_route), (1, 1));
    assert_eq!(f6.kinds, vec![message_type::RFQ]);

    assert_eq!(inbox.dispatch_routes(&mut contracts)?.applied, 1);
    assert_eq!(contracts.payloads, vec![b"signed-dsc1".to_vec()]);
    assert_eq!(inbox.dispatch_f6(&mut f6)?.applied, 1);
    assert_eq!(f6.kinds, vec![message_type::RFQ, message_type::ACCEPTANCE]);
    assert_eq!(inbox.stats()?.delivered, 3);
    Ok(())
}

#[test]
fn production_relay_pages_one_item_persists_inbox_then_acks_and_gcs() -> Result<(), Box<dyn Error>>
{
    let temporary = secure_tempdir()?;
    let relay_root = temporary.path().join("relay");
    let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0x91; 32])?, 64)?;
    let mut relay = ProductionRelayV1::create(&relay_root, relay_config)
        .map_err(|error| format!("create relay: {error:?}"))?;
    let ack = sender()?.send(&mut relay, b"production-dsc1".to_vec(), expiry(), [4; 32])?;
    let exact = relay
        .stored_bytes(&ack.key)?
        .ok_or("production relay lost an acknowledged row")?;
    drop(relay);

    // Models loss of the first ACK: exact persisted bytes are submitted after
    // process restart and produce the byte-identical receipt.
    let mut relay = ProductionRelayV1::open(&relay_root, relay_config)?;
    let replayed = relay.submit(&exact)?;
    assert_eq!(ack.canonical_bytes(), replayed.canonical_bytes());

    let inbox_root = temporary.path().join("inbox");
    let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters())?;
    let ingest = inbox.ingest(&mut relay, &rosters(), now())?;
    assert_eq!((ingest.accepted, ingest.refused.len()), (1, 0));
    assert_eq!(relay.len()?, 0, "Relay GC follows the durable inbox commit");
    let empty = inbox.ingest(&mut relay, &rosters(), now())?;
    assert_eq!((empty.accepted, empty.duplicates), (0, 0));
    let mut contracts = RestartSafeContractsPort::default();
    assert_eq!(inbox.dispatch_routes(&mut contracts)?.applied, 1);
    assert_eq!(contracts.payloads, vec![b"production-dsc1".to_vec()]);
    Ok(())
}

#[test]
fn real_contracts_store_commit_is_redelivered_as_duplicate_after_both_restarts(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let (store, signed_dsc1) = create_contracts_store(&temporary)?;

    let mut relay = RelayV1::new();
    sender()?.send(&mut relay, signed_dsc1, expiry(), [5; 32])?;
    let inbox_root = temporary.path().join("inbox");
    let mut inbox = DurableRelayInboxV1::create(&inbox_root, config()?, &rosters())?;
    assert_eq!(
        inbox
            .ingest_ephemeral_v1(&relay, &rosters(), now())?
            .accepted,
        1
    );

    let mut port = RealContractsStorePort {
        store,
        lose_next_receipt: true,
    };
    // The narrow fixture authority already committed the message + successor;
    // the derived production port recognizes that durable redelivery, but the
    // worker dies before the inbox can persist its delivery receipt.
    let lost = inbox.dispatch_routes(&mut port);
    assert!(lost.is_err(), "the injected receipt loss must surface");
    assert_eq!(port.store.load_session(SESSION)?.revision(), 1);
    assert_eq!(inbox.stats()?.pending_route, 1);
    drop(port);
    drop(inbox);

    // Both authorities reopen from disk.  Exact redelivery reaches the real
    // Store, which returns its durable duplicate receipt; only then does the
    // inbox clear the pending row.
    let store = reopen_contracts_store(&temporary)?;
    let mut port = RealContractsStorePort {
        store,
        lose_next_receipt: false,
    };
    let mut inbox = DurableRelayInboxV1::open(&inbox_root, config()?, &rosters())?;
    let report = inbox.dispatch_routes(&mut port)?;
    assert_eq!((report.applied, report.duplicate_commits), (1, 1));
    assert_eq!(port.store.load_session(SESSION)?.revision(), 1);
    assert_eq!(
        (inbox.stats()?.pending_route, inbox.stats()?.delivered),
        (0, 1)
    );
    Ok(())
}

#[test]
fn retained_inbox_lock_prevents_two_transcript_owners() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("inbox");
    let first = DurableRelayInboxV1::create(&root, config()?, &rosters())?;
    assert!(matches!(
        DurableRelayInboxV1::open(&root, config()?, &rosters()),
        Err(DurableInboxError::StorageUnavailable)
    ));
    drop(first);
    let reopened = DurableRelayInboxV1::open(&root, config()?, &rosters())?;
    assert_eq!(reopened.stats()?.pending_route, 0);
    Ok(())
}

#[test]
fn truncating_even_the_last_inbox_row_is_detected_on_reopen() -> Result<(), Box<dyn Error>> {
    let mut relay = RelayV1::new();
    sender()?.send(&mut relay, b"retained".to_vec(), expiry(), [6; 32])?;
    let temporary = secure_tempdir()?;
    let root = temporary.path().join("inbox");
    let mut inbox = DurableRelayInboxV1::create(&root, config()?, &rosters())?;
    assert_eq!(
        inbox
            .ingest_ephemeral_v1(&relay, &rosters(), now())?
            .accepted,
        1
    );
    drop(inbox);

    let connection = rusqlite::Connection::open(root.join("route-inbox-v1.sqlite3"))?;
    connection.execute("DELETE FROM inbox_entries WHERE ordinal = 1", [])?;
    drop(connection);
    assert!(matches!(
        DurableRelayInboxV1::open(&root, config()?, &rosters()),
        Err(DurableInboxError::CorruptState)
    ));
    Ok(())
}

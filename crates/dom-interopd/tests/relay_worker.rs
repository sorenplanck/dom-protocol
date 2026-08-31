//! Production Relay worker adversarial integration tests.

#![cfg(all(feature = "production", target_os = "linux"))]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use btc_crypto::SecpContext;
use cap_std::fs::Dir;
use dom_adaptor::{
    aggregate_public_nonces_v1, aggregate_shared_commitment_v1, binding_factor_v1,
    canonical_template_v1, contribute_blinding_share_v1, nonce_commitment_hash_v1,
    prove_share_knowledge_v1, AdaptorPreSignatureV1, AggregateBpRound1, AggregateBpRound2,
    BindingContextV1, BpRound2ShareV1, BpStatementV1, CollaborativeRangeProof, ContractKindV1,
    DomCollaborativeRangeProofV1, EarlyShareCommitmentV1, EarlyShareRevealV1, EarlyTermsBindingV1,
    EarlyTermsMessageKindV1, NonceCommitmentV1, NonceRevealV1, PartialSignatureV1,
    ParticipantIdentityV1, ParticipantPublicNoncesV1, ParticipantRosterV1, PendingCommonNonce,
    PendingSharedBlindingBindingV1, PurposeV1, RangeProof739, ScriptlessTransactionTemplateV1,
    SharePoPStatementV1, SharedBlindingBindingV1, SigningShareV1, TrustedChainIdV1,
    VerifiedSharedOutputV1,
};
use dom_consensus::{Transaction, TransactionInput, TransactionKernel, TransactionOutput};
use dom_core::{Amount, Hash256, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
use dom_crypto::{
    blake2b_256, hash::blake2b_256_tagged, pedersen::BlindingFactor, pedersen::Commitment,
    recovery::RecoveryCapsule, schnorr_challenge, schnorr_sign, PartialSig, PublicKey, SecretKey,
};
use dom_interopd::{
    ContractsRelayIngressErrorV1, DurableRelayWorkerV1, PreparedContractsIngressV1,
    PreparedRelayOutboundV1, RelayF6MessageKindV1, RelayOutboundStepV1, RelayWorkerConfigV1,
    RelayWorkerInboundErrorV1, RelayWorkerOpenErrorV1, RelayWorkerOutboundErrorV1,
    RelayWorkerPathsV1,
};
use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};
use dom_scriptless_store::{
    BudgetPolicyProfileV1, BudgetPolicyV1, CommittedOutboundDsc1V1, ContractsSessionStoreV1,
    DirectionV1, DurableTransportOutcomeV1, OutboundDsc1RecoveryV1, SessionChainProjectionV1,
    SessionIrreversibleV1, SessionPhaseV1, SessionRecordFieldsV1, SessionRecordV1,
    SessionStoreError, SessionTransportIdentityReferenceV1, SessionTransportParticipantV1,
    SessionTxObservationV1, BUDGET_POLICY_LEN,
};
use dom_scriptless_transport::{AbortPayloadV1, MessageTypeV1, SignedMessageV1, UnsignedMessageV1};
use k256::{elliptic_curve::PrimeField, Scalar};
use kaystra_core::types::Digest32;
use relay::auth::{message_type, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
use relay::server::AckV1;
use relay::{ParticipantId, SenderRoleV1, TimelockSpec};
use route_transport::{
    BridgeRefusal, DurableFrameReassemblerConfigV2, DurableFrameReassemblerV2,
    DurableInboxConfigV1, DurablePayloadCommitV1, DurablePayloadDispositionV1, DurableRelayInboxV1,
    DurableRelaySenderConfigV1, DurableRelaySenderErrorV1, DurableRelaySenderV1,
    F6PayloadDeliveryV1, F6TransportPortV1, FramedContractsTransportErrorV2, RelayQueueV1,
    RouteApplicationDispositionV2, RouteDispatchErrorV1, RouteWireContextV1,
    MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES,
};

const NETWORK: Digest32 = [0x21; 32];
const SESSION: Digest32 = [0x31; 32];
const ROUTE: Digest32 = [0x41; 32];
const SNAPSHOT: Digest32 = [0x51; 32];
const INITIATOR: ParticipantId = ParticipantId([0xa1; 32]);
const RESPONDER: ParticipantId = ParticipantId([0xb2; 32]);
const INITIATOR_RELAY_SECRET: [u8; 32] = [0x71; 32];
const RESPONDER_RELAY_SECRET: [u8; 32] = [0x72; 32];

#[derive(Clone, Copy)]
struct TestRelayParticipants {
    initiator: ParticipantId,
    responder: ParticipantId,
}

const DEFAULT_RELAY_PARTICIPANTS: TestRelayParticipants = TestRelayParticipants {
    initiator: INITIATOR,
    responder: RESPONDER,
};

struct OperationalBpFixture {
    statement: BpStatementV1,
    messages: Vec<Vec<u8>>,
}

fn wire() -> RouteWireContextV1 {
    RouteWireContextV1 {
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        roster_snapshot: SNAPSHOT,
        policy_version: 1,
    }
}

fn expiry() -> TimelockSpec {
    TimelockSpec::BlockHeight { value: 10_000 }
}

fn now() -> TimelockSpec {
    TimelockSpec::BlockHeight { value: 100 }
}

fn xonly(secret: &[u8; 32]) -> [u8; 32] {
    SecpContext::new(&[0x19; 32])
        .sign_bip340(secret, &[0; 32], &[0; 32])
        .expect("public test relay secret")
        .1
}

fn rosters_for(participants: TestRelayParticipants) -> RosterRegistryV1 {
    RosterRegistryV1::new().with_snapshot(
        SNAPSHOT,
        RosterSnapshotV1::new()
            .with_member(
                participants.initiator,
                RosterMemberV1 {
                    xonly_key: xonly(&INITIATOR_RELAY_SECRET),
                    role: SenderRoleV1::Initiator,
                },
            )
            .with_member(
                participants.responder,
                RosterMemberV1 {
                    xonly_key: xonly(&RESPONDER_RELAY_SECRET),
                    role: SenderRoleV1::Solver,
                },
            ),
    )
}

fn rosters() -> RosterRegistryV1 {
    rosters_for(DEFAULT_RELAY_PARTICIPANTS)
}

fn sender_config_for(
    local_initiator: bool,
    participants: TestRelayParticipants,
) -> DurableRelaySenderConfigV1 {
    let (local, remote, role, secret, discriminator) = if local_initiator {
        (
            participants.initiator,
            participants.responder,
            SenderRoleV1::Initiator,
            INITIATOR_RELAY_SECRET,
            0xa0,
        )
    } else {
        (
            participants.responder,
            participants.initiator,
            SenderRoleV1::Solver,
            RESPONDER_RELAY_SECRET,
            0xb0,
        )
    };
    DurableRelaySenderConfigV1::new(
        [discriminator + 1; 32],
        wire(),
        local,
        remote,
        role,
        xonly(&secret),
        128,
    )
    .expect("valid sender config")
}

fn worker_config_for(
    local_initiator: bool,
    participants: TestRelayParticipants,
) -> RelayWorkerConfigV1 {
    let discriminator = if local_initiator { 0xa0 } else { 0xb0 };
    let local = if local_initiator {
        participants.initiator
    } else {
        participants.responder
    };
    let sender = sender_config_for(local_initiator, participants);
    let inbox = DurableInboxConfigV1::new([discriminator + 2; 32], wire(), local, 128)
        .expect("valid inbox config");
    let frames = DurableFrameReassemblerConfigV2::new(
        [discriminator + 3; 32],
        wire(),
        local,
        16,
        2 * 1024 * 1024,
        128,
    )
    .expect("valid frame config");
    RelayWorkerConfigV1::new(sender, inbox, frames).expect("cross-bound worker config")
}

fn worker_config(local_initiator: bool) -> RelayWorkerConfigV1 {
    worker_config_for(local_initiator, DEFAULT_RELAY_PARTICIPANTS)
}

fn worker_paths(root: &Path, local_initiator: bool) -> RelayWorkerPathsV1 {
    let prefix = if local_initiator { "alice" } else { "bob" };
    RelayWorkerPathsV1::new(
        root.join(format!("{prefix}-sender")),
        root.join(format!("{prefix}-inbox")),
        root.join(format!("{prefix}-frames")),
    )
}

fn secure_tempdir() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let directory = tempfile::Builder::new()
        .prefix("dom-relay-worker-")
        .tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn parent_capability(path: &Path) -> Result<Arc<Dir>, Box<dyn Error>> {
    Ok(Arc::new(Dir::from_std_file(File::open(path)?)))
}

fn production_policy() -> Result<BudgetPolicyV1, Box<dyn Error>> {
    let mut bytes = [0; BUDGET_POLICY_LEN];
    bytes[..8].copy_from_slice(b"DOMNVBP1");
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
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

fn initial_record() -> Result<SessionRecordV1, Box<dyn Error>> {
    Ok(SessionRecordV1::new(
        SessionRecordFieldsV1 {
            session_id: SESSION,
            revision: 0,
            phase: SessionPhaseV1::Created,
            terms_hash: [0x32; 32],
            transcript_hash: [0x33; 32],
            irreversible: SessionIrreversibleV1 {
                any_signing_share_sent: true,
                funding_authorized: false,
                adaptor_secret_exposed: false,
                nonce_epoch: 7,
            },
            chain: SessionChainProjectionV1 {
                tip_id: [0x34; 32],
                tip_height: 100,
                funding: SessionTxObservationV1::Unknown,
                claim: SessionTxObservationV1::Unknown,
                refund: SessionTxObservationV1::Unknown,
            },
        },
        b"sealed-relay-worker-test",
    )?)
}

struct EarlyFixture {
    trusted_chain: TrustedChainIdV1,
    recovery_capsule: RecoveryCapsule,
    identity_keys: [SecretKey; 2],
    participant_ids: [[u8; 32]; 2],
    directions: [DirectionV1; 2],
    signing_shares: [SigningShareV1; 2],
    signing_share_bytes: [[u8; 32]; 2],
    shared_bindings: [SharedBlindingBindingV1; 2],
}

impl EarlyFixture {
    fn new(initial: &SessionRecordV1) -> Result<Self, Box<dyn Error>> {
        let trusted_chain = TrustedChainIdV1::from_authenticated_genesis(
            0x4455_6677,
            &Hash256::from_bytes([0x91; 32]),
        );
        let participant_ids = [INITIATOR.0, RESPONDER.0];
        let directions = [DirectionV1::Initiator, DirectionV1::Responder];
        let identity_keys = [
            SecretKey::from_bytes(&[0x11; 32])?,
            SecretKey::from_bytes(&[0x12; 32])?,
        ];
        let mut share_a = [0; 32];
        share_a[31] = 7;
        let mut share_b = [0; 32];
        share_b[31] = 9;
        let signing_shares = [
            SigningShareV1::from_be_bytes(share_a)?,
            SigningShareV1::from_be_bytes(share_b)?,
        ];
        let mut capsule_bytes = [0; 96];
        capsule_bytes[..2].copy_from_slice(&1_u16.to_le_bytes());
        capsule_bytes[14..16].copy_from_slice(&80_u16.to_le_bytes());
        let recovery_capsule = RecoveryCapsule::from_bytes(&capsule_bytes)?;
        let pending_a = PendingSharedBlindingBindingV1::new(
            &trusted_chain,
            initial.session_id(),
            &participant_ids,
            directions[0],
            0,
            initial.terms_hash(),
            signing_shares[0].public_key().clone(),
        )?;
        let pending_b = PendingSharedBlindingBindingV1::new(
            &trusted_chain,
            initial.session_id(),
            &participant_ids,
            directions[1],
            1,
            initial.terms_hash(),
            signing_shares[1].public_key().clone(),
        )?;
        let shared_bindings = [
            SharedBlindingBindingV1::bind_recovery_capsule(&pending_a, &recovery_capsule),
            SharedBlindingBindingV1::bind_recovery_capsule(&pending_b, &recovery_capsule),
        ];
        Ok(Self {
            trusted_chain,
            recovery_capsule,
            identity_keys,
            participant_ids,
            directions,
            signing_shares,
            signing_share_bytes: [share_a, share_b],
            shared_bindings,
        })
    }

    fn new_responder_first_signing_compatible(
        initial: &SessionRecordV1,
    ) -> Result<Self, Box<dyn Error>> {
        let trusted_chain = TrustedChainIdV1::from_authenticated_genesis(
            0x4455_6677,
            &Hash256::from_bytes([0x91; 32]),
        );
        let mut identity_keys = [
            SecretKey::from_bytes(&[0x11; 32])?,
            SecretKey::from_bytes(&[0x12; 32])?,
        ];
        let mut share_a = [0; 32];
        share_a[31] = 7;
        let mut share_b = [0; 32];
        share_b[31] = 9;
        let mut signing_share_bytes = [share_a, share_b];
        let mut signing_shares = [
            SigningShareV1::from_be_bytes(share_a)?,
            SigningShareV1::from_be_bytes(share_b)?,
        ];
        let first = ParticipantIdentityV1::new(
            &trusted_chain,
            identity_keys[0].public_key(),
            signing_shares[0].public_key().clone(),
            DirectionV1::Initiator,
        )?;
        let second = ParticipantIdentityV1::new(
            &trusted_chain,
            identity_keys[1].public_key(),
            signing_shares[1].public_key().clone(),
            DirectionV1::Responder,
        )?;
        if first.participant_id() > second.participant_id() {
            identity_keys.swap(0, 1);
            signing_shares.swap(0, 1);
            signing_share_bytes.swap(0, 1);
        }
        let directions = [DirectionV1::Responder, DirectionV1::Initiator];
        let participants = [
            ParticipantIdentityV1::new(
                &trusted_chain,
                identity_keys[0].public_key(),
                signing_shares[0].public_key().clone(),
                directions[0],
            )?,
            ParticipantIdentityV1::new(
                &trusted_chain,
                identity_keys[1].public_key(),
                signing_shares[1].public_key().clone(),
                directions[1],
            )?,
        ];
        let participant_ids = [
            *participants[0].participant_id(),
            *participants[1].participant_id(),
        ];
        let mut capsule_bytes = [0; 96];
        capsule_bytes[..2].copy_from_slice(&1_u16.to_le_bytes());
        capsule_bytes[14..16].copy_from_slice(&80_u16.to_le_bytes());
        let recovery_capsule = RecoveryCapsule::from_bytes(&capsule_bytes)?;
        let pending_a = PendingSharedBlindingBindingV1::new(
            &trusted_chain,
            initial.session_id(),
            &participant_ids,
            directions[0],
            0,
            initial.terms_hash(),
            signing_shares[0].public_key().clone(),
        )?;
        let pending_b = PendingSharedBlindingBindingV1::new(
            &trusted_chain,
            initial.session_id(),
            &participant_ids,
            directions[1],
            1,
            initial.terms_hash(),
            signing_shares[1].public_key().clone(),
        )?;
        let shared_bindings = [
            SharedBlindingBindingV1::bind_recovery_capsule(&pending_a, &recovery_capsule),
            SharedBlindingBindingV1::bind_recovery_capsule(&pending_b, &recovery_capsule),
        ];
        Ok(Self {
            trusted_chain,
            recovery_capsule,
            identity_keys,
            participant_ids,
            directions,
            signing_shares,
            signing_share_bytes,
            shared_bindings,
        })
    }

    fn index_for_direction(&self, direction: DirectionV1) -> Result<usize, Box<dyn Error>> {
        self.directions
            .iter()
            .position(|candidate| *candidate == direction)
            .ok_or_else(|| {
                Box::<dyn Error>::from(dom_scriptless_store::SessionStoreError::Canonical)
            })
    }

    fn relay_participants(&self) -> Result<TestRelayParticipants, Box<dyn Error>> {
        let initiator = self.index_for_direction(DirectionV1::Initiator)?;
        let responder = self.index_for_direction(DirectionV1::Responder)?;
        Ok(TestRelayParticipants {
            initiator: ParticipantId(self.participant_ids[initiator]),
            responder: ParticipantId(self.participant_ids[responder]),
        })
    }

    fn canonical_reveal(
        &self,
        initial: &SessionRecordV1,
        context_commitment: [u8; 32],
        index: usize,
    ) -> Result<EarlyShareRevealV1, Box<dyn Error>> {
        let direction = *self.directions.get(index).ok_or_else(|| {
            Box::<dyn Error>::from(dom_scriptless_store::SessionStoreError::Canonical)
        })?;
        let statement = SharePoPStatementV1::new(
            &self.trusted_chain,
            initial.session_id(),
            &self.participant_ids,
            direction,
            u16::try_from(index)?,
            self.signing_shares[index].public_key().clone(),
            initial.terms_hash(),
            *self.shared_bindings[index].capsule_hash(),
        )?;
        let proof = prove_share_knowledge_v1(&statement, &self.signing_shares[index])?;
        Ok(EarlyShareRevealV1::new(
            context_commitment,
            statement,
            proof,
        )?)
    }
}

fn create_contracts_store(
    root: &Path,
    name: &str,
    fixture: &EarlyFixture,
) -> Result<ContractsSessionStoreV1, Box<dyn Error>> {
    let store = ContractsSessionStoreV1::create_production(
        parent_capability(root)?,
        name,
        production_policy()?,
    )?;
    let initial = initial_record()?;
    let initiator = fixture.index_for_direction(DirectionV1::Initiator)?;
    let responder = fixture.index_for_direction(DirectionV1::Responder)?;
    store.create_session(&initial)?;
    store.bind_transport_roster(
        SESSION,
        *fixture.trusted_chain.as_bytes(),
        [
            SessionTransportParticipantV1::new(
                fixture.participant_ids[initiator],
                fixture.identity_keys[initiator].public_key(),
                DirectionV1::Initiator,
            )?,
            SessionTransportParticipantV1::new(
                fixture.participant_ids[responder],
                fixture.identity_keys[responder].public_key(),
                DirectionV1::Responder,
            )?,
        ],
    )?;
    store.bind_transport_identity_references(
        SESSION,
        [
            SessionTransportIdentityReferenceV1::new(
                fixture.participant_ids[initiator],
                [0x61; 32],
                [0x71; 32],
                fixture.identity_keys[initiator].public_key(),
            )?,
            SessionTransportIdentityReferenceV1::new(
                fixture.participant_ids[responder],
                [0x62; 32],
                [0x72; 32],
                fixture.identity_keys[responder].public_key(),
            )?,
        ],
    )?;
    Ok(store)
}

fn open_contracts_store(
    root: &Path,
    name: &str,
) -> Result<ContractsSessionStoreV1, Box<dyn Error>> {
    Ok(ContractsSessionStoreV1::open_production(
        parent_capability(root)?,
        name,
        production_policy()?,
    )?)
}

#[derive(Debug, thiserror::Error)]
#[error("test F6 authority refused")]
struct TestF6Error;

#[derive(Default)]
struct TestF6Authority {
    receipts: BTreeSet<Digest32>,
    kinds: Vec<u16>,
}

impl F6TransportPortV1 for TestF6Authority {
    type Error = TestF6Error;

    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let receipt = *delivery.envelope_digest();
        let duplicate = !self.receipts.insert(receipt);
        self.kinds.push(delivery.message_type());
        Ok(
            DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, receipt, duplicate)
                .expect("nonzero envelope digest"),
        )
    }
}

type TestWorker = DurableRelayWorkerV1<TestF6Authority>;

fn create_worker(
    root: &Path,
    local_initiator: bool,
    store: ContractsSessionStoreV1,
) -> Result<TestWorker, Box<dyn Error>> {
    create_worker_for(root, local_initiator, store, DEFAULT_RELAY_PARTICIPANTS)
}

fn create_worker_for(
    root: &Path,
    local_initiator: bool,
    store: ContractsSessionStoreV1,
    participants: TestRelayParticipants,
) -> Result<TestWorker, Box<dyn Error>> {
    let secret = if local_initiator {
        INITIATOR_RELAY_SECRET
    } else {
        RESPONDER_RELAY_SECRET
    };
    Ok(DurableRelayWorkerV1::create(
        &worker_paths(root, local_initiator),
        worker_config_for(local_initiator, participants),
        Rc::new(store),
        rosters_for(participants),
        TestF6Authority::default(),
        secret,
    )?)
}

fn open_worker(
    root: &Path,
    local_initiator: bool,
    store: ContractsSessionStoreV1,
) -> Result<TestWorker, Box<dyn Error>> {
    open_worker_for(root, local_initiator, store, DEFAULT_RELAY_PARTICIPANTS)
}

fn open_worker_for(
    root: &Path,
    local_initiator: bool,
    store: ContractsSessionStoreV1,
    participants: TestRelayParticipants,
) -> Result<TestWorker, Box<dyn Error>> {
    let secret = if local_initiator {
        INITIATOR_RELAY_SECRET
    } else {
        RESPONDER_RELAY_SECRET
    };
    Ok(DurableRelayWorkerV1::open_existing(
        &worker_paths(root, local_initiator),
        worker_config_for(local_initiator, participants),
        Rc::new(store),
        rosters_for(participants),
        TestF6Authority::default(),
        secret,
    )?)
}

#[test]
fn production_resume_completes_each_relay_authority_boundary_and_reopens(
) -> Result<(), Box<dyn Error>> {
    for completed in 0_u8..=3 {
        let temporary = secure_tempdir()?;
        let initial = initial_record()?;
        let fixture = EarlyFixture::new(&initial)?;
        let store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
        let paths = worker_paths(temporary.path(), true);
        let sender = sender_config_for(true, DEFAULT_RELAY_PARTICIPANTS);
        let inbox = DurableInboxConfigV1::new([0xa2; 32], wire(), INITIATOR, 128)?;
        let frames = DurableFrameReassemblerConfigV2::new(
            [0xa3; 32],
            wire(),
            INITIATOR,
            16,
            2 * 1024 * 1024,
            128,
        )?;
        if completed >= 1 {
            drop(DurableRelaySenderV1::create(
                paths.sender_root(),
                sender,
                INITIATOR_RELAY_SECRET,
                [0xc1; 32],
            )?);
        }
        if completed >= 2 {
            drop(DurableRelayInboxV1::create(
                paths.inbox_root(),
                inbox,
                &rosters(),
            )?);
        }
        if completed >= 3 {
            drop(DurableFrameReassemblerV2::create(
                paths.frame_reassembly_root(),
                frames,
            )?);
        }
        let worker = DurableRelayWorkerV1::resume_create_production(
            &paths,
            RelayWorkerConfigV1::new(sender, inbox, frames)?,
            Rc::new(store),
            rosters(),
            TestF6Authority::default(),
            INITIATOR_RELAY_SECRET,
        )?;
        assert_eq!(worker.sender_stats()?.completed, 0);
        assert_eq!(worker.inbox_stats()?, Default::default());
        assert_eq!(worker.frame_stats()?, Default::default());
        drop(worker);
        let store = open_contracts_store(temporary.path(), "contracts-a")?;
        drop(open_worker(temporary.path(), true, store)?);
    }
    Ok(())
}

#[test]
fn production_resume_refuses_non_pristine_sender_before_creating_later_authorities(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let paths = worker_paths(temporary.path(), true);
    let sender_config = sender_config_for(true, DEFAULT_RELAY_PARTICIPANTS);
    let mut sender = DurableRelaySenderV1::create(
        paths.sender_root(),
        sender_config,
        INITIATOR_RELAY_SECRET,
        [0xc2; 32],
    )?;
    sender.prepare_message(message_type::RFQ, b"economic", expiry(), [0xc3; 32])?;
    drop(sender);
    assert!(matches!(
        DurableRelayWorkerV1::resume_create_production(
            &paths,
            worker_config(true),
            Rc::new(store),
            rosters(),
            TestF6Authority::default(),
            INITIATOR_RELAY_SECRET,
        ),
        Err(RelayWorkerOpenErrorV1::Sender(
            DurableRelaySenderErrorV1::UnsupportedFormat
        ))
    ));
    assert!(!paths.inbox_root().exists());
    assert!(!paths.frame_reassembly_root().exists());
    Ok(())
}

#[test]
fn production_resume_preflights_malformed_authority_topology_without_mutation(
) -> Result<(), Box<dyn Error>> {
    for frame_only in [false, true] {
        let temporary = secure_tempdir()?;
        let initial = initial_record()?;
        let fixture = EarlyFixture::new(&initial)?;
        let store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
        let paths = worker_paths(temporary.path(), true);
        if frame_only {
            let frames = DurableFrameReassemblerConfigV2::new(
                [0xa3; 32],
                wire(),
                INITIATOR,
                16,
                2 * 1024 * 1024,
                128,
            )?;
            drop(DurableFrameReassemblerV2::create(
                paths.frame_reassembly_root(),
                frames,
            )?);
        } else {
            let inbox = DurableInboxConfigV1::new([0xa2; 32], wire(), INITIATOR, 128)?;
            drop(DurableRelayInboxV1::create(
                paths.inbox_root(),
                inbox,
                &rosters(),
            )?);
        }
        assert!(matches!(
            DurableRelayWorkerV1::resume_create_production(
                &paths,
                worker_config(true),
                Rc::new(store),
                rosters(),
                TestF6Authority::default(),
                INITIATOR_RELAY_SECRET,
            ),
            Err(RelayWorkerOpenErrorV1::InvalidConfiguration)
        ));
        assert!(!paths.sender_root().exists());
        if frame_only {
            assert!(!paths.inbox_root().exists());
        }
    }
    Ok(())
}

/// Evidence-only producer for inbound worker tests.
///
/// These tests deliberately synthesize peer traffic for every ingress phase;
/// this helper is not linked into `dom-interopd` and therefore cannot restore
/// the removed caller-shaped worker surface.
struct TestPeerOutbound {
    sender: DurableRelaySenderV1,
}

impl TestPeerOutbound {
    fn create(
        root: &Path,
        local_initiator: bool,
        unused_store: ContractsSessionStoreV1,
    ) -> Result<Self, Box<dyn Error>> {
        Self::create_for(
            root,
            local_initiator,
            unused_store,
            DEFAULT_RELAY_PARTICIPANTS,
        )
    }

    fn create_for(
        root: &Path,
        local_initiator: bool,
        _unused_store: ContractsSessionStoreV1,
        participants: TestRelayParticipants,
    ) -> Result<Self, Box<dyn Error>> {
        let signing_secret = if local_initiator {
            INITIATOR_RELAY_SECRET
        } else {
            RESPONDER_RELAY_SECRET
        };
        Ok(Self {
            sender: DurableRelaySenderV1::create(
                worker_paths(root, local_initiator).sender_root(),
                sender_config_for(local_initiator, participants),
                signing_secret,
                [0xc1; 32],
            )?,
        })
    }

    fn open_existing(
        root: &Path,
        local_initiator: bool,
        unused_store: ContractsSessionStoreV1,
    ) -> Result<Self, Box<dyn Error>> {
        Self::open_existing_for(
            root,
            local_initiator,
            unused_store,
            DEFAULT_RELAY_PARTICIPANTS,
        )
    }

    fn open_existing_for(
        root: &Path,
        local_initiator: bool,
        _unused_store: ContractsSessionStoreV1,
        participants: TestRelayParticipants,
    ) -> Result<Self, Box<dyn Error>> {
        let signing_secret = if local_initiator {
            INITIATOR_RELAY_SECRET
        } else {
            RESPONDER_RELAY_SECRET
        };
        Ok(Self {
            sender: DurableRelaySenderV1::open_existing(
                worker_paths(root, local_initiator).sender_root(),
                sender_config_for(local_initiator, participants),
                signing_secret,
                [0xc2; 32],
            )?,
        })
    }

    fn prepare_f6(
        &mut self,
        kind: RelayF6MessageKindV1,
        payload: &[u8],
        expiry: TimelockSpec,
    ) -> Result<PreparedRelayOutboundV1, RelayWorkerOutboundErrorV1> {
        let message_type = match kind {
            RelayF6MessageKindV1::Rfq => message_type::RFQ,
            RelayF6MessageKindV1::Quote => message_type::QUOTE,
            RelayF6MessageKindV1::Acceptance => message_type::ACCEPTANCE,
            RelayF6MessageKindV1::Selection => message_type::SELECTION,
        };
        let pending = self
            .sender
            .prepare_message(message_type, payload, expiry, [0xc3; 32])?;
        Ok(test_prepared_report(&pending))
    }

    fn prepare_signed_dsc1(
        &mut self,
        signed_dsc1: &[u8],
        expiry: TimelockSpec,
    ) -> Result<PreparedRelayOutboundV1, RelayWorkerOutboundErrorV1> {
        let pending = if signed_dsc1.len() <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES {
            self.sender.prepare_message(
                message_type::ROUTE_TRANSPORT,
                signed_dsc1,
                expiry,
                [0xc4; 32],
            )?
        } else {
            self.sender
                .begin_framed_route(signed_dsc1, expiry, [0xc4; 32])?
        };
        Ok(test_prepared_report(&pending))
    }

    fn submit_outbound_once<Q: RelayQueueV1>(
        &mut self,
        queue: &mut Q,
    ) -> Result<RelayOutboundStepV1, RelayWorkerOutboundErrorV1> {
        if self.sender.pending_envelope()?.is_none() {
            if self.sender.frame_transfer_status()?.is_none() {
                return Ok(RelayOutboundStepV1::Idle);
            }
            self.sender.prepare_next_frame([0xc5; 32])?;
        }
        let committed = self.sender.submit_pending(queue)?;
        Ok(RelayOutboundStepV1::Acked {
            message_type: committed.message_type(),
            frame_index: committed.frame_index(),
            next_sequence: committed.checkpoint().next_sequence(),
            envelope_digest: committed.ack().digest,
        })
    }

    fn sender_stats(
        &self,
    ) -> Result<
        route_transport::DurableRelaySenderStatsV1,
        route_transport::DurableRelaySenderErrorV1,
    > {
        self.sender.stats()
    }
}

fn test_prepared_report(
    pending: &route_transport::DurableOutboundEnvelopeV1,
) -> PreparedRelayOutboundV1 {
    PreparedRelayOutboundV1 {
        message_type: pending.message_type(),
        sequence: pending.sequence(),
        envelope_digest: *pending.envelope_digest(),
        frame_index: pending.frame_index(),
        frame_count: pending.frame_count(),
    }
}

fn issue_early_authority(
    store: &ContractsSessionStoreV1,
    fixture: &EarlyFixture,
) -> Result<dom_scriptless_store::PreparedEarlyTransportAuthorityV1, Box<dyn Error>> {
    Ok(store.prepare_early_transport_authority(
        fixture.trusted_chain,
        [&fixture.shared_bindings[0], &fixture.shared_bindings[1]],
    )?)
}

fn complete_early_transport(
    store: &ContractsSessionStoreV1,
    initial: &SessionRecordV1,
    fixture: &EarlyFixture,
) -> Result<SessionRecordV1, Box<dyn Error>> {
    let authority = issue_early_authority(store, fixture)?;
    let reveals = [
        fixture.canonical_reveal(initial, *authority.context_commitment(), 0)?,
        fixture.canonical_reveal(initial, *authority.context_commitment(), 1)?,
    ];
    let commitments = [
        EarlyShareCommitmentV1::new(&reveals[0]),
        EarlyShareCommitmentV1::new(&reveals[1]),
    ];
    let initiator = fixture.index_for_direction(DirectionV1::Initiator)?;
    let responder = fixture.index_for_direction(DirectionV1::Responder)?;
    let payloads = [
        authority.offer_payload()?.to_vec(),
        authority.accept_payload()?.to_vec(),
        commitments[initiator].to_bytes().to_vec(),
        commitments[responder].to_bytes().to_vec(),
        reveals[initiator].to_bytes().to_vec(),
        reveals[responder].to_bytes().to_vec(),
    ];
    let positions = [
        (MessageTypeV1::Offer, initiator, 0_u64),
        (MessageTypeV1::Accept, responder, 0),
        (MessageTypeV1::ShareCommit, initiator, 1),
        (MessageTypeV1::ShareCommit, responder, 1),
        (MessageTypeV1::ShareReveal, initiator, 2),
        (MessageTypeV1::ShareReveal, responder, 2),
    ];
    let mut current = initial.clone();
    for ((kind, participant, sequence), payload) in positions.into_iter().zip(payloads) {
        let signed = signed_inner(
            fixture,
            kind,
            participant,
            sequence,
            current.transcript_hash(),
            payload,
        )?;
        match store.accept_prepared_early_transport_message(&authority, &signed)? {
            DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate => {}
            _ => {
                return Err(Box::new(
                    dom_scriptless_store::SessionStoreError::Quarantined,
                ))
            }
        }
        current = store.load_session(SESSION)?;
    }
    Ok(current)
}

fn operational_bp_fixture(fixture: &EarlyFixture) -> Result<OperationalBpFixture, Box<dyn Error>> {
    let commitment_shares = fixture
        .signing_shares
        .iter()
        .map(|share| share.public_key().clone())
        .collect::<Vec<_>>();
    let aggregate = BpStatementV1::aggregate_commitment_from_shares(&commitment_shares, 42)?;
    let statement = BpStatementV1::new(
        &fixture.trusted_chain,
        SESSION,
        fixture.participant_ids.to_vec(),
        42,
        commitment_shares,
        aggregate,
        Some(*blake2b_256(fixture.recovery_capsule.as_bytes()).as_bytes()),
    )?;
    let driver_a = DomCollaborativeRangeProofV1::new(
        &statement,
        fixture.recovery_capsule.as_bytes().to_vec(),
    )?;
    let driver_b = DomCollaborativeRangeProofV1::new(
        &statement,
        fixture.recovery_capsule.as_bytes().to_vec(),
    )?;
    let (pending_a, common_commit_a) =
        PendingCommonNonce::new(&statement, 0, &fixture.signing_shares[0])?;
    let (pending_b, common_commit_b) =
        PendingCommonNonce::new(&statement, 1, &fixture.signing_shares[1])?;
    let common_reveal_a = pending_a.reveal_bytes();
    let common_reveal_b = pending_b.reveal_bytes();
    let accepted_common = [common_commit_a, common_commit_b];
    let local_a = pending_a.finish(
        &statement,
        &accepted_common,
        vec![common_reveal_a.clone(), common_reveal_b.clone()],
    )?;
    let local_b = pending_b.finish(
        &statement,
        &accepted_common,
        vec![common_reveal_a.clone(), common_reveal_b.clone()],
    )?;
    let round1_a = driver_a.round1(&statement, &local_a)?;
    let round1_b = driver_b.round1(&statement, &local_b)?;
    let round1_commit_a = round1_a.reveal_commitment();
    let round1_commit_b = round1_b.reveal_commitment();
    let aggregate_round1 = AggregateBpRound1::new(
        &statement,
        &[round1_commit_a, round1_commit_b],
        &[round1_a.clone(), round1_b.clone()],
    )?;
    let round2_a = driver_a
        .round2(&statement, &local_a, &aggregate_round1)?
        .into_zeroizing_bytes();
    let round2_b = driver_b
        .round2(&statement, &local_b, &aggregate_round1)?
        .into_zeroizing_bytes();
    let aggregate_round2 = AggregateBpRound2::new(
        &statement,
        vec![
            BpRound2ShareV1::from_bytes(round2_a.as_ref(), &statement)?,
            BpRound2ShareV1::from_bytes(round2_b.as_ref(), &statement)?,
        ],
    )?;
    let proof = driver_b.finalize(&statement, &aggregate_round1, &aggregate_round2)?;
    Ok(OperationalBpFixture {
        statement,
        messages: vec![
            common_commit_a.to_vec(),
            common_commit_b.to_vec(),
            common_reveal_a[..].to_vec(),
            common_reveal_b[..].to_vec(),
            round1_commit_a.to_vec(),
            round1_commit_b.to_vec(),
            round1_a.to_bytes().to_vec(),
            round1_b.to_bytes().to_vec(),
            round2_a[..].to_vec(),
            round2_b[..].to_vec(),
            proof.as_bytes().to_vec(),
        ],
    })
}

fn complete_operational_bp_transport(
    store: &ContractsSessionStoreV1,
    initial: &SessionRecordV1,
    fixture: &EarlyFixture,
) -> Result<(SessionRecordV1, OperationalBpFixture), Box<dyn Error>> {
    let mut current = complete_early_transport(store, initial, fixture)?;
    let operational = operational_bp_fixture(fixture)?;
    let authority = store.prepare_operational_bp_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    let positions = [
        (MessageTypeV1::BpCommonCommit, 0_usize, 3_u64),
        (MessageTypeV1::BpCommonCommit, 1, 3),
        (MessageTypeV1::BpCommonReveal, 0, 4),
        (MessageTypeV1::BpCommonReveal, 1, 4),
        (MessageTypeV1::BpRoundCommit, 0, 5),
        (MessageTypeV1::BpRoundCommit, 1, 5),
        (MessageTypeV1::BpRound1, 0, 6),
        (MessageTypeV1::BpRound1, 1, 6),
        (MessageTypeV1::BpRound2, 0, 7),
        (MessageTypeV1::BpRound2, 1, 7),
        (MessageTypeV1::BpFinal, 1, 8),
    ];
    for ((kind, participant, sequence), payload) in
        positions.into_iter().zip(operational.messages.iter())
    {
        let signed = signed_inner(
            fixture,
            kind,
            participant,
            sequence,
            current.transcript_hash(),
            payload.clone(),
        )?;
        match store.accept_prepared_operational_bp_transport_message(&authority, &signed)? {
            DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate => {}
            _ => {
                return Err(Box::new(
                    dom_scriptless_store::SessionStoreError::Quarantined,
                ))
            }
        }
        current = store.load_session(SESSION)?;
    }
    Ok((current, operational))
}

fn test_blinding(seed: u8) -> Result<BlindingFactor, Box<dyn Error>> {
    let mut bytes = [0; 32];
    bytes[31] = seed.max(1);
    Ok(BlindingFactor::from_bytes(bytes)?)
}

fn kernel_message(features: u8, fee: u64, lock_height: u64) -> [u8; 32] {
    let mut body = Vec::new();
    body.push(features);
    body.extend_from_slice(&fee.to_le_bytes());
    body.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &body).as_bytes()
}

struct CanonicalTransactionValuesV1 {
    input: u64,
    output: u64,
}

fn canonical_test_transaction(
    features: u8,
    lock_height: u64,
    values: CanonicalTransactionValuesV1,
    input_seed: u8,
    kernel_seed: u8,
    chain_id: &[u8; 32],
) -> Result<Transaction, Box<dyn Error>> {
    let CanonicalTransactionValuesV1 {
        input: input_value,
        output: output_value,
    } = values;
    let input_blinding = test_blinding(input_seed)?;
    let kernel_blinding = test_blinding(kernel_seed)?;
    let output_blinding = input_blinding.add(&kernel_blinding)?;
    let fee = input_value
        .checked_sub(output_value)
        .ok_or(dom_scriptless_store::SessionStoreError::InvalidDomTransaction)?;
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding)?;
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes())?;
    let signature = schnorr_sign(
        &secret,
        &kernel_message(features, fee, lock_height),
        chain_id,
    )?;
    Ok(Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features,
            fee: Amount::from_noms(fee)?,
            lock_height,
            excess,
            excess_signature: signature.to_bytes(),
        }],
        offset: [0; 32],
    })
}

fn canonical_template_transactions(
    fixture: &EarlyFixture,
) -> Result<[Transaction; 3], Box<dyn Error>> {
    let chain_id = fixture.trusted_chain.as_bytes();
    Ok([
        canonical_test_transaction(
            KERNEL_FEAT_PLAIN,
            0,
            CanonicalTransactionValuesV1 {
                input: 1_000,
                output: 990,
            },
            21,
            22,
            chain_id,
        )?,
        canonical_test_transaction(
            KERNEL_FEAT_PLAIN,
            0,
            CanonicalTransactionValuesV1 {
                input: 2_000,
                output: 1_980,
            },
            23,
            24,
            chain_id,
        )?,
        canonical_test_transaction(
            KERNEL_FEAT_HEIGHT_LOCKED,
            144,
            CanonicalTransactionValuesV1 {
                input: 3_000,
                output: 2_970,
            },
            25,
            26,
            chain_id,
        )?,
    ])
}

fn crypto_real_final_refund_transactions(
    initial: &SessionRecordV1,
    fixture: &EarlyFixture,
    operational: &OperationalBpFixture,
) -> Result<[Transaction; 3], Box<dyn Error>> {
    let contributions = (0..2)
        .map(|index| -> Result<_, Box<dyn Error>> {
            Ok(contribute_blinding_share_v1(
                &fixture.trusted_chain,
                initial.session_id(),
                &fixture.participant_ids,
                fixture.directions[index],
                u16::try_from(index)?,
                &fixture.signing_shares[index],
                initial.terms_hash(),
                *operational.statement.recovery_binding_hash(),
            )?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let shared = aggregate_shared_commitment_v1(
        &fixture.trusted_chain,
        initial.session_id(),
        &fixture.participant_ids,
        42,
        initial.terms_hash(),
        *operational.statement.recovery_binding_hash(),
        &contributions,
    )?;
    if shared.commitment_bytes()
        != &operational
            .statement
            .aggregate_commitment()
            .to_compressed_bytes()
    {
        return Err(Box::new(SessionStoreError::Canonical));
    }
    let proof = RangeProof739::try_from(
        operational
            .messages
            .get(10)
            .ok_or(SessionStoreError::Canonical)?
            .as_slice(),
    )?;
    let shared_output = VerifiedSharedOutputV1::from_collaborative_proof_and_capsule(
        &shared,
        proof,
        Some(&fixture.recovery_capsule),
    )?;

    let aggregate_blinding = test_blinding(16)?;
    let unsigned_kernel =
        |features: u8, fee: u64, lock_height: u64| -> Result<TransactionKernel, Box<dyn Error>> {
            Ok(TransactionKernel {
                features,
                fee: Amount::from_noms(fee)?,
                lock_height,
                excess: Commitment::commit(0, &aggregate_blinding),
                excess_signature: [0; 65],
            })
        };
    let funding_input_blinding = test_blinding(5)?;
    let change_blinding = test_blinding(5)?;
    let (change_proof, _) = dom_crypto::bp2_prove(7, &change_blinding)?;
    let payout_blinding = test_blinding(32)?;
    let (payout_proof, _) = dom_crypto::bp2_prove(40, &payout_blinding)?;
    let funding = ScriptlessTransactionTemplateV1::funding(
        &shared_output,
        vec![TransactionInput {
            commitment: Commitment::commit(50, &funding_input_blinding),
        }],
        vec![TransactionOutput {
            commitment: Commitment::commit(7, &change_blinding),
            proof: change_proof,
        }],
        0,
        unsigned_kernel(KERNEL_FEAT_PLAIN, 1, 0)?,
        [0; 32],
    )?;
    let payout = TransactionOutput {
        commitment: Commitment::commit(40, &payout_blinding),
        proof: payout_proof,
    };
    let claim = ScriptlessTransactionTemplateV1::claim(
        &shared_output,
        vec![payout.clone()],
        unsigned_kernel(KERNEL_FEAT_PLAIN, 2, 0)?,
        [0; 32],
    )?;
    let refund = ScriptlessTransactionTemplateV1::refund(
        &shared_output,
        vec![payout],
        unsigned_kernel(KERNEL_FEAT_HEIGHT_LOCKED, 2, 500)?,
        [0; 32],
        100,
    )?;
    Ok([
        funding.transaction_template().clone(),
        claim.transaction_template().clone(),
        refund.transaction_template().clone(),
    ])
}

fn signing_roster(fixture: &EarlyFixture) -> Result<ParticipantRosterV1, Box<dyn Error>> {
    let mut participants = vec![
        ParticipantIdentityV1::new(
            &fixture.trusted_chain,
            fixture.identity_keys[0].public_key(),
            fixture.signing_shares[0].public_key().clone(),
            fixture.directions[0],
        )?,
        ParticipantIdentityV1::new(
            &fixture.trusted_chain,
            fixture.identity_keys[1].public_key(),
            fixture.signing_shares[1].public_key().clone(),
            fixture.directions[1],
        )?,
    ];
    participants.sort_by_key(|participant| *participant.participant_id());
    Ok(ParticipantRosterV1::new(participants)?)
}

fn scalar_bytes(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[31] = value;
    bytes
}

fn scalar_from_be_bytes(bytes: &[u8; 32]) -> Result<Scalar, Box<dyn Error>> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .ok_or_else(|| Box::<dyn Error>::from(dom_scriptless_store::SessionStoreError::Canonical))
}

fn prepared_signing_payloads(
    fixture: &EarlyFixture,
    roster: &ParticipantRosterV1,
    transaction: &Transaction,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let purpose = PurposeV1::Refund;
    let (_, template_hash) = canonical_template_v1(transaction)?;
    let nonce_scalars = [
        [scalar_bytes(31), scalar_bytes(32)],
        [scalar_bytes(33), scalar_bytes(34)],
    ];
    let mut commitments = Vec::with_capacity(2);
    let mut reveals = Vec::with_capacity(2);
    let mut public_nonces = Vec::with_capacity(2);
    for (protocol_index, nonce_pair) in nonce_scalars.iter().enumerate() {
        let participant = &roster.entries()[protocol_index];
        let signing_index = roster.signing_index(participant.participant_id())?;
        let first = SecretKey::from_bytes(&nonce_pair[0])?.public_key();
        let second = SecretKey::from_bytes(&nonce_pair[1])?.public_key();
        let commitment = nonce_commitment_hash_v1(
            fixture.trusted_chain.as_bytes(),
            &SESSION,
            participant.participant_id(),
            purpose,
            &template_hash,
            &first,
            &second,
            None,
        )?;
        commitments.push(
            NonceCommitmentV1::new(purpose, signing_index, *commitment.as_bytes())
                .to_bytes()
                .to_vec(),
        );
        reveals.push(
            NonceRevealV1::new(purpose, signing_index, first.clone(), second.clone())
                .to_bytes()
                .to_vec(),
        );
        public_nonces.push(ParticipantPublicNoncesV1 {
            participant_index: signing_index,
            signing_key: participant.signing_public_key().clone(),
            first_nonce: first,
            second_nonce: second,
        });
    }
    public_nonces.sort_by_key(|entry| entry.participant_index);
    let binding = binding_factor_v1(
        &BindingContextV1 {
            chain_id: *fixture.trusted_chain.as_bytes(),
            session_id: SESSION,
            purpose,
            template_hash,
        },
        &public_nonces,
        None,
    )?;
    let effective_nonces = public_nonces
        .iter()
        .map(|entry| binding.bind_public_nonces(&entry.first_nonce, &entry.second_nonce))
        .collect::<Result<Vec<_>, _>>()?;
    let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)?;
    let mut signing_keys = roster
        .entries()
        .iter()
        .map(|participant| participant.signing_public_key().clone())
        .collect::<Vec<_>>();
    signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
    let aggregate_signing_key = aggregate_public_nonces_v1(&signing_keys)?;
    let kernel = transaction
        .kernels
        .first()
        .ok_or(dom_scriptless_store::SessionStoreError::InvalidDomTransaction)?;
    let challenge = schnorr_challenge(
        &aggregate_nonce.to_compressed_bytes(),
        &aggregate_signing_key,
        fixture.trusted_chain.as_bytes(),
        &kernel_message(kernel.features, kernel.fee.noms(), kernel.lock_height),
    );
    let binding_scalar = scalar_from_be_bytes(&binding.to_be_bytes())?;
    let challenge_scalar = scalar_from_be_bytes(challenge.as_bytes())?;
    let mut partials = Vec::with_capacity(2);
    for (protocol_index, nonce_pair) in nonce_scalars.iter().enumerate() {
        let participant = &roster.entries()[protocol_index];
        let fixture_index = fixture
            .participant_ids
            .iter()
            .position(|candidate| candidate == participant.participant_id())
            .ok_or(dom_scriptless_store::SessionStoreError::Canonical)?;
        let partial = scalar_from_be_bytes(&nonce_pair[0])?
            + binding_scalar * scalar_from_be_bytes(&nonce_pair[1])?
            + challenge_scalar * scalar_from_be_bytes(&fixture.signing_share_bytes[fixture_index])?;
        partials.push(
            PartialSignatureV1::new(
                purpose,
                roster.signing_index(participant.participant_id())?,
                template_hash,
                PartialSig::from_bytes(partial.to_bytes().as_ref())?,
            )
            .to_bytes()
            .to_vec(),
        );
    }
    let mut messages = Vec::with_capacity(6);
    messages.extend(commitments);
    messages.extend(reveals);
    messages.extend(partials);
    Ok(messages)
}

fn signed_prepared_signing_position(
    fixture: &EarlyFixture,
    roster: &ParticipantRosterV1,
    current: &SessionRecordV1,
    position: usize,
    payload: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let protocol_index = position % 2;
    let stage = position / 2;
    let participant_id = roster
        .entries()
        .get(protocol_index)
        .ok_or(dom_scriptless_store::SessionStoreError::Canonical)?
        .participant_id();
    let fixture_index = fixture
        .participant_ids
        .iter()
        .position(|candidate| candidate == participant_id)
        .ok_or(dom_scriptless_store::SessionStoreError::Canonical)?;
    let sequence = 9_u64
        .checked_add(u64::try_from(fixture_index)?)
        .and_then(|value| value.checked_add(u64::try_from(stage).ok()?))
        .ok_or(dom_scriptless_store::SessionStoreError::CapacityExceeded)?;
    let kind = match stage {
        0 => MessageTypeV1::SigNonceCommit,
        1 => MessageTypeV1::SigNonceReveal,
        2 => MessageTypeV1::PartialSignature,
        _ => {
            return Err(Box::new(
                dom_scriptless_store::SessionStoreError::InvalidTransition,
            ))
        }
    };
    signed_inner(
        fixture,
        kind,
        fixture_index,
        sequence,
        current.transcript_hash(),
        payload,
    )
}

fn complete_crypto_real_refund_signing_transport(
    store: &ContractsSessionStoreV1,
    initial: &SessionRecordV1,
    fixture: &EarlyFixture,
) -> Result<(SessionRecordV1, ParticipantRosterV1), Box<dyn Error>> {
    let (mut current, _operational, transactions) =
        complete_crypto_real_template_transport(store, initial, fixture)?;

    let roster = signing_roster(fixture)?;
    if roster.entries()[0].direction() != DirectionV1::Responder {
        return Err(Box::new(SessionStoreError::Canonical));
    }
    store.bind_operational_signing_session(
        fixture.trusted_chain,
        SESSION,
        ContractKindV1::WitnessOrTimeout,
        PurposeV1::Refund,
        roster.clone(),
        transactions[2].clone(),
        0,
        None,
    )?;
    let payloads = prepared_signing_payloads(fixture, &roster, &transactions[2])?;
    let signing_authority = store.prepare_operational_signing_transport_authority(
        fixture.trusted_chain,
        SESSION,
        PurposeV1::Refund,
    )?;
    for (position, payload) in payloads.into_iter().enumerate() {
        let signed =
            signed_prepared_signing_position(fixture, &roster, &current, position, payload)?;
        match store
            .accept_prepared_operational_signing_transport_message(&signing_authority, &signed)?
        {
            DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate => {}
            _ => return Err(Box::new(SessionStoreError::Quarantined)),
        }
        current = store.load_session(SESSION)?;
    }
    Ok((current, roster))
}

fn complete_crypto_real_template_transport(
    store: &ContractsSessionStoreV1,
    initial: &SessionRecordV1,
    fixture: &EarlyFixture,
) -> Result<(SessionRecordV1, OperationalBpFixture, [Transaction; 3]), Box<dyn Error>> {
    let (mut current, operational) = complete_operational_bp_transport(store, initial, fixture)?;
    let transactions = crypto_real_final_refund_transactions(initial, fixture, &operational)?;
    let template_authority = store.prepare_operational_template_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &transactions[0],
        &transactions[1],
        &transactions[2],
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    for direction in [DirectionV1::Initiator, DirectionV1::Responder] {
        let participant = fixture.index_for_direction(direction)?;
        let sequence = 8_u64
            .checked_add(u64::try_from(participant)?)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        let signed = signed_inner(
            fixture,
            MessageTypeV1::TxTemplateCommit,
            participant,
            sequence,
            current.transcript_hash(),
            template_authority.template_commit_payload().to_vec(),
        )?;
        match store
            .accept_prepared_operational_template_transport_message(&template_authority, &signed)?
        {
            DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate => {}
            _ => return Err(Box::new(SessionStoreError::Quarantined)),
        }
        current = store.load_session(SESSION)?;
    }
    Ok((current, operational, transactions))
}

fn signed_inner(
    fixture: &EarlyFixture,
    kind: MessageTypeV1,
    participant: usize,
    sequence: u64,
    previous: Digest32,
    payload: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unsigned = UnsignedMessageV1::new(
        kind,
        *fixture.trusted_chain.as_bytes(),
        SESSION,
        fixture.participant_ids[participant],
        sequence,
        previous,
        payload,
    )?;
    Ok(
        SignedMessageV1::sign(unsigned, &fixture.identity_keys[participant])?
            .as_bytes()
            .to_vec(),
    )
}

fn committed_abort(
    store: &ContractsSessionStoreV1,
    fixture: &EarlyFixture,
    decision_digest: Digest32,
) -> Result<CommittedOutboundDsc1V1, Box<dyn Error>> {
    let authority = store.prepare_operational_abort_transport_authority(
        fixture.trusted_chain,
        SESSION,
        decision_digest,
    )?;
    let canonical_sender = fixture
        .participant_ids
        .iter()
        .min()
        .ok_or(SessionStoreError::Canonical)?;
    let sender = fixture
        .participant_ids
        .iter()
        .position(|participant| participant == canonical_sender)
        .ok_or(SessionStoreError::Canonical)?;
    let key_reference = match fixture.directions[sender] {
        DirectionV1::Initiator => [0x61; 32],
        DirectionV1::Responder => [0x62; 32],
    };
    store.bind_local_transport_signer(SESSION, key_reference)?;
    let request = store
        .prepare_abort_dsc1_signing_request(&authority)?
        .ok_or(SessionStoreError::InvalidTransition)?;
    let payload = AbortPayloadV1::decode_exact(request.payload())?;
    let unsigned = UnsignedMessageV1::new_abort(
        *request.chain_id(),
        *request.session_id(),
        *request.sender_id(),
        request.sequence(),
        *request.previous_transcript_hash(),
        payload,
    )?;
    let signed = SignedMessageV1::sign(unsigned, &fixture.identity_keys[sender])?;
    Ok(store.commit_prepared_outbound_dsc1(request, signed.as_bytes())?)
}

fn resumed_committed(
    store: &ContractsSessionStoreV1,
) -> Result<CommittedOutboundDsc1V1, Box<dyn Error>> {
    match store.resume_outbound_dsc1(SESSION)? {
        OutboundDsc1RecoveryV1::Committed(outbound) => Ok(*outbound),
        OutboundDsc1RecoveryV1::SigningRequest(_) | OutboundDsc1RecoveryV1::None => {
            Err(Box::new(SessionStoreError::Quarantined))
        }
    }
}

struct LoseAckQueue {
    relay: ProductionRelayV1,
    lose_next_ack: bool,
    attempts: Vec<Vec<u8>>,
}

impl RelayQueueV1 for LoseAckQueue {
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
        self.attempts.push(raw.to_vec());
        let ack = self
            .relay
            .submit(raw)
            .map_err(BridgeRefusal::DurableRelay)?;
        if self.lose_next_ack {
            self.lose_next_ack = false;
            Err(BridgeRefusal::AckDigestMismatch)
        } else {
            Ok(ack)
        }
    }

    fn queue_deliver(&self, recipient: &ParticipantId) -> Result<Vec<Vec<u8>>, BridgeRefusal> {
        self.relay
            .deliver(recipient)
            .map_err(BridgeRefusal::DurableRelay)
    }
}

fn relay_config() -> Result<RelayDatabaseConfigV1, Box<dyn Error>> {
    Ok(RelayDatabaseConfigV1::new(
        RelayDatabaseIdV1::new([0xd1; 32])?,
        256,
    )?)
}

fn create_relay(root: &Path, lose_next_ack: bool) -> Result<LoseAckQueue, Box<dyn Error>> {
    Ok(LoseAckQueue {
        relay: ProductionRelayV1::create(root, relay_config()?)?,
        lose_next_ack,
        attempts: Vec::new(),
    })
}

fn open_relay(root: &Path) -> Result<LoseAckQueue, Box<dyn Error>> {
    Ok(LoseAckQueue {
        relay: ProductionRelayV1::open(root, relay_config()?)?,
        lose_next_ack: false,
        attempts: Vec::new(),
    })
}

#[test]
fn ack_loss_contracts_crash_duplicate_and_equivocation_survive_restart(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let ingress_authority = issue_early_authority(&responder_store, &fixture)?;
    let offer_payload = ingress_authority.offer_payload()?.to_vec();
    let mut initiator = TestPeerOutbound::create(temporary.path(), true, initiator_store)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;
    responder.install_contracts_ingress(PreparedContractsIngressV1::early(ingress_authority))?;
    let offer = signed_inner(
        &fixture,
        MessageTypeV1::Offer,
        0,
        0,
        initial.transcript_hash(),
        offer_payload,
    )?;

    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, true)?;
    let prepared = initiator.prepare_signed_dsc1(&offer, expiry())?;
    assert_eq!(prepared.sequence, 0);
    assert!(matches!(
        initiator.submit_outbound_once(&mut relay),
        Err(RelayWorkerOutboundErrorV1::Sender(_))
    ));
    assert!(initiator.sender_stats()?.pending);
    let first_attempt = relay.attempts[0].clone();
    drop(initiator);
    drop(relay);

    let initiator_store = open_contracts_store(temporary.path(), "contracts-a")?;
    let mut initiator = TestPeerOutbound::open_existing(temporary.path(), true, initiator_store)?;
    let mut relay = open_relay(&relay_root)?;
    let ack = initiator.submit_outbound_once(&mut relay)?;
    assert!(matches!(
        ack,
        RelayOutboundStepV1::Acked {
            next_sequence: 1,
            ..
        }
    ));
    assert_eq!(relay.attempts[0], first_attempt);

    let ingest = responder.ingest_mailbox(&relay, now())?;
    assert_eq!((ingest.accepted, ingest.refused.len()), (1, 0));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);

    // Exact crash cut: the inbox row is durable, then the worker dies.  The
    // Contracts Store is reopened alone and commits the same typed message;
    // it dies before the inbox can persist the downstream receipt.
    drop(responder);
    let crash_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let crash_boundary_authority = issue_early_authority(&crash_store, &fixture)?;
    assert!(matches!(
        crash_store.accept_prepared_early_transport_message(&crash_boundary_authority, &offer)?,
        DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate
    ));
    assert_eq!(crash_store.load_session(SESSION)?.revision(), 1);
    drop(crash_store);

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let resumed = issue_early_authority(&responder_store, &fixture)?;
    let mut responder = open_worker(temporary.path(), false, responder_store)?;
    responder.install_contracts_ingress(PreparedContractsIngressV1::early(resumed))?;
    let recovered = responder.dispatch_inbound()?;
    assert_eq!(recovered.contracts.applied, 1);
    assert_eq!(recovered.contracts.duplicate_commits, 1);
    assert_eq!(recovered.inbox.pending_route, 0);
    assert_eq!(responder.contracts_session_status()?.revision, 1);

    // A new outer sequence carrying the exact same DSC1 is a Store duplicate,
    // not a second semantic transition.
    assert_eq!(initiator.prepare_signed_dsc1(&offer, expiry())?.sequence, 1);
    assert!(matches!(
        initiator.submit_outbound_once(&mut relay)?,
        RelayOutboundStepV1::Acked {
            next_sequence: 2,
            ..
        }
    ));
    let duplicate = responder.poll_inbound(&relay, now())?;
    assert_eq!(duplicate.dispatch.contracts.applied, 1);
    assert_eq!(duplicate.dispatch.contracts.duplicate_commits, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 1);

    let conflicting_payload = EarlyTermsBindingV1::new(EarlyTermsMessageKindV1::Offer, [0x99; 32])?
        .to_bytes()
        .to_vec();
    let conflict = signed_inner(
        &fixture,
        MessageTypeV1::Offer,
        0,
        0,
        initial.transcript_hash(),
        conflicting_payload,
    )?;
    assert_eq!(
        initiator.prepare_signed_dsc1(&conflict, expiry())?.sequence,
        2
    );
    initiator.submit_outbound_once(&mut relay)?;
    let equivocation = responder.poll_inbound(&relay, now())?;
    assert_eq!(equivocation.dispatch.contracts.failed_closed, 1);
    let failed = responder.contracts_session_status()?;
    assert_eq!(failed.phase, SessionPhaseV1::FailedClosed);
    let failed_revision = failed.revision;
    drop(responder);

    // No early capability can be reissued from FailedClosed.  The worker still
    // recognizes another authenticated copy as terminal without advancing the
    // failed Contracts history again.
    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let mut responder = open_worker(temporary.path(), false, responder_store)?;
    initiator.prepare_signed_dsc1(&conflict, expiry())?;
    initiator.submit_outbound_once(&mut relay)?;
    let terminal_duplicate = responder.poll_inbound(&relay, now())?;
    assert_eq!(terminal_duplicate.dispatch.contracts.failed_closed, 1);
    assert_eq!(terminal_duplicate.dispatch.contracts.duplicate_commits, 1);
    assert_eq!(
        responder.contracts_session_status()?.revision,
        failed_revision
    );
    Ok(())
}

#[test]
fn one_checkpoint_and_inbox_order_cover_f6_then_prepared_contracts() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let authority = issue_early_authority(&responder_store, &fixture)?;
    let refused_replacement = issue_early_authority(&responder_store, &fixture)?;
    let payload = authority.offer_payload()?.to_vec();
    let mut initiator = TestPeerOutbound::create(temporary.path(), true, initiator_store)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;
    responder.install_contracts_ingress(PreparedContractsIngressV1::early(authority))?;
    assert!(matches!(
        responder.install_contracts_ingress(PreparedContractsIngressV1::early(refused_replacement)),
        Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled)
    ));
    let retained = responder
        .take_contracts_ingress()
        .expect("installed early authority remains linear");
    let retained = match retained.into_early() {
        Ok(authority) => authority,
        Err(_) => panic!("early authority kind must not change"),
    };
    responder.install_contracts_ingress(PreparedContractsIngressV1::early(retained))?;
    let offer = signed_inner(
        &fixture,
        MessageTypeV1::Offer,
        0,
        0,
        initial.transcript_hash(),
        payload,
    )?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    assert_eq!(
        initiator
            .prepare_f6(RelayF6MessageKindV1::Rfq, b"bounded-rfq", expiry())?
            .sequence,
        0
    );
    assert!(matches!(
        initiator.submit_outbound_once(&mut relay)?,
        RelayOutboundStepV1::Acked {
            next_sequence: 1,
            ..
        }
    ));
    assert_eq!(initiator.prepare_signed_dsc1(&offer, expiry())?.sequence, 1);
    assert!(matches!(
        initiator.submit_outbound_once(&mut relay)?,
        RelayOutboundStepV1::Acked {
            next_sequence: 2,
            ..
        }
    ));

    let report = responder.poll_inbound(&relay, now())?;
    assert_eq!(report.ingest.accepted, 2);
    assert_eq!(report.dispatch.f6.applied, 1);
    assert_eq!(report.dispatch.f6.blocked_by_route, 0);
    assert_eq!(report.dispatch.contracts.applied, 1);
    assert_eq!(
        responder.f6_mut().kinds,
        vec![relay::auth::message_type::RFQ]
    );
    assert_eq!(responder.contracts_session_status()?.revision, 1);
    Ok(())
}

#[test]
fn prepared_operational_bp_stays_closed_then_reissues_across_worker_restart(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let early_complete = complete_early_transport(&responder_store, &initial, &fixture)?;
    assert_eq!(early_complete.revision(), 6);
    assert_eq!(early_complete.phase(), SessionPhaseV1::SharesRevealed);

    let operational = operational_bp_fixture(&fixture)?;
    let bp_authority = responder_store.prepare_operational_bp_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    let first = signed_inner(
        &fixture,
        MessageTypeV1::BpCommonCommit,
        0,
        3,
        early_complete.transcript_hash(),
        operational.messages[0].clone(),
    )?;
    assert!(matches!(
        responder_store.accept_prepared_operational_bp_transport_message(&bp_authority, &first)?,
        DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate
    ));
    let after_first = responder_store.load_session(SESSION)?;
    assert_eq!(after_first.revision(), 7);
    let resumed = responder_store.prepare_operational_bp_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    let second = signed_inner(
        &fixture,
        MessageTypeV1::BpCommonCommit,
        1,
        3,
        after_first.transcript_hash(),
        operational.messages[1].clone(),
    )?;
    let participants = fixture.relay_participants()?;
    let mut peer =
        TestPeerOutbound::create_for(temporary.path(), false, initiator_store, participants)?;
    let mut worker = create_worker_for(temporary.path(), true, responder_store, participants)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    // The initiator's local first position is part of fixture setup above.
    // Only the responder's DSC1 crosses this initiator-owned Relay ingress, so
    // the authenticated outer and inner sender identities remain identical.
    peer.prepare_signed_dsc1(&second, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    let refusal = worker
        .dispatch_inbound()
        .expect_err("unseen BP transport must require its prepared authority");
    assert!(matches!(
        refusal,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(worker.contracts_session_status()?.revision, 7);

    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_bp(resumed))?;
    let accepted = worker.dispatch_inbound()?;
    assert_eq!(accepted.contracts.applied, 1);
    assert_eq!(accepted.contracts.duplicate_commits, 0);
    let accepted_status = worker.contracts_session_status()?;
    assert_eq!(accepted_status.revision, 8);
    assert_eq!(accepted_status.phase, SessionPhaseV1::BpCommonCommitted);
    let retained = worker
        .take_contracts_ingress()
        .expect("the BP authority remains linear after one message");
    let retained = match retained.into_operational_bp() {
        Ok(authority) => authority,
        Err(_) => panic!("the prepared authority kind must not change"),
    };
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_bp(retained))?;
    drop(worker);

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let resumed = responder_store.prepare_operational_bp_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    let mut worker = open_worker_for(temporary.path(), true, responder_store, participants)?;
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_bp(resumed))?;

    // A new outer Relay sequence carrying the exact same signed DSC1 message
    // is a Store duplicate, never a second Bulletproof transition.
    peer.prepare_signed_dsc1(&second, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    let duplicate = worker.poll_inbound(&relay, now())?;
    assert_eq!(duplicate.dispatch.contracts.applied, 1);
    assert_eq!(duplicate.dispatch.contracts.duplicate_commits, 1);
    assert_eq!(worker.contracts_session_status()?.revision, 8);
    Ok(())
}

#[test]
fn prepared_operational_template_stays_closed_then_reissues_across_worker_restart(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let (bp_complete, operational) =
        complete_operational_bp_transport(&responder_store, &initial, &fixture)?;
    assert_eq!(bp_complete.revision(), 17);
    assert_eq!(bp_complete.phase(), SessionPhaseV1::OutputFinalized);
    let [funding, claim, refund] = canonical_template_transactions(&fixture)?;
    let template_authority = responder_store.prepare_operational_template_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &funding,
        &claim,
        &refund,
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    let first = signed_inner(
        &fixture,
        MessageTypeV1::TxTemplateCommit,
        0,
        8,
        bp_complete.transcript_hash(),
        template_authority.template_commit_payload().to_vec(),
    )?;
    assert!(matches!(
        responder_store.accept_prepared_operational_template_transport_message(
            &template_authority,
            &first,
        )?,
        DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate
    ));
    let after_first = responder_store.load_session(SESSION)?;
    assert_eq!(after_first.revision(), 18);
    let resumed = responder_store.prepare_operational_template_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &funding,
        &claim,
        &refund,
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    let second = signed_inner(
        &fixture,
        MessageTypeV1::TxTemplateCommit,
        1,
        9,
        after_first.transcript_hash(),
        resumed.template_commit_payload().to_vec(),
    )?;
    let participants = fixture.relay_participants()?;
    let mut peer =
        TestPeerOutbound::create_for(temporary.path(), false, initiator_store, participants)?;
    let mut worker = create_worker_for(temporary.path(), true, responder_store, participants)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    peer.prepare_signed_dsc1(&second, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    let refusal = worker
        .dispatch_inbound()
        .expect_err("unseen template commit must require its prepared authority");
    assert!(matches!(
        refusal,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(worker.contracts_session_status()?.revision, 18);

    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_template(resumed))?;
    let accepted = worker.dispatch_inbound()?;
    assert_eq!(accepted.contracts.applied, 1);
    assert_eq!(accepted.contracts.duplicate_commits, 0);
    let accepted_status = worker.contracts_session_status()?;
    assert_eq!(accepted_status.revision, 19);
    assert_eq!(accepted_status.phase, SessionPhaseV1::TemplatesCommitted);
    let retained = worker
        .take_contracts_ingress()
        .expect("the template authority remains linear after one message");
    let retained = match retained.into_operational_bp() {
        Ok(_) => panic!("a template authority must not unwrap as Bulletproof"),
        Err(retained) => retained,
    };
    let retained = match retained.into_operational_template() {
        Ok(authority) => authority,
        Err(_) => panic!("the prepared template authority kind must not change"),
    };
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_template(retained))?;
    drop(worker);

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let resumed = responder_store.prepare_operational_template_transport_authority(
        fixture.trusted_chain,
        SESSION,
        initial.terms_hash(),
        &funding,
        &claim,
        &refund,
        &operational.statement,
        &fixture.recovery_capsule,
    )?;
    let mut worker = open_worker_for(temporary.path(), true, responder_store, participants)?;
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_template(resumed))?;

    // A new outer Relay sequence carrying the exact same signed DSC1 is a
    // Store duplicate and cannot create a third template transition.
    peer.prepare_signed_dsc1(&second, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    let duplicate = worker.poll_inbound(&relay, now())?;
    assert_eq!(duplicate.dispatch.contracts.applied, 1);
    assert_eq!(duplicate.dispatch.contracts.duplicate_commits, 1);
    assert_eq!(worker.contracts_session_status()?.revision, 19);
    Ok(())
}

#[test]
fn prepared_operational_signing_stays_closed_then_reissues_across_worker_restart(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new_responder_first_signing_compatible(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let (round_start, _operational, transactions) =
        complete_crypto_real_template_transport(&responder_store, &initial, &fixture)?;
    assert_eq!(round_start.revision(), 19);
    assert_eq!(round_start.phase(), SessionPhaseV1::TemplatesCommitted);

    let roster = signing_roster(&fixture)?;
    assert_eq!(roster.entries()[0].direction(), DirectionV1::Responder);
    assert_eq!(roster.entries()[1].direction(), DirectionV1::Initiator);
    responder_store.bind_operational_signing_session(
        fixture.trusted_chain,
        SESSION,
        ContractKindV1::WitnessOrTimeout,
        PurposeV1::Refund,
        roster.clone(),
        transactions[2].clone(),
        0,
        None,
    )?;
    let payloads = prepared_signing_payloads(&fixture, &roster, &transactions[2])?;
    assert_eq!(payloads.len(), 6);
    let signing_authority = responder_store.prepare_operational_signing_transport_authority(
        fixture.trusted_chain,
        SESSION,
        PurposeV1::Refund,
    )?;
    assert_eq!(signing_authority.session_id(), &SESSION);
    assert_eq!(signing_authority.purpose(), PurposeV1::Refund);
    let first =
        signed_prepared_signing_position(&fixture, &roster, &round_start, 0, payloads[0].clone())?;

    let participants = fixture.relay_participants()?;
    let mut peer =
        TestPeerOutbound::create_for(temporary.path(), false, initiator_store, participants)?;
    let mut worker = create_worker_for(temporary.path(), true, responder_store, participants)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    peer.prepare_signed_dsc1(&first, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    let refusal = worker
        .dispatch_inbound()
        .expect_err("unseen signing transport must require its prepared authority");
    assert!(matches!(
        refusal,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(worker.contracts_session_status()?.revision, 19);

    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_signing(
        signing_authority,
    ))?;
    let first_report = worker.dispatch_inbound()?;
    assert_eq!(first_report.contracts.applied, 1);
    assert_eq!(first_report.contracts.duplicate_commits, 0);
    let first_status = worker.contracts_session_status()?;
    assert_eq!(first_status.revision, 20);
    assert_eq!(first_status.phase, SessionPhaseV1::RefundSigning);
    let retained = worker
        .take_contracts_ingress()
        .expect("the signing authority remains linear after one message");
    let retained = match retained.into_operational_template() {
        Ok(_) => panic!("a signing authority must not unwrap as a template authority"),
        Err(retained) => retained,
    };
    let retained = match retained.into_operational_signing() {
        Ok(authority) => authority,
        Err(_) => panic!("the prepared signing authority kind must not change"),
    };
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_signing(retained))?;
    drop(worker);

    let mut last_remote = first;
    for (position, payload) in payloads.iter().enumerate().skip(1) {
        let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
        let current = responder_store.load_session(SESSION)?;
        let reissued = responder_store.prepare_operational_signing_transport_authority(
            fixture.trusted_chain,
            SESSION,
            PurposeV1::Refund,
        )?;
        let signed = signed_prepared_signing_position(
            &fixture,
            &roster,
            &current,
            position,
            payload.clone(),
        )?;
        let sender_direction = roster
            .entries()
            .get(position % 2)
            .ok_or(SessionStoreError::Canonical)?
            .direction();
        if sender_direction == DirectionV1::Initiator {
            // This Store belongs to the initiator-facing worker. Its own
            // alternating positions are fixture-local transitions and never
            // re-enter through Relay as self-messages.
            assert!(matches!(
                responder_store.accept_prepared_operational_signing_transport_message(
                    &reissued,
                    &signed,
                )?,
                DurableTransportOutcomeV1::Accepted(receipt) if !receipt.duplicate
            ));
            let status = responder_store.load_session(SESSION)?;
            assert_eq!(status.revision(), 20 + u64::try_from(position)?);
            assert_eq!(status.phase(), SessionPhaseV1::RefundSigning);
        } else {
            let mut worker =
                open_worker_for(temporary.path(), true, responder_store, participants)?;
            worker.install_contracts_ingress(PreparedContractsIngressV1::operational_signing(
                reissued,
            ))?;
            peer.prepare_signed_dsc1(&signed, expiry())?;
            peer.submit_outbound_once(&mut relay)?;
            let report = worker.poll_inbound(&relay, now())?;
            assert_eq!(report.dispatch.contracts.applied, 1);
            assert_eq!(report.dispatch.contracts.duplicate_commits, 0);
            let status = worker.contracts_session_status()?;
            assert_eq!(status.revision, 20 + u64::try_from(position)?);
            assert_eq!(status.phase, SessionPhaseV1::RefundSigning);
            last_remote = signed;
        }
    }

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    assert_eq!(responder_store.load_session(SESSION)?.revision(), 25);
    let reissued = responder_store.prepare_operational_signing_transport_authority(
        fixture.trusted_chain,
        SESSION,
        PurposeV1::Refund,
    )?;
    let mut worker = open_worker_for(temporary.path(), true, responder_store, participants)?;
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_signing(reissued))?;

    // A fresh outer Relay sequence carrying the last remote signing position
    // is an exact Store duplicate and cannot create a seventh transition.
    peer.prepare_signed_dsc1(&last_remote, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    let duplicate = worker.poll_inbound(&relay, now())?;
    assert_eq!(duplicate.dispatch.contracts.applied, 1);
    assert_eq!(duplicate.dispatch.contracts.duplicate_commits, 1);
    assert_eq!(worker.contracts_session_status()?.revision, 25);
    Ok(())
}

#[test]
fn prepared_operational_final_refund_is_exact_linear_and_restart_safe() -> Result<(), Box<dyn Error>>
{
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new_responder_first_signing_compatible(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let (refund_terminal, roster) =
        complete_crypto_real_refund_signing_transport(&responder_store, &initial, &fixture)?;
    assert_eq!(refund_terminal.revision(), 25);
    assert_eq!(refund_terminal.phase(), SessionPhaseV1::RefundSigning);

    let final_refund_authority = responder_store
        .prepare_operational_final_refund_transport_authority(fixture.trusted_chain, SESSION)?;
    let final_refund_payload = final_refund_authority.final_refund_payload().to_vec();
    assert_eq!(
        final_refund_authority.refund_tx_hash(),
        blake2b_256(&final_refund_payload).as_bytes()
    );
    let canonical_sender_id = *roster
        .entries()
        .first()
        .ok_or(SessionStoreError::Canonical)?
        .participant_id();
    let canonical_sender = fixture
        .participant_ids
        .iter()
        .position(|candidate| candidate == &canonical_sender_id)
        .ok_or(SessionStoreError::Canonical)?;
    assert_eq!(fixture.directions[canonical_sender], DirectionV1::Responder);
    let canonical_sequence = 12_u64
        .checked_add(u64::try_from(canonical_sender)?)
        .ok_or(SessionStoreError::CapacityExceeded)?;
    let final_refund = signed_inner(
        &fixture,
        MessageTypeV1::FinalRefund,
        canonical_sender,
        canonical_sequence,
        refund_terminal.transcript_hash(),
        final_refund_payload.clone(),
    )?;

    let participants = fixture.relay_participants()?;
    let mut peer =
        TestPeerOutbound::create_for(temporary.path(), false, initiator_store, participants)?;
    let mut worker = create_worker_for(temporary.path(), true, responder_store, participants)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    peer.prepare_signed_dsc1(&final_refund, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    let unprepared = worker
        .dispatch_inbound()
        .expect_err("unseen FinalRefund must not enter through generic ingress");
    assert!(matches!(
        unprepared,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(worker.contracts_session_status()?.revision, 25);

    let ingress = PreparedContractsIngressV1::operational_final_refund(final_refund_authority);
    let ingress = match ingress.into_operational_signing() {
        Ok(_) => panic!("a final Refund authority must not unwrap as signing"),
        Err(ingress) => ingress,
    };
    let final_refund_authority = match ingress.into_operational_final_refund() {
        Ok(authority) => authority,
        Err(_) => panic!("the final Refund authority kind must remain intact"),
    };
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_final_refund(
        final_refund_authority,
    ))?;
    let accepted = worker.dispatch_inbound()?;
    assert_eq!(accepted.contracts.applied, 1);
    assert_eq!(accepted.contracts.duplicate_commits, 0);
    let accepted_status = worker.contracts_session_status()?;
    assert_eq!(accepted_status.revision, 26);
    assert_eq!(accepted_status.phase, SessionPhaseV1::RefundSigned);
    let retained = worker
        .take_contracts_ingress()
        .expect("the exact final Refund authority remains process-linear");
    let retained = match retained.into_operational_final_refund() {
        Ok(authority) => authority,
        Err(_) => panic!("the installed final Refund authority kind must not change"),
    };
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_final_refund(
        retained,
    ))?;
    drop(worker);

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let reissued = responder_store
        .prepare_operational_final_refund_transport_authority(fixture.trusted_chain, SESSION)?;
    assert_eq!(reissued.final_refund_payload(), final_refund_payload);
    let mut worker = open_worker_for(temporary.path(), true, responder_store, participants)?;
    worker.install_contracts_ingress(PreparedContractsIngressV1::operational_final_refund(
        reissued,
    ))?;

    // A fresh outer Relay envelope carrying the exact same signed DSC1 bytes
    // is a Store duplicate, never a second RefundSigned transition.
    peer.prepare_signed_dsc1(&final_refund, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    let duplicate = worker.poll_inbound(&relay, now())?;
    assert_eq!(duplicate.dispatch.contracts.applied, 1);
    assert_eq!(duplicate.dispatch.contracts.duplicate_commits, 1);
    assert_eq!(worker.contracts_session_status()?.revision, 26);

    // Tamper only the Store-derived exact payload while retaining the same
    // authenticated logical key. The generic path may record the signed
    // equivocation, but it may never reinterpret the bytes as another refund.
    let mut conflicting_payload = final_refund_payload;
    conflicting_payload[0] ^= 1;
    let conflict = signed_inner(
        &fixture,
        MessageTypeV1::FinalRefund,
        canonical_sender,
        canonical_sequence,
        refund_terminal.transcript_hash(),
        conflicting_payload,
    )?;
    peer.prepare_signed_dsc1(&conflict, expiry())?;
    peer.submit_outbound_once(&mut relay)?;
    let equivocation = worker.poll_inbound(&relay, now())?;
    assert_eq!(equivocation.dispatch.contracts.failed_closed, 1);
    let failed = worker.contracts_session_status()?;
    assert_eq!(failed.phase, SessionPhaseV1::FailedClosed);
    assert_eq!(failed.revision, 27);
    Ok(())
}

#[test]
fn post_anchor_claim_pre_signature_requires_its_exact_authority_across_restart(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let wrong_phase_authority = issue_early_authority(&responder_store, &fixture)?;
    let mut scalar = [0; 32];
    scalar[31] = 0x46;
    let payload = AdaptorPreSignatureV1::new(
        [0x47; 32],
        SecretKey::from_bytes(&[0x48; 32])?.public_key(),
        SecretKey::from_bytes(&[0x49; 32])?.public_key(),
        PartialSig::from_bytes(&scalar)?,
        [0x4a; 32],
    )
    .to_bytes()
    .to_vec();
    let signed = signed_inner(
        &fixture,
        MessageTypeV1::AdaptorPreSignature,
        0,
        0,
        initial.transcript_hash(),
        payload,
    )?;
    let mut initiator = TestPeerOutbound::create(temporary.path(), true, initiator_store)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    initiator.prepare_signed_dsc1(&signed, expiry())?;
    initiator.submit_outbound_once(&mut relay)?;
    assert_eq!(responder.ingest_mailbox(&relay, now())?.accepted, 1);
    let unprepared = responder
        .dispatch_inbound()
        .expect_err("unseen 0x0f must not enter through generic derived ingress");
    assert!(matches!(
        unprepared,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(responder.contracts_session_status()?.revision, 0);

    responder
        .install_contracts_ingress(PreparedContractsIngressV1::early(wrong_phase_authority))?;
    let wrong_phase = responder
        .dispatch_inbound()
        .expect_err("an early authority must not authorize post-anchor 0x0f");
    assert!(matches!(
        wrong_phase,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(ContractsRelayIngressErrorV1::Store(
                SessionStoreError::InvalidTransition
            ))
        ))
    ));
    let retained = responder
        .take_contracts_ingress()
        .expect("wrong-phase rejection must not consume the linear authority");
    let retained = match retained.into_post_anchor_claim_pre_signature() {
        Ok(_) => panic!("an early authority must not unwrap as post-anchor 0x0f"),
        Err(retained) => retained,
    };
    let retained = match retained.into_post_anchor_claim_pre_signature_v2() {
        Ok(_) => panic!("an early authority must not unwrap as the productive V2 0x0f edge"),
        Err(retained) => retained,
    };
    assert!(retained.into_early().is_ok());
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    drop(responder);

    // The authenticated Relay row survives restart, but no generic dispatcher
    // manufactures the M.8/post-anchor authority required for this edge.
    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let mut responder = open_worker(temporary.path(), false, responder_store)?;
    let retried = responder
        .dispatch_inbound()
        .expect_err("restarted 0x0f must remain pending without its exact authority");
    assert!(matches!(
        retried,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    Ok(())
}

#[test]
fn store_committed_outbound_is_staged_acked_and_reconciled_once() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let store = Rc::new(create_contracts_store(
        temporary.path(),
        "contracts-a",
        &fixture,
    )?);
    let outbound = committed_abort(store.as_ref(), &fixture, [0x81; 32])?;
    let application_id = *outbound.application_id();
    let message_digest = *outbound.message_digest();
    let mut worker = DurableRelayWorkerV1::create(
        &worker_paths(temporary.path(), true),
        worker_config(true),
        Rc::clone(&store),
        rosters(),
        TestF6Authority::default(),
        INITIATOR_RELAY_SECRET,
    )?;

    let staged = worker.stage_store_outbound_dsc1(outbound, expiry())?;
    let status = match staged {
        RouteApplicationDispositionV2::Pending(status) => status,
        RouteApplicationDispositionV2::AlreadyAcked(_) => {
            return Err(Box::new(SessionStoreError::Quarantined))
        }
    };
    assert_eq!(status.application_id(), &application_id);
    assert_eq!(status.first_sequence(), 0);
    assert_eq!(status.final_sequence(), 0);
    assert_eq!(status.acknowledged_frames(), 0);

    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;
    assert!(matches!(
        worker.submit_outbound_once(&mut relay)?,
        RelayOutboundStepV1::Acked {
            next_sequence: 1,
            ..
        }
    ));
    let recovered = resumed_committed(store.as_ref())?;
    assert_eq!(recovered.application_id(), &application_id);
    assert_eq!(recovered.message_digest(), &message_digest);
    let reconciled = worker.stage_store_outbound_dsc1(recovered, expiry())?;
    assert!(matches!(
        reconciled,
        RouteApplicationDispositionV2::AlreadyAcked(status)
            if status.application_id() == &application_id
                && status.acknowledged_frames() == 1
    ));
    assert!(matches!(
        store.resume_outbound_dsc1(SESSION)?,
        OutboundDsc1RecoveryV1::None
    ));
    Ok(())
}

#[test]
fn store_application_ack_loss_restarts_with_identical_bytes_and_no_new_sequence(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let store = Rc::new(create_contracts_store(
        temporary.path(),
        "contracts-a",
        &fixture,
    )?);
    let outbound = committed_abort(store.as_ref(), &fixture, [0x84; 32])?;
    let application_id = *outbound.application_id();
    let mut worker = DurableRelayWorkerV1::create(
        &worker_paths(temporary.path(), true),
        worker_config(true),
        Rc::clone(&store),
        rosters(),
        TestF6Authority::default(),
        INITIATOR_RELAY_SECRET,
    )?;
    assert!(matches!(
        worker.stage_store_outbound_dsc1(outbound, expiry())?,
        RouteApplicationDispositionV2::Pending(status)
            if status.application_id() == &application_id
                && status.first_sequence() == 0
    ));
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, true)?;
    assert!(matches!(
        worker.submit_outbound_once(&mut relay),
        Err(RelayWorkerOutboundErrorV1::Sender(_))
    ));
    let first_attempt = relay.attempts[0].clone();
    drop(worker);
    drop(store);
    drop(relay);

    let store = Rc::new(open_contracts_store(temporary.path(), "contracts-a")?);
    let recovered = resumed_committed(store.as_ref())?;
    let mut worker = DurableRelayWorkerV1::open_existing(
        &worker_paths(temporary.path(), true),
        worker_config(true),
        Rc::clone(&store),
        rosters(),
        TestF6Authority::default(),
        INITIATOR_RELAY_SECRET,
    )?;
    assert!(matches!(
        worker.stage_store_outbound_dsc1(recovered, expiry())?,
        RouteApplicationDispositionV2::Pending(status)
            if status.application_id() == &application_id
                && status.first_sequence() == 0
                && status.acknowledged_frames() == 0
    ));
    let mut relay = open_relay(&relay_root)?;
    assert!(matches!(
        worker.submit_outbound_once(&mut relay)?,
        RelayOutboundStepV1::Acked {
            next_sequence: 1,
            ..
        }
    ));
    assert_eq!(relay.attempts[0], first_attempt);
    let recovered = resumed_committed(store.as_ref())?;
    assert!(matches!(
        worker.stage_store_outbound_dsc1(recovered, expiry())?,
        RouteApplicationDispositionV2::AlreadyAcked(status)
            if status.application_id() == &application_id
    ));
    assert!(matches!(
        store.resume_outbound_dsc1(SESSION)?,
        OutboundDsc1RecoveryV1::None
    ));
    Ok(())
}

#[test]
fn outbound_handle_requires_the_workers_exact_store_opening() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let expected_store = Rc::new(create_contracts_store(
        temporary.path(),
        "contracts-a",
        &fixture,
    )?);
    let unrelated_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let unrelated = committed_abort(&unrelated_store, &fixture, [0x82; 32])?;
    let mut worker = DurableRelayWorkerV1::create(
        &worker_paths(temporary.path(), true),
        worker_config(true),
        Rc::clone(&expected_store),
        rosters(),
        TestF6Authority::default(),
        INITIATOR_RELAY_SECRET,
    )?;
    assert!(matches!(
        worker.stage_store_outbound_dsc1(unrelated, expiry()),
        Err(RelayWorkerOutboundErrorV1::StoreRejected)
    ));
    assert!(!worker.sender_stats()?.pending);

    let old_opening = committed_abort(expected_store.as_ref(), &fixture, [0x83; 32])?;
    drop(worker);
    drop(expected_store);
    let reopened = Rc::new(open_contracts_store(temporary.path(), "contracts-a")?);
    let mut reopened_worker = DurableRelayWorkerV1::open_existing(
        &worker_paths(temporary.path(), true),
        worker_config(true),
        Rc::clone(&reopened),
        rosters(),
        TestF6Authority::default(),
        INITIATOR_RELAY_SECRET,
    )?;
    assert!(matches!(
        reopened_worker.stage_store_outbound_dsc1(old_opening, expiry()),
        Err(RelayWorkerOutboundErrorV1::StoreRejected)
    ));
    assert!(!reopened_worker.sender_stats()?.pending);
    Ok(())
}

#[test]
fn product_worker_exposes_no_caller_shaped_dsc1_or_legacy_frame_staging() {
    let _only_store_issued_stage: fn(
        &mut TestWorker,
        CommittedOutboundDsc1V1,
        TimelockSpec,
    ) -> Result<
        RouteApplicationDispositionV2,
        RelayWorkerOutboundErrorV1,
    > = TestWorker::stage_store_outbound_dsc1;
    let source = include_str!("../src/relay_worker.rs");
    assert!(!source.contains("pub fn prepare_signed_dsc1"));
    assert!(!source.contains(".begin_framed_route("));
    assert!(!source.contains(".prepare_next_frame("));
    // No DSC1 `Ack` (0x14) surface exists in the worker: no ingress variant,
    // no constructor, no extractor and no raw discriminant.  The Relay's own
    // `AckV1` is a transport delivery receipt handled by the sender, and is
    // deliberately never named here as a Contracts message kind.
    assert!(!source.contains("MessageTypeV1::Ack"));
    assert!(!source.contains("0x14"));
}

/// Extracts one feature's exact declared list from the `[features]` table.
fn declared_feature_list<'a>(features: &'a str, name: &str) -> &'a str {
    let needle = format!("\n{name} = [");
    let start = features
        .find(&needle)
        .unwrap_or_else(|| panic!("the daemon manifest must declare the {name} feature"));
    let rest = &features[start + needle.len()..];
    let end = rest
        .find(']')
        .unwrap_or_else(|| panic!("the {name} feature list must be terminated"));
    &rest[..end]
}

#[test]
fn no_shipped_feature_reaches_the_evidence_only_ancestry_surface() {
    let manifest = include_str!("../Cargo.toml");
    let features = manifest
        .split_once("[features]")
        .expect("the daemon manifest must declare a [features] table")
        .1;
    let features = features
        .split_once("\n[")
        .map_or(features, |(table, _)| table);

    // The laboratory ancestry feature exists, and its weak `?` form cannot pull
    // the Store into a graph that did not already contain it.
    assert!(features
        .contains("evidence-only-ancestry-tests = [\"dom-scriptless-store?/evidence-only\"]"));

    // No shipped feature reaches it, directly or through the Store's own
    // evidence-only surface.  This is what keeps the production artifact and
    // this production test suite free of the laboratory constructors.
    for shipped in ["default", "development", "simulation", "production"] {
        let declared = declared_feature_list(features, shipped);
        assert!(
            !declared.contains("evidence-only"),
            "the {shipped} feature must never reach the evidence-only surface: {declared}"
        );
    }
}

#[test]
fn config_only_is_an_isolated_test_feature_no_shipped_feature_reaches() {
    let manifest = include_str!("../Cargo.toml");
    let features = manifest
        .split_once("[features]")
        .expect("the daemon manifest must declare a [features] table")
        .1;
    let features = features
        .split_once("\n[")
        .map_or(features, |(table, _)| table);

    // `config-only` exists, activates no dependency, and is reachable from no
    // shipped feature: it compiles `production_config` for its own codec and
    // golden tests and nothing else.
    assert!(features.contains("config-only = []"));
    for other in [
        "default",
        "development",
        "simulation",
        "production",
        "evidence-only-ancestry-tests",
    ] {
        let declared = declared_feature_list(features, other);
        assert!(
            !declared.contains("config-only"),
            "the {other} feature must never reach the config-only test surface: {declared}"
        );
    }
}

#[test]
fn relay_delivery_ack_is_not_a_dsc1_ack_and_0x14_stays_inaccessible() -> Result<(), Box<dyn Error>>
{
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let mut initiator = TestPeerOutbound::create(temporary.path(), true, initiator_store)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    // A signed DSC1 `Ack` is a structurally valid transport envelope, so the
    // Relay transports it and returns its own delivery receipt.  That receipt
    // advances only the shared outer checkpoint.
    let dsc1_ack = signed_inner(
        &fixture,
        MessageTypeV1::Ack,
        0,
        0,
        initial.transcript_hash(),
        b"typed-ack-without-normative-target".to_vec(),
    )?;
    initiator.prepare_signed_dsc1(&dsc1_ack, expiry())?;
    let delivered = initiator.submit_outbound_once(&mut relay)?;
    let RelayOutboundStepV1::Acked {
        message_type: outer_kind,
        next_sequence,
        ..
    } = delivered
    else {
        panic!("the Relay must deliver and acknowledge a well-formed outer envelope");
    };
    assert_eq!(outer_kind, message_type::ROUTE_TRANSPORT);
    assert_eq!(next_sequence, 1);
    assert_eq!(responder.ingest_mailbox(&relay, now())?.accepted, 1);

    // The Relay `AckV1` above is a delivery fact only.  The DSC1 `Ack` it
    // carried has no prepared Contracts authority and no derived redelivery
    // row, so it never becomes a Contracts transition: the inbox row stays
    // pending and the session revision does not move.
    let unprepared = responder
        .dispatch_inbound()
        .expect_err("a signed DSC1 Ack must never reach the Contracts Store as a transition");
    assert!(matches!(
        unprepared,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    drop(responder);

    // Restart may not reinterpret the retained row as an acknowledgement.
    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let mut responder = open_worker(temporary.path(), false, responder_store)?;
    let retried = responder
        .dispatch_inbound()
        .expect_err("restart must not manufacture a DSC1 Ack authority");
    assert!(matches!(
        retried,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    Ok(())
}

#[test]
fn inbound_outer_and_inner_sender_mismatch_remains_durably_pending() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;

    // Bypass the worker's outbound guard with a lower-level sender authority:
    // the outer envelope is validly signed by INITIATOR while the inner DSC1
    // message names and is validly signed by RESPONDER.
    let inner = signed_inner(
        &fixture,
        MessageTypeV1::Offer,
        1,
        0,
        initial.transcript_hash(),
        EarlyTermsBindingV1::new(EarlyTermsMessageKindV1::Offer, [0x82; 32])?
            .to_bytes()
            .to_vec(),
    )?;
    let malicious_config = DurableRelaySenderConfigV1::new(
        [0xe1; 32],
        wire(),
        INITIATOR,
        RESPONDER,
        SenderRoleV1::Initiator,
        xonly(&INITIATOR_RELAY_SECRET),
        4,
    )?;
    let mut malicious_sender = DurableRelaySenderV1::create(
        &temporary.path().join("mismatched-sender"),
        malicious_config,
        INITIATOR_RELAY_SECRET,
        [0xe2; 32],
    )?;
    malicious_sender.prepare_message(
        message_type::ROUTE_TRANSPORT,
        &inner,
        expiry(),
        [0xe3; 32],
    )?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;
    malicious_sender.submit_pending(&mut relay)?;
    assert_eq!(responder.ingest_mailbox(&relay, now())?.accepted, 1);

    let mismatch = responder
        .dispatch_inbound()
        .expect_err("outer and inner authenticated senders differ");
    assert!(matches!(
        mismatch,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::SenderMismatch
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    drop(responder);

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let mut responder = open_worker(temporary.path(), false, responder_store)?;
    let mismatch = responder
        .dispatch_inbound()
        .expect_err("restart must not reinterpret the cross-identity payload");
    assert!(matches!(
        mismatch,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::SenderMismatch
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    Ok(())
}

// --- FinalClaim (`0x12`) receiver-lane matrix -------------------------------
//
// Four adversarial rows around the `FinalClaimIngressV2` ingress variant.
// Each row carries at least one assertion that fails if the row is weakened,
// because the shared cells (`UnpreparedMessage`, `pending_route == 1`,
// `revision == 0`) already hold for six other variants and would let a row
// shrink to green without anyone noticing.

/// B1: a `0x12` with no installed ingress capability stays durably pending.
///
/// Discriminating cell: `take_contracts_ingress()` must still be `None`.  The
/// refusal path must not leave a capability behind, and that is the one
/// assertion here that a weakened row cannot keep while still passing.
#[test]
fn final_claim_0x12_without_its_ingress_authority_stays_durably_pending(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let mut initiator = TestPeerOutbound::create(temporary.path(), true, initiator_store)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    let final_claim = signed_inner(
        &fixture,
        MessageTypeV1::FinalClaim,
        0,
        0,
        initial.transcript_hash(),
        b"canonical-transaction-bytes-without-an-observation".to_vec(),
    )?;
    initiator.prepare_signed_dsc1(&final_claim, expiry())?;
    initiator.submit_outbound_once(&mut relay)?;
    assert_eq!(responder.ingest_mailbox(&relay, now())?.accepted, 1);

    let unprepared = responder
        .dispatch_inbound()
        .expect_err("a 0x12 without its Store-issued ingress capability must not transition");
    assert!(matches!(
        unprepared,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    assert!(
        responder.take_contracts_ingress().is_none(),
        "refusing an unauthorized 0x12 must not install a capability"
    );
    Ok(())
}

/// B2: the refusal above leaves the irreversible cryptographic state byte
/// identical across a restart.
///
/// Discriminating cell: `SessionIrreversibleV1` compared whole, before and
/// after.  A row that only re-asserted `UnpreparedMessage` would not see a
/// refused `0x12` that had set `adaptor_secret_exposed` or bumped the nonce
/// epoch as a side effect, which is the failure this row exists to exclude.
#[test]
fn refused_final_claim_0x12_leaves_irreversible_state_identical_across_restart(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let initiator_store = create_contracts_store(temporary.path(), "contracts-a", &fixture)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let before: SessionIrreversibleV1 = responder_store.load_session(SESSION)?.irreversible();
    assert!(
        !before.adaptor_secret_exposed,
        "the receiver lane must start with an unexposed adaptor secret"
    );
    let mut initiator = TestPeerOutbound::create(temporary.path(), true, initiator_store)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;

    let final_claim = signed_inner(
        &fixture,
        MessageTypeV1::FinalClaim,
        0,
        0,
        initial.transcript_hash(),
        b"canonical-transaction-bytes-without-an-observation".to_vec(),
    )?;
    initiator.prepare_signed_dsc1(&final_claim, expiry())?;
    initiator.submit_outbound_once(&mut relay)?;
    assert_eq!(responder.ingest_mailbox(&relay, now())?.accepted, 1);
    assert!(responder.dispatch_inbound().is_err());
    drop(responder);

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let after: SessionIrreversibleV1 = responder_store.load_session(SESSION)?.irreversible();
    assert_eq!(
        before, after,
        "a refused 0x12 must not move any irreversible flag or the nonce epoch"
    );
    let mut responder = open_worker(temporary.path(), false, responder_store)?;
    let retried = responder
        .dispatch_inbound()
        .expect_err("restart must not manufacture a FinalClaim ingress capability");
    assert!(matches!(
        retried,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::UnpreparedMessage
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    Ok(())
}

/// B7: the FinalClaim capability is linear -- a second install is refused and
/// the first survives intact.
///
/// Discriminating cell: after the refusal the retained capability must still
/// unwrap as the *early* authority through `into_early`.  A row asserting only
/// `AuthorityAlreadyInstalled` would still pass if the refusal had swapped or
/// dropped the installed capability.
///
/// NOT COVERED HERE, and deliberately not faked: the two identity predicates
/// (`final_claim_receiver_id == local_participant` and
/// `dom_claim_sender_id == remote_participant`).  Exercising them needs a real
/// `PreparedOperationalFinalClaimIngressAuthorityV2`, which only
/// `prepare_operational_final_claim_ingress_authority_v2` mints, and that
/// requires a durable observation record whose sole writer
/// (`revalidate_final_claim_chain_observation_v2`) has no caller outside the
/// Store's own `#[cfg(test)]`.  Until the receiver-side observation path is
/// productive, those two cells have no material and this row covers linearity
/// only.
#[test]
fn a_second_install_over_a_live_final_claim_lane_is_refused_and_keeps_the_first(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let installed = issue_early_authority(&responder_store, &fixture)?;
    let usurper = issue_early_authority(&responder_store, &fixture)?;
    let mut responder = create_worker(temporary.path(), false, responder_store)?;

    responder.install_contracts_ingress(PreparedContractsIngressV1::early(installed))?;
    let already = responder
        .install_contracts_ingress(PreparedContractsIngressV1::early(usurper))
        .expect_err("a linear capability must be taken before another is installed");
    assert!(matches!(
        already,
        ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled
    ));
    assert_eq!(responder.contracts_session_status()?.revision, 0);

    let retained = responder
        .take_contracts_ingress()
        .expect("a refused second install must leave the first capability installed");
    let retained = match retained.into_final_claim_ingress_v2() {
        Ok(_) => panic!("an early authority must not unwrap as the FinalClaim ingress lane"),
        Err(retained) => retained,
    };
    assert!(
        retained.into_early().is_ok(),
        "the surviving capability must be the exact one installed first"
    );
    assert!(
        responder.take_contracts_ingress().is_none(),
        "taking a linear capability twice must not produce a second one"
    );
    Ok(())
}

/// B8: a `0x12` whose outer Relay sender differs from its inner DSC1 signer is
/// refused as `SenderMismatch` and never reaches the Contracts Store.
///
/// Discriminating cell: the refusal is asserted as `SenderMismatch`
/// specifically, never as `is_err()`.  `SenderMismatch` is raised at
/// `accept_signed_dsc1` before any authority is consulted and before any Store
/// read of the payload, so an `is_err()` row here would also pass on
/// `UnpreparedMessage` and would stop distinguishing a cross-identity forgery
/// from an ordinary unauthorized claim.
#[test]
fn final_claim_0x12_with_crossed_outer_and_inner_senders_never_reaches_the_store(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let initial = initial_record()?;
    let fixture = EarlyFixture::new(&initial)?;
    let responder_store = create_contracts_store(temporary.path(), "contracts-b", &fixture)?;
    let before: SessionIrreversibleV1 = responder_store.load_session(SESSION)?.irreversible();
    let mut responder = create_worker(temporary.path(), false, responder_store)?;

    // Outer envelope validly signed by INITIATOR; the inner 0x12 names and is
    // validly signed by RESPONDER.  Both signatures verify in isolation.
    let inner = signed_inner(
        &fixture,
        MessageTypeV1::FinalClaim,
        1,
        0,
        initial.transcript_hash(),
        b"canonical-transaction-bytes-signed-by-the-other-leg".to_vec(),
    )?;
    let malicious_config = DurableRelaySenderConfigV1::new(
        [0xe4; 32],
        wire(),
        INITIATOR,
        RESPONDER,
        SenderRoleV1::Initiator,
        xonly(&INITIATOR_RELAY_SECRET),
        4,
    )?;
    let mut malicious_sender = DurableRelaySenderV1::create(
        &temporary.path().join("mismatched-final-claim-sender"),
        malicious_config,
        INITIATOR_RELAY_SECRET,
        [0xe5; 32],
    )?;
    malicious_sender.prepare_message(
        message_type::ROUTE_TRANSPORT,
        &inner,
        expiry(),
        [0xe6; 32],
    )?;
    let relay_root = temporary.path().join("relay");
    let mut relay = create_relay(&relay_root, false)?;
    malicious_sender.submit_pending(&mut relay)?;
    assert_eq!(responder.ingest_mailbox(&relay, now())?.accepted, 1);

    let mismatch = responder
        .dispatch_inbound()
        .expect_err("outer and inner authenticated senders of a 0x12 differ");
    assert!(matches!(
        mismatch,
        RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
            FramedContractsTransportErrorV2::Contracts(
                ContractsRelayIngressErrorV1::SenderMismatch
            )
        ))
    ));
    assert_eq!(responder.inbox_stats()?.pending_route, 1);
    assert_eq!(responder.contracts_session_status()?.revision, 0);
    assert!(
        responder.take_contracts_ingress().is_none(),
        "a cross-identity 0x12 must not install a capability"
    );
    drop(responder);

    let responder_store = open_contracts_store(temporary.path(), "contracts-b")?;
    let after: SessionIrreversibleV1 = responder_store.load_session(SESSION)?.irreversible();
    assert_eq!(
        before, after,
        "a cross-identity 0x12 must not leave an exposure marker behind"
    );
    Ok(())
}

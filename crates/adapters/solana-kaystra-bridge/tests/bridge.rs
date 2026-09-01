//! Adversarial coverage of the DOM-claim -> Solana-Claim bridge: exactly one
//! durable transaction per settlement, byte-for-byte retransmission, witness
//! hygiene after durability, and rejection of everything that is not this
//! settlement's claim.

use std::sync::{Arc, Mutex};

use counterparty_api::RevealedSecretBytes;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::{
    settlement_engine::EffectOutcome,
    state::{Effect, EvidenceRefV1},
    store_port::ClaimedEffectV1,
    types::{
        AssetId, ChainId, EffectId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
        LockMechanism, ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId,
        TimelockSpec,
    },
};
use solana_delivery::{DeliveryState, DeliveryStore, MemoryDeliveryStore};
use solana_kaystra_bridge::{
    BuiltClaimV1, ClaimBuildPort, ClaimPortError, ExactBroadcastPort, SolanaClaimSink,
};
use solana_profile::{
    SolanaAdapterProfileV1, SolanaAssetV1, SolanaNetwork, SolanaProofContextV1,
    ValidatedSolanaSetup,
};
use solana_secret_store::{
    EncryptedSqliteWitnessStore, SecretStoreError, SecretStoreMasterKey, WitnessMaterialStore,
};
use solana_session_init::{finalize_session, persist_route_witness, prepare_route_secret};
use solana_setup_store::SolanaSetupStore;
use solana_types::{SolanaPubkey, SolanaSignature};

const SETTLEMENT: [u8; 32] = [1; 32];

struct Fixture {
    setup: ValidatedSolanaSetup,
    revealed_secret_be: [u8; 32],
    secrets: EncryptedSqliteWitnessStore,
    _directory: tempfile::TempDir,
}

fn terms(adaptor: [u8; 33], profile_hash: [u8; 32], funder: SolanaPubkey) -> SettlementTermsV1 {
    let recipient = ParticipantId([0x31; 32]);
    let refund = ParticipantId([0x21; 32]);
    SettlementTermsV1 {
        settlement_id: SettlementId(SETTLEMENT),
        session_id: SessionId([2; 32]),
        intent_hash: IntentHash([3; 32]),
        solver_id: SolverId([4; 32]),
        roster: [refund, recipient],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId([0xD0; 32]),
            asset_id: AssetId([0xD1; 32]),
            amount: 500,
            beneficiary: refund,
            refund_to: recipient,
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 1_000 },
            finality: FinalityPolicyV1 {
                min_confirmations: 10,
                max_reorg_depth: 20,
            },
            adapter_profile_hash: [0xD2; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId([0x51; 32]),
            asset_id: AssetId([0x52; 32]),
            amount: 500,
            beneficiary: recipient,
            refund_to: refund,
            mechanism: LockMechanism::CrossCurveConditionLock,
            deadline: TimelockSpec::TimestampSeconds {
                value: 2_000_000_000,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 32,
            },
            adapter_profile_hash: profile_hash,
        },
        adaptor_point_sec1: adaptor,
        fee_limit: FeeLimitV1 {
            dom_max: 50,
            counterparty_max: 50,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 1_000,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: funder.0.to_vec(),
    }
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut rng = rand::thread_rng();
    let funder = SolanaPubkey([0x77; 32]);
    let program = SolanaPubkey([0x3a; 32]);
    let profile =
        SolanaAdapterProfileV1::new(SolanaNetwork::LocalValidator, program, 3, 2).expect("profile");
    let context = SolanaProofContextV1 {
        settlement_id: SETTLEMENT,
        chain_id: [0x51; 32],
        asset_id: [0x52; 32],
        amount: 500,
        beneficiary: [0x31; 32],
        refund_to: [0x21; 32],
        refund_after_unix: 2_000_000_000,
        min_confirmations: 1,
        max_reorg_depth: 32,
        asset: SolanaAssetV1::NativeSol,
        funder,
    };
    let route = prepare_route_secret(&profile, &context, &mut rng).expect("route secret");
    let revealed_secret_be = route.with_revealed_dom_secret(|r| r.expose_scalar_bytes());
    let frozen = terms(route.dom_adaptor_point().0, profile.profile_hash(), funder);
    let setup_store =
        SolanaSetupStore::open(directory.path().join("setup.sqlite")).expect("setup store");
    let session = finalize_session(
        &profile,
        &frozen,
        SolanaAssetV1::NativeSol,
        funder,
        [0xA5; 32],
        route,
        &setup_store,
    )
    .expect("session");
    let secrets = EncryptedSqliteWitnessStore::open(
        directory.path().join("witness.sqlite"),
        SecretStoreMasterKey::new([9; 32]).expect("key"),
    )
    .expect("witness store");
    persist_route_witness(&session, &secrets, &mut rng).expect("persist witness");
    Fixture {
        setup: session.setup().clone(),
        revealed_secret_be,
        secrets,
        _directory: directory,
    }
}

fn effect(evidence: EvidenceRefV1) -> ClaimedEffectV1 {
    ClaimedEffectV1 {
        settlement_id: SettlementId(SETTLEMENT),
        effect_id: EffectId([0x42; 32]),
        kind: Effect::RequestClaimConsumption { evidence },
        payload: Vec::new(),
        payload_hash: [0x24; 32],
        attempts: 1,
    }
}

fn evidence() -> EvidenceRefV1 {
    EvidenceRefV1 {
        chain_id: ChainId([0xD0; 32]),
        tx_id: [0x33; 32],
        event_index: 0,
        block_height: 100,
        block_anchor: [0x44; 32],
    }
}

fn well_formed_raw(signature: SolanaSignature) -> Vec<u8> {
    let mut raw = vec![1u8];
    raw.extend_from_slice(&signature.0);
    raw.extend_from_slice(b"legacy-message-bytes");
    raw
}

#[derive(Default)]
struct BuilderLog {
    calls: usize,
}

struct ScriptedBuilder {
    log: Arc<Mutex<BuilderLog>>,
    tamper_nonce: bool,
    tamper_signature: bool,
}

impl ClaimBuildPort for ScriptedBuilder {
    fn build_claim(
        &mut self,
        request_nonce: [u8; 32],
        _setup: &ValidatedSolanaSetup,
        _revealed_secret_be: [u8; 32],
    ) -> Result<BuiltClaimV1, ClaimPortError> {
        self.log.lock().unwrap().calls += 1;
        let signature = SolanaSignature([0x66; 64]);
        let raw_transaction = well_formed_raw(signature);
        let mut nonce = request_nonce;
        if self.tamper_nonce {
            nonce[0] ^= 1;
        }
        let signature = if self.tamper_signature {
            SolanaSignature([0x67; 64])
        } else {
            signature
        };
        Ok(BuiltClaimV1 {
            request_nonce: nonce,
            raw_transaction,
            signature,
        })
    }
}

#[derive(Default)]
struct BroadcastLog {
    submissions: Vec<(SolanaSignature, Vec<u8>)>,
    fail_first: bool,
}

struct ScriptedBroadcaster {
    log: Arc<Mutex<BroadcastLog>>,
}

impl ExactBroadcastPort for ScriptedBroadcaster {
    fn submit_exact(
        &mut self,
        signature: SolanaSignature,
        raw_transaction: &[u8],
    ) -> Result<(), ClaimPortError> {
        let mut log = self.log.lock().unwrap();
        if log.fail_first {
            log.fail_first = false;
            return Err(ClaimPortError::Retryable);
        }
        log.submissions.push((signature, raw_transaction.to_vec()));
        Ok(())
    }
}

#[allow(clippy::type_complexity)]
fn sink(
    fixture: Fixture,
    tamper_nonce: bool,
    tamper_signature: bool,
    fail_first_broadcast: bool,
) -> (
    SolanaClaimSink<
        EncryptedSqliteWitnessStore,
        MemoryDeliveryStore,
        ScriptedBuilder,
        ScriptedBroadcaster,
    >,
    Arc<Mutex<BuilderLog>>,
    Arc<Mutex<BroadcastLog>>,
    [u8; 32],
) {
    let builder_log = Arc::new(Mutex::new(BuilderLog::default()));
    let broadcast_log = Arc::new(Mutex::new(BroadcastLog {
        fail_first: fail_first_broadcast,
        ..BroadcastLog::default()
    }));
    let revealed = fixture.revealed_secret_be;
    let sink = SolanaClaimSink::new(
        fixture.setup,
        fixture.secrets,
        MemoryDeliveryStore::default(),
        ScriptedBuilder {
            log: builder_log.clone(),
            tamper_nonce,
            tamper_signature,
        },
        ScriptedBroadcaster {
            log: broadcast_log.clone(),
        },
    );
    (sink, builder_log, broadcast_log, revealed)
}

#[test]
fn happy_path_journals_broadcasts_and_deletes_the_witness() {
    let fixture = fixture();
    let terms_hash = fixture.setup.terms_hash();
    let (mut sink, builder_log, broadcast_log, revealed) = sink(fixture, false, false, false);
    let outcome = solana_claim(&mut sink, revealed);
    assert_eq!(outcome, EffectOutcome::Completed);
    assert_eq!(builder_log.lock().unwrap().calls, 1);
    let submissions = &broadcast_log.lock().unwrap().submissions;
    assert_eq!(submissions.len(), 1);

    let (secrets, delivery, _, _) = sink.ports();
    let record = delivery.load(&SETTLEMENT).expect("load").expect("record");
    assert_eq!(record.state, DeliveryState::Submitted);
    assert_eq!(record.raw_transaction, submissions[0].1);
    assert_eq!(record.signature, submissions[0].0);
    // Witness hygiene: deleted once the exact bytes were durable.
    assert_eq!(
        secrets.load(&SETTLEMENT, &terms_hash).unwrap_err(),
        SecretStoreError::NotFound
    );
}

#[test]
fn replay_after_submission_is_idempotent_without_a_second_broadcast() {
    let fixture = fixture();
    let (mut sink, builder_log, broadcast_log, revealed) = sink(fixture, false, false, false);
    assert_eq!(solana_claim(&mut sink, revealed), EffectOutcome::Completed);
    assert_eq!(solana_claim(&mut sink, revealed), EffectOutcome::Completed);
    assert_eq!(builder_log.lock().unwrap().calls, 1, "no rebuild on replay");
    assert_eq!(broadcast_log.lock().unwrap().submissions.len(), 1);
}

#[test]
fn a_retryable_broadcast_retries_the_exact_journalled_bytes() {
    let fixture = fixture();
    let (mut sink, builder_log, broadcast_log, revealed) = sink(fixture, false, false, true);
    assert_eq!(solana_claim(&mut sink, revealed), EffectOutcome::RetryLater);
    let journalled = {
        let (_, delivery, _, _) = sink.ports();
        let record = delivery.load(&SETTLEMENT).expect("load").expect("record");
        assert_eq!(record.state, DeliveryState::Prepared);
        record.raw_transaction
    };
    // The retry consumes the journal, not the builder.
    assert_eq!(solana_claim(&mut sink, revealed), EffectOutcome::Completed);
    assert_eq!(
        builder_log.lock().unwrap().calls,
        1,
        "one build, two attempts"
    );
    let submissions = &broadcast_log.lock().unwrap().submissions;
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].1, journalled, "byte-for-byte retransmission");
}

#[test]
fn a_foreign_or_malformed_revelation_is_rejected_before_any_port_runs() {
    let fixture = fixture();
    let (mut sink, builder_log, broadcast_log, _) = sink(fixture, false, false, false);
    // A scalar that opens no registered claim.
    assert_eq!(solana_claim(&mut sink, [0x55; 32]), EffectOutcome::Rejected);
    assert_eq!(builder_log.lock().unwrap().calls, 0);
    assert!(broadcast_log.lock().unwrap().submissions.is_empty());
}

#[test]
fn the_wrong_settlement_and_the_wrong_effect_kind_are_rejected() {
    let fixture = fixture();
    let (mut sink, _, _, revealed) = sink(fixture, false, false, false);
    let mut foreign = effect(evidence());
    foreign.settlement_id = SettlementId([9; 32]);
    assert_eq!(
        sink_consume(&mut sink, foreign, revealed),
        EffectOutcome::Rejected
    );
    let mut wrong_evidence = effect(evidence());
    wrong_evidence.kind = Effect::RequestClaimConsumption {
        evidence: EvidenceRefV1 {
            tx_id: [0x99; 32],
            ..evidence()
        },
    };
    assert_eq!(
        sink_consume(&mut sink, wrong_evidence, revealed),
        EffectOutcome::Rejected
    );
}

#[test]
fn a_builder_that_tampers_nonce_or_signature_is_rejected() {
    for (tamper_nonce, tamper_signature) in [(true, false), (false, true)] {
        let fixture = fixture();
        let (mut sink, _, broadcast_log, revealed) =
            sink(fixture, tamper_nonce, tamper_signature, false);
        assert_eq!(solana_claim(&mut sink, revealed), EffectOutcome::Rejected);
        assert!(broadcast_log.lock().unwrap().submissions.is_empty());
    }
}

fn solana_claim(
    sink: &mut SolanaClaimSink<
        EncryptedSqliteWitnessStore,
        MemoryDeliveryStore,
        ScriptedBuilder,
        ScriptedBroadcaster,
    >,
    revealed: [u8; 32],
) -> EffectOutcome {
    sink_consume(sink, effect(evidence()), revealed)
}

fn sink_consume(
    sink: &mut SolanaClaimSink<
        EncryptedSqliteWitnessStore,
        MemoryDeliveryStore,
        ScriptedBuilder,
        ScriptedBroadcaster,
    >,
    claimed: ClaimedEffectV1,
    revealed: [u8; 32],
) -> EffectOutcome {
    use adapter_dom_real::RevealedSecretSinkV1;
    let Effect::RequestClaimConsumption { evidence } = claimed.kind else {
        unreachable!("fixture only builds claim consumption");
    };
    let claimed = ClaimedEffectV1 {
        kind: Effect::RequestClaimConsumption { evidence },
        ..claimed
    };
    sink.consume_revealed_secret(
        &claimed,
        &self::evidence(),
        &RevealedSecretBytes::new(revealed),
    )
}

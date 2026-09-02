use super::*;

use std::error::Error;
use std::fs::File;
use std::path::Path;

use dom_adaptor::initial_transcript_hash_v1;
use dom_core::Hash256;
use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};
use dom_scriptless_store::{
    SessionChainProjectionV1, SessionIrreversibleV1, SessionRecordFieldsV1, SessionRecordV1,
    SessionTxObservationV1, BUDGET_POLICY_LEN,
};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const NETWORK_MAGIC: u32 = 0x5031_3037;
const GENESIS_HASH: [u8; 32] = [0x71; 32];
const SESSION_ID: [u8; 32] = [0x77; 32];
const TERMS_HASH: [u8; 32] = [0x78; 32];
const TIP_ID: [u8; 32] = [0x79; 32];
const REFUND_LOCK_HEIGHT: u64 = 144;
const SESSION_ROOT: &str = "sessions";
const NONCE_ROOTS: [&str; 2] = ["nonce-a", "nonce-b"];
const IDENTITY_ROOTS: [&str; 2] = ["identity-a", "identity-b"];

fn production_policy() -> TestResult<BudgetPolicyV1> {
    let mut bytes = [0_u8; BUDGET_POLICY_LEN];
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

fn parent_capability(path: &Path) -> TestResult<Arc<Dir>> {
    Ok(Arc::new(Dir::from_std_file(File::open(path)?)))
}

fn nonce_passphrase(index: usize) -> TestResult<Passphrase> {
    Ok(Passphrase::new(
        format!("f7-production-nonce-passphrase-{index}").into_bytes(),
    )?)
}

fn identity_passphrase(index: usize) -> TestResult<ContractsIdentityPassphraseV1> {
    Ok(ContractsIdentityPassphraseV1::new(
        format!("f7-production-identity-passphrase-{index}").into_bytes(),
    )?)
}

fn storage_ids(index: usize) -> TestResult<StorageIdsV1> {
    let marker = u8::try_from(index)?;
    Ok(StorageIdsV1::new([0x31 + marker; 32], [0x41 + marker; 32])?)
}

fn create_participant(
    parent: Arc<Dir>,
    index: usize,
    policy: BudgetPolicyV1,
) -> TestResult<F7ProductionParticipantAuthoritiesV1> {
    let nonce_passphrase = nonce_passphrase(index)?;
    let identity_passphrase = identity_passphrase(index)?;
    Ok(F7ProductionParticipantAuthoritiesV1::create_production(
        parent,
        NONCE_ROOTS[index],
        IDENTITY_ROOTS[index],
        storage_ids(index)?,
        &nonce_passphrase,
        &identity_passphrase,
        policy,
    )?)
}

fn open_participant(
    parent: Arc<Dir>,
    index: usize,
    policy: BudgetPolicyV1,
) -> TestResult<F7ProductionParticipantAuthoritiesV1> {
    let identity_passphrase = identity_passphrase(index)?;
    Ok(F7ProductionParticipantAuthoritiesV1::open_production(
        parent,
        NONCE_ROOTS[index],
        IDENTITY_ROOTS[index],
        nonce_passphrase(index)?,
        &identity_passphrase,
        policy,
    )?)
}

fn trusted_chain_id() -> TrustedChainIdV1 {
    TrustedChainIdV1::from_authenticated_genesis(NETWORK_MAGIC, &Hash256::from_bytes(GENESIS_HASH))
}

fn small_scalar(marker: u8) -> [u8; 32] {
    let mut scalar = [0_u8; 32];
    scalar[31] = marker;
    scalar
}

fn signing_share_bytes() -> TestResult<[[u8; 32]; 2]> {
    let candidates = [small_scalar(7), small_scalar(9)];
    let mut ordered = [
        (
            SigningShareV1::from_be_bytes(candidates[0])?
                .public_key()
                .to_compressed_bytes(),
            candidates[0],
        ),
        (
            SigningShareV1::from_be_bytes(candidates[1])?
                .public_key()
                .to_compressed_bytes(),
            candidates[1],
        ),
    ];
    ordered.sort_by_key(|entry| entry.0);
    Ok([ordered[0].1, ordered[1].1])
}

fn signing_shares() -> TestResult<[SigningShareV1; 2]> {
    let bytes = signing_share_bytes()?;
    Ok([
        SigningShareV1::from_be_bytes(bytes[0])?,
        SigningShareV1::from_be_bytes(bytes[1])?,
    ])
}

fn signing_keys() -> TestResult<[PublicKey; 2]> {
    let shares = signing_shares()?;
    Ok([
        shares[0].public_key().clone(),
        shares[1].public_key().clone(),
    ])
}

fn roster_for_composition(
    composition: &F7ProductionContractsCompositionV1,
    chain: &TrustedChainIdV1,
) -> TestResult<ParticipantRosterV1> {
    let keys = signing_keys()?;
    let layout = composition.participant_layout()?;
    let mut entries = Vec::with_capacity(2);
    // `index` is the canonical participant index and selects both the
    // authority slot and the signing key.
    #[allow(clippy::needless_range_loop)]
    for index in 0..2 {
        let authority_slot = layout.canonical_to_authority[index];
        let identity = PublicKey::from_compressed_bytes(
            composition
                .participant_identity_store(u16::try_from(authority_slot)?)?
                .reference()
                .schnorr_public_key(),
        )?;
        let entry = ParticipantIdentityV1::new(
            chain,
            identity,
            keys[index].clone(),
            layout.directions[index],
        )?;
        if entry.participant_id() != &layout.roster[index] {
            return Err(std::io::Error::other("canonical roster identity changed").into());
        }
        entries.push(entry);
    }
    Ok(ParticipantRosterV1::new(entries)?)
}

fn transaction_template() -> TestResult<dom_consensus::Transaction> {
    let keys = signing_keys()?;
    let aggregate = aggregate_public_nonces_v1(&keys)?;
    Ok(dom_consensus::Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_HEIGHT_LOCKED,
            fee: Amount::ZERO,
            lock_height: REFUND_LOCK_HEIGHT,
            excess: Commitment::from_compressed_bytes(&aggregate.to_compressed_bytes())?,
            excess_signature: [0; 65],
        }],
        offset: small_scalar(11),
    })
}

fn initial_record(roster: &ParticipantRosterV1) -> TestResult<SessionRecordV1> {
    let transcript = initial_transcript_hash_v1(
        &trusted_chain_id(),
        &SESSION_ID,
        ContractKindV1::WitnessOrTimeout,
        roster,
    );
    Ok(SessionRecordV1::new(
        SessionRecordFieldsV1 {
            session_id: SESSION_ID,
            revision: 0,
            // The hardened store only creates sessions at `Created`; the
            // fixture then advances to `TemplatesCommitted` through the real
            // dual template-commit accepts below.
            phase: SessionPhaseV1::Created,
            terms_hash: TERMS_HASH,
            transcript_hash: transcript,
            irreversible: SessionIrreversibleV1 {
                any_signing_share_sent: false,
                funding_authorized: false,
                adaptor_secret_exposed: false,
                nonce_epoch: 1,
            },
            chain: SessionChainProjectionV1 {
                tip_id: TIP_ID,
                tip_height: 1,
                funding: SessionTxObservationV1::Unknown,
                claim: SessionTxObservationV1::Unknown,
                refund: SessionTxObservationV1::Unknown,
            },
        },
        &[],
    )?)
}

fn create_composition(path: &Path) -> TestResult<F7ProductionContractsCompositionV1> {
    let parent = parent_capability(path)?;
    let policy = production_policy()?;
    let participants = [
        create_participant(Arc::clone(&parent), 0, policy.clone())?,
        create_participant(Arc::clone(&parent), 1, policy.clone())?,
    ];
    Ok(F7ProductionContractsCompositionV1::create_production(
        parent,
        SESSION_ROOT,
        policy,
        NETWORK_MAGIC,
        GENESIS_HASH,
        *trusted_chain_id().as_bytes(),
        participants,
    )?)
}

fn open_composition(path: &Path) -> TestResult<F7ProductionContractsCompositionV1> {
    let parent = parent_capability(path)?;
    let policy = production_policy()?;
    let participants = [
        open_participant(Arc::clone(&parent), 0, policy.clone())?,
        open_participant(Arc::clone(&parent), 1, policy.clone())?,
    ];
    Ok(F7ProductionContractsCompositionV1::open_production(
        parent,
        SESSION_ROOT,
        policy,
        NETWORK_MAGIC,
        GENESIS_HASH,
        *trusted_chain_id().as_bytes(),
        participants,
    )?)
}

fn identity_store_for_reference<'a>(
    composition: &'a F7ProductionContractsCompositionV1,
    reference: &SessionTransportIdentityReferenceV1,
) -> TestResult<&'a ContractsTransportIdentityStoreV1> {
    for index in 0..2 {
        let store = composition.participant_identity_store(u16::try_from(index)?)?;
        if store.reference().key_reference() == reference.key_reference() {
            return Ok(store);
        }
    }
    Err(std::io::Error::other("retained identity reference has no owner").into())
}

// ─── Stage-12 recontract ────────────────────────────────────────────────────
// The durable-execution hardening closed the caller-successor ingress for
// message types `0x0b` and later in EVERY profile: `TxTemplateCommit` and the
// signing rounds now require the prepared operational authority ladder
// (early → collaborative-BP → template → signing). The legacy pair rounds
// this suite drove through `accept_transport_message` are therefore asserted
// to REFUSE — fail closed, with the retained journal unchanged — while the
// durable gap/equivocation/restart properties those rounds also exercised
// are covered by the session store's own hardened suite. Driving the F7
// pair composition through the prepared ladder is the remaining
// reintegration work; it merges with the composed-route initiator harness,
// which needs the same authorities.

#[test]
fn hardened_store_refuses_legacy_template_commit_ingress() -> TestResult {
    let temporary = TempDir::new()?;
    let composition = create_composition(temporary.path())?;
    let roster = roster_for_composition(&composition, &trusted_chain_id())?;
    let initial = initial_record(&roster)?;
    composition.session_store().create_session(&initial)?;
    let context = composition.bind_operational_transport(SESSION_ID, signing_keys()?)?;
    if context.roster() != &roster {
        return Err(std::io::Error::other("production roster binding changed").into());
    }

    let transaction = transaction_template()?;
    let (_, template_hash) = canonical_template_v1(&transaction)?;
    let mut payload = [0_u8; 160];
    payload[..32].copy_from_slice(&template_hash);
    payload[32..64].copy_from_slice(&template_hash);
    payload[64..96].copy_from_slice(&template_hash);
    payload[96..128].copy_from_slice(&TERMS_HASH);
    payload[128..].copy_from_slice(&[0x7a; 32]);

    let store = composition.session_store();
    let references = store.transport_identity_references(SESSION_ID)?;
    let sender = &references[0];
    let identity_store = identity_store_for_reference(&composition, sender)?;
    let current = store.load_session(SESSION_ID)?;
    let unsigned = UnsignedMessageV1::new(
        MessageTypeV1::TxTemplateCommit,
        *context.trusted_chain_id(),
        SESSION_ID,
        *sender.participant_id(),
        0,
        current.transcript_hash(),
        payload.to_vec(),
    )?;
    let signed = identity_store.sign_exact_dsc1_for_session(unsigned, sender)?;
    let successor = current.advance(
        current.revision(),
        SessionPhaseV1::TemplatesCommitted,
        current.transcript_hash(),
        current.irreversible(),
        current.chain(),
        current.encrypted_payload(),
    )?;

    // The generic evidence ingress refuses the operational boundary outright.
    if !matches!(
        store.accept_transport_message(signed.as_bytes(), &successor, None),
        Err(SessionStoreError::InvalidTransition)
    ) {
        return Err(std::io::Error::other("legacy 0x0b ingress was not refused").into());
    }
    // The refusal left no durable trace.
    if store.load_session(SESSION_ID)?.as_bytes() != current.as_bytes() {
        return Err(std::io::Error::other("refused ingress mutated the Store").into());
    }
    // And the untouched session record survives a full journal restart.
    drop(context);
    drop(composition);
    let reopened = open_composition(temporary.path())?;
    if reopened
        .session_store()
        .load_session(SESSION_ID)?
        .as_bytes()
        != current.as_bytes()
    {
        return Err(std::io::Error::other("session record changed across restart").into());
    }
    Ok(())
}

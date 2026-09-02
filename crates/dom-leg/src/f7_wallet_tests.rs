use super::*;

use std::error::Error;
use std::fs::File;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;

use dom_adaptor::initial_transcript_hash_v1;
use dom_core::Hash256;
use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};
use dom_scriptless_store::{
    SessionChainProjectionV1, SessionIrreversibleV1, SessionRecordFieldsV1, SessionRecordV1,
    SessionTxObservationV1, BUDGET_POLICY_LEN,
};
use dom_scriptless_transport::{SessionReceiverV1, TransportParticipantV1};
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
const CRASH_ROOT_ENV: &str = "DOM_F7_DOM_LEG_STAGE_CRASH_ROOT";
const CRASH_PREFIX_ENV: &str = "DOM_F7_DOM_LEG_STAGE_CRASH_PREFIX";
const CRASH_CHILD_TEST: &str =
    "f7_wallet::f7_wallet_tests::production_refund_stage_prefix_crash_child";

struct OpenedFixture {
    composition: F7ProductionContractsCompositionV1,
    context: F7OperationalSigningContextV1,
    transaction: dom_consensus::Transaction,
}

struct CreatedFixture {
    opened: OpenedFixture,
    template_messages: [Vec<u8>; 2],
    template_initial_transcript: [u8; 32],
    template_payload: [u8; 160],
}

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

fn create_fixture(path: &Path) -> TestResult<CreatedFixture> {
    let composition = create_composition(path)
        .map_err(|error| std::io::Error::other(format!("create composition: {error}")))?;
    let roster = roster_for_composition(&composition, &trusted_chain_id())
        .map_err(|error| std::io::Error::other(format!("build roster: {error}")))?;
    let initial = initial_record(&roster)
        .map_err(|error| std::io::Error::other(format!("build initial record: {error}")))?;
    composition
        .session_store()
        .create_session(&initial)
        .map_err(|error| std::io::Error::other(format!("create session: {error}")))?;
    let context = composition
        .bind_operational_transport(
            SESSION_ID,
            signing_keys()
                .map_err(|error| std::io::Error::other(format!("load signing keys: {error}")))?,
        )
        .map_err(|error| std::io::Error::other(format!("bind operational transport: {error}")))?;
    if context.roster() != &roster {
        return Err(std::io::Error::other("production roster binding changed").into());
    }
    let transaction = transaction_template()
        .map_err(|error| std::io::Error::other(format!("build transaction: {error}")))?;
    let (template_messages, template_initial_transcript, template_payload) =
        persist_template_commits(&composition, &context, &transaction)
            .map_err(|error| std::io::Error::other(format!("persist template commits: {error}")))?;
    Ok(CreatedFixture {
        opened: OpenedFixture {
            composition,
            context,
            transaction,
        },
        template_messages,
        template_initial_transcript,
        template_payload,
    })
}

fn open_fixture(path: &Path) -> TestResult<OpenedFixture> {
    let composition = open_composition(path)?;
    let context = composition.bind_operational_transport(SESSION_ID, signing_keys()?)?;
    Ok(OpenedFixture {
        composition,
        context,
        transaction: transaction_template()?,
    })
}

fn transport_participants(
    context: &F7OperationalSigningContextV1,
) -> TestResult<[TransportParticipantV1; 2]> {
    let entries = context.roster().entries();
    Ok([
        TransportParticipantV1::new(
            *entries[0].participant_id(),
            entries[0].identity_public_key().clone(),
            entries[0].direction(),
        )?,
        TransportParticipantV1::new(
            *entries[1].participant_id(),
            entries[1].identity_public_key().clone(),
            entries[1].direction(),
        )?,
    ])
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

// The triple is the two commit payloads, the template hash, and the packed
// commit bytes; a named alias for a helper used once reads worse.
#[allow(clippy::type_complexity)]
fn persist_template_commits(
    composition: &F7ProductionContractsCompositionV1,
    context: &F7OperationalSigningContextV1,
    transaction: &dom_consensus::Transaction,
) -> TestResult<([Vec<u8>; 2], [u8; 32], [u8; 160])> {
    let (_, template_hash) = canonical_template_v1(transaction)?;
    let mut payload = [0_u8; 160];
    payload[..32].copy_from_slice(&template_hash);
    payload[32..64].copy_from_slice(&template_hash);
    payload[64..96].copy_from_slice(&template_hash);
    payload[96..128].copy_from_slice(&TERMS_HASH);
    payload[128..].copy_from_slice(&[0x7a; 32]);

    let store = composition.session_store();
    let mut current = store.load_session(SESSION_ID)?;
    let initial_transcript = current.transcript_hash();
    let mut receiver = SessionReceiverV1::new(
        *context.trusted_chain_id(),
        SESSION_ID,
        transport_participants(context)?,
        SessionPhaseV1::TemplatesCommitted,
        initial_transcript,
    )?;
    let references = store.transport_identity_references(SESSION_ID)?;
    let mut messages = Vec::with_capacity(2);
    for reference in &references {
        let identity_store = identity_store_for_reference(composition, reference)?;
        let unsigned = UnsignedMessageV1::new(
            MessageTypeV1::TxTemplateCommit,
            *context.trusted_chain_id(),
            SESSION_ID,
            *reference.participant_id(),
            0,
            current.transcript_hash(),
            payload.to_vec(),
        )?;
        let signed = identity_store.sign_exact_dsc1_for_session(unsigned, reference)?;
        let volatile = receiver.accept(signed.as_bytes(), SessionPhaseV1::TemplatesCommitted)?;
        let successor = current.advance(
            current.revision(),
            SessionPhaseV1::TemplatesCommitted,
            volatile.transcript_hash,
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        match store.accept_transport_message(signed.as_bytes(), &successor, None)? {
            DurableTransportOutcomeV1::Accepted(durable)
                if !durable.duplicate
                    && durable.message_digest == volatile.message_digest
                    && durable.transcript_hash == volatile.transcript_hash
                    && durable.sequence == 0
                    && durable.message_type == MessageTypeV1::TxTemplateCommit as u8 => {}
            _ => return Err(std::io::Error::other("template commit was not durable").into()),
        }
        messages.push(signed.as_bytes().to_vec());
        current = store.load_session(SESSION_ID)?;
    }
    if current.revision() != 2 || current.phase() != SessionPhaseV1::TemplatesCommitted {
        return Err(std::io::Error::other("template ancestry is incomplete").into());
    }
    let refund_signing = current.advance(
        current.revision(),
        SessionPhaseV1::RefundSigning,
        current.transcript_hash(),
        current.irreversible(),
        current.chain(),
        current.encrypted_payload(),
    )?;
    let refund_signing = store.advance_session(current.revision(), &refund_signing)?;
    if refund_signing.revision() != 3 || refund_signing.phase() != SessionPhaseV1::RefundSigning {
        return Err(std::io::Error::other("refund signing phase was not durable").into());
    }
    let messages: [Vec<u8>; 2] = messages
        .try_into()
        .map_err(|_| std::io::Error::other("template message count changed"))?;
    Ok((messages, initial_transcript, payload))
}

fn run_round(
    fixture: OpenedFixture,
    invocation: OperationalRoundInvocationV1,
) -> Result<OperationalRoundCompletionV1, F7WalletCompositorError> {
    let OpenedFixture {
        composition,
        context,
        transaction,
    } = fixture;
    let (store, participants, _) = composition.into_canonical_parts()?;
    let [first, second] = participants;
    let (first_vault, first_identity) = first.into_parts();
    let (second_vault, second_identity) = second.into_parts();
    let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
    complete_production_operational_round_with_fault_v1(
        &store,
        [&first_identity, &second_identity],
        [first_vault, second_vault],
        &context,
        PurposeV1::Refund,
        &transaction,
        None,
        signing_shares().map_err(|_| F7WalletCompositorError::Binding)?,
        None,
        invocation,
        &mut fault_controller,
    )
}

fn inspect_prefix(path: &Path, expected_len: usize) -> TestResult<Vec<Vec<u8>>> {
    let fixture = open_fixture(path)?;
    let accepted = fixture
        .composition
        .session_store()
        .resume_operational_signing_session(trusted_chain_id(), SESSION_ID, PurposeV1::Refund)?;
    let bases = *accepted.sender_sequence_bases();
    let messages: Vec<Vec<u8>> = accepted
        .accepted_signing_messages()
        .map(<[u8]>::to_vec)
        .collect();
    if messages.len() != expected_len {
        return Err(std::io::Error::other("unexpected durable signing prefix length").into());
    }
    let current = fixture
        .composition
        .session_store()
        .load_session(SESSION_ID)?;
    if current.phase() != SessionPhaseV1::RefundSigning
        || current.revision() != 3 + u64::try_from(expected_len)?
    {
        return Err(std::io::Error::other("signing prefix revision mismatch").into());
    }
    for (position, bytes) in messages.iter().enumerate() {
        let protocol_index = position % 2;
        let stage_index = position / 2;
        let expected_kind = match stage_index {
            0 => MessageTypeV1::SigNonceCommit,
            1 => MessageTypeV1::SigNonceReveal,
            2 => MessageTypeV1::PartialSignature,
            _ => return Err(std::io::Error::other("unexpected signing stage").into()),
        };
        let participant = &fixture.context.roster().entries()[protocol_index];
        let signed = SignedMessageV1::decode_exact(bytes)?;
        if signed.unsigned().kind() != expected_kind
            || signed.unsigned().sender_id() != participant.participant_id()
            || signed.unsigned().sequence() != bases[protocol_index] + u64::try_from(stage_index)?
        {
            return Err(std::io::Error::other("durable signing prefix is noncanonical").into());
        }
    }
    Ok(messages)
}

fn spawn_crash_child(root: &Path, cut: usize) -> TestResult {
    let status = Command::new(std::env::current_exe()?)
        .arg("--ignored")
        .arg("--exact")
        .arg(CRASH_CHILD_TEST)
        .arg("--nocapture")
        .env(CRASH_ROOT_ENV, root)
        .env(CRASH_PREFIX_ENV, cut.to_string())
        .status()?;
    if status.signal() != Some(6) {
        return Err(std::io::Error::other(format!(
            "crash child for cut {cut} did not terminate with SIGABRT: {status}"
        ))
        .into());
    }
    Ok(())
}

#[test]
#[ignore = "subprocess crash helper"]
fn production_refund_stage_prefix_crash_child() {
    let root = std::env::var_os(CRASH_ROOT_ENV).expect("crash fixture root is required");
    let fixture = create_fixture(Path::new(&root)).expect("production fixture must initialize");
    let _ = run_round(fixture.opened, OperationalRoundInvocationV1::Fresh)
        .expect("configured crash cut must abort before round completion");
    panic!("configured crash hook did not abort");
}

#[test]
fn production_refund_round_resumes_every_durable_prefix_without_remint() -> TestResult {
    for cut in 0..=6 {
        let temporary = TempDir::new()?;
        spawn_crash_child(temporary.path(), cut)?;

        let retained = inspect_prefix(temporary.path(), cut)?;
        let fresh = run_round(
            open_fixture(temporary.path())?,
            OperationalRoundInvocationV1::Fresh,
        );
        match (cut, fresh) {
            (
                0,
                Err(
                    F7WalletCompositorError::ContractsSigner
                    | F7WalletCompositorError::ContractsSignerSource(_),
                ),
            ) => {}
            (
                1..=6,
                Err(
                    F7WalletCompositorError::ContractsSession
                    | F7WalletCompositorError::ContractsSessionSource(_),
                ),
            ) => {}
            (_, Ok(_)) => {
                return Err(std::io::Error::other(format!(
                    "fresh signing authority was reminted at durable cut {cut}: round succeeded"
                ))
                .into());
            }
            (_, Err(error)) => {
                return Err(std::io::Error::other(format!(
                    "fresh signing authority was reminted at durable cut {cut}: {error:?}"
                ))
                .into());
            }
        }

        let resumed = run_round(
            open_fixture(temporary.path())?,
            OperationalRoundInvocationV1::ResumeAfterRestart,
        )?;
        if !matches!(resumed, OperationalRoundCompletionV1::Material(_)) {
            return Err(std::io::Error::other("refund round did not recover material").into());
        }
        let complete = inspect_prefix(temporary.path(), 6)?;
        if complete[..cut] != retained {
            return Err(std::io::Error::other("retained signing bytes changed on restart").into());
        }
    }
    Ok(())
}

#[test]
fn production_transport_rejects_gap_and_persists_equivocation() -> TestResult {
    let temporary = TempDir::new()?;
    let fixture = create_fixture(temporary.path())?;
    let composition = &fixture.opened.composition;
    let store = composition.session_store();
    let references = store.transport_identity_references(SESSION_ID)?;
    let sender = &references[0];
    let sender_entry = fixture
        .opened
        .context
        .roster()
        .entries()
        .iter()
        .find(|entry| entry.participant_id() == sender.participant_id())
        .ok_or_else(|| std::io::Error::other("sender is absent from roster"))?;
    let identity_store = identity_store_for_reference(composition, sender)?;
    let before_gap = store.load_session(SESSION_ID)?;
    let gap_unsigned = UnsignedMessageV1::new(
        MessageTypeV1::SigNonceCommit,
        *fixture.opened.context.trusted_chain_id(),
        SESSION_ID,
        *sender.participant_id(),
        2,
        before_gap.transcript_hash(),
        vec![0x55; 67],
    )?;
    let gap = identity_store.sign_exact_dsc1_for_session(gap_unsigned, sender)?;
    let gap_transcript = advance_transcript_hash_v1(
        &before_gap.transcript_hash(),
        gap.digest(),
        sender_entry.direction(),
        SigningPhaseV1::SigNonceCommit,
    );
    let gap_successor = before_gap.advance(
        before_gap.revision(),
        SessionPhaseV1::RefundSigning,
        gap_transcript,
        before_gap.irreversible(),
        before_gap.chain(),
        before_gap.encrypted_payload(),
    )?;
    if !matches!(
        store.accept_transport_message(gap.as_bytes(), &gap_successor, None),
        Err(SessionStoreError::InvalidTransition)
    ) || store.load_session(SESSION_ID)?.as_bytes() != before_gap.as_bytes()
    {
        return Err(std::io::Error::other("sender-sequence gap mutated the Store").into());
    }

    let mut alternate_payload = fixture.template_payload;
    alternate_payload[159] ^= 1;
    let alternate_unsigned = UnsignedMessageV1::new(
        MessageTypeV1::TxTemplateCommit,
        *fixture.opened.context.trusted_chain_id(),
        SESSION_ID,
        *sender.participant_id(),
        0,
        fixture.template_initial_transcript,
        alternate_payload.to_vec(),
    )?;
    let alternate = identity_store.sign_exact_dsc1_for_session(alternate_unsigned, sender)?;
    let mut receiver = SessionReceiverV1::new(
        *fixture.opened.context.trusted_chain_id(),
        SESSION_ID,
        transport_participants(&fixture.opened.context)?,
        SessionPhaseV1::TemplatesCommitted,
        fixture.template_initial_transcript,
    )?;
    receiver.accept(
        &fixture.template_messages[0],
        SessionPhaseV1::TemplatesCommitted,
    )?;
    if !matches!(
        receiver.accept(alternate.as_bytes(), SessionPhaseV1::TemplatesCommitted),
        Err(TransportError::Equivocation)
    ) || !receiver.is_failed_closed()
        || receiver.phase() != SessionPhaseV1::FailedClosed
    {
        return Err(std::io::Error::other("valid same-key equivocation was not terminal").into());
    }

    let current = store.load_session(SESSION_ID)?;
    let failed = current.advance(
        current.revision(),
        SessionPhaseV1::FailedClosed,
        current.transcript_hash(),
        current.irreversible(),
        current.chain(),
        current.encrypted_payload(),
    )?;
    if store.accept_transport_message(alternate.as_bytes(), &failed, Some(&failed))?
        != DurableTransportOutcomeV1::EquivocationPersisted
        || store.load_session(SESSION_ID)?.phase() != SessionPhaseV1::FailedClosed
    {
        return Err(std::io::Error::other("equivocation terminal state was not durable").into());
    }
    drop(fixture);

    let reopened = open_composition(temporary.path())?;
    if reopened.session_store().load_session(SESSION_ID)?.phase() != SessionPhaseV1::FailedClosed {
        return Err(std::io::Error::other("equivocation did not survive Store restart").into());
    }
    Ok(())
}

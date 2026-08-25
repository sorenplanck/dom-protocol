//! Public composition tests for the canonical Contracts nonce vault.

use super::{
    inventory::install_resend_interposition, BackupPolicyLimitsV1, CompletedBackupV1,
    ContractsNonceVaultV1, InventoryError,
};
use crate::{
    ArtifactKindV1, BudgetPolicyV1, ExposureStateV1, UnauthenticatedExposureRecordV1,
    UnauthenticatedJournalEntryV1, UnauthenticatedJournalPayloadV1, BUDGET_CHARGE_NO_ADAPTOR_LEN,
    BUDGET_POLICY_LEN, PERMIT_RETIREMENT_LEN,
};
use cap_std::fs::Dir;
use dom_adaptor::{
    advance_transcript_hash_v1, aggregate_public_nonces_v1, binding_factor_v1,
    canonical_template_v1, initial_transcript_hash_v1, session_message_digest_v1,
    AcceptedMessageDispositionV1, AcceptedSigningSessionV1, BindingContextV1, ContractKindV1,
    DurableReservationLookupV1, NonceCommitmentV1, ParticipantIdentityV1,
    ParticipantPublicNoncesV1, ParticipantRosterV1, PurposeV1, ResentArtifactV1,
    ReservationLookupCustodyV1, ReservationRequestLookupV1, ReservationResumeResultV1,
    SigningPhaseV1, SigningSessionAuthorityV1, SigningShareV1, TrustedChainIdV1,
    VaultBackedSignerV1,
};
use dom_consensus::{Transaction, TransactionKernel, validate_kernel_signatures};
use dom_scriptless_consensus::{scriptless_kernel_message_digest_v1};
use dom_core::{Amount, Hash256};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{PartialSig, PublicKey, SchnorrSignature, SecretKey, schnorr_challenge, schnorr_sign};
use dom_scriptless_primitives::{scriptless_add_public_points, scriptless_aggregate_partial_scalars, scriptless_verify_bound_partial, scriptless_verify_final_signature};
use dom_scriptless_crypto::{
    authoritative_storage_hash_v1, Passphrase, StorageHashDomainV1, StorageIdsV1,
};
use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::Write,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{self, Command},
    sync::{Arc, Mutex, MutexGuard},
};

const KIND_COMMITMENT: u8 = 0x0c;
const KIND_REVEAL: u8 = 0x0d;
const KIND_PARTIAL: u8 = 0x0e;

// TEST VECTOR ONLY — PUBLIC AND INSECURE.
// NEVER USE THIS SEED, KEY, NONCE, SCALAR, OR MNEMONIC ON MAINNET.
// TEST_ONLY / NO_ECONOMIC_VALUE / MUST_NOT_BE_REUSED. Every scalar, key,
// nonce source, passphrase, and identifier in this module is synthetic public
// test material scoped to temporary evidence stores.

#[derive(Debug)]
struct TestError(&'static str);

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for TestError {}

fn lock<T>(value: &Mutex<T>) -> Result<MutexGuard<'_, T>, TestError> {
    value.lock().map_err(|_| TestError("test lock poisoned"))
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create(suffix: &str) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "dom-contracts-signer-e2e-{}-{suffix}",
            process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn capability(&self) -> Result<Arc<Dir>, Box<dyn Error>> {
        Ok(Arc::new(Dir::from_std_file(File::open(&self.0)?)))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn copy_directory_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::symlink_metadata(source)?.permissions())?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.is_dir() {
            copy_directory_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path)?;
            fs::set_permissions(&destination_path, metadata.permissions())?;
        } else {
            return Err(Box::new(TestError("non-regular test tree entry")));
        }
    }
    Ok(())
}

fn canonical_exposure_record_paths(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut records = Vec::new();
    for identity in fs::read_dir(root)? {
        let identity = identity?;
        if !identity.file_type()?.is_dir() {
            continue;
        }
        for sequence in fs::read_dir(identity.path())? {
            let sequence = sequence?;
            if !sequence.file_type()?.is_dir() {
                continue;
            }
            for record in fs::read_dir(sequence.path())? {
                let record = record?;
                if record.file_type()?.is_file() {
                    records.push(record.path());
                }
            }
        }
    }
    records.sort();
    Ok(records)
}

fn canonical_backup_name(backup: &CompletedBackupV1) -> String {
    format!(
        "backup-{:020}-{}",
        backup.backup_generation(),
        backup
            .backup_id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

struct EvidenceTestClockGuard;

impl Drop for EvidenceTestClockGuard {
    fn drop(&mut self) {
        ContractsNonceVaultV1::set_evidence_test_time(None);
    }
}

fn set_evidence_test_clock(now: u64) -> EvidenceTestClockGuard {
    ContractsNonceVaultV1::set_evidence_test_time(Some(now));
    EvidenceTestClockGuard
}

fn evidence_policy() -> Result<BudgetPolicyV1, Box<dyn Error>> {
    evidence_policy_with_limits(100, 100, 10, 100, 3_600, 3_600)
}

fn evidence_policy_with_limits(
    global: u64,
    counterparty: u64,
    concurrent: u32,
    rolling: u64,
    rolling_window_seconds: u64,
    maximum_forward_step_seconds: u64,
) -> Result<BudgetPolicyV1, Box<dyn Error>> {
    let mut bytes = [0_u8; BUDGET_POLICY_LEN];
    bytes[..8].copy_from_slice(b"DOMNVBP1");
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10] = 0x02;
    bytes[11] = 0x01;
    bytes[16..48].fill(0x41);
    bytes[48..56].copy_from_slice(&global.to_le_bytes());
    bytes[56..64].copy_from_slice(&counterparty.to_le_bytes());
    bytes[64..68].copy_from_slice(&concurrent.to_le_bytes());
    bytes[72..80].copy_from_slice(&rolling.to_le_bytes());
    bytes[80..88].copy_from_slice(&rolling_window_seconds.to_le_bytes());
    bytes[88..96].copy_from_slice(&maximum_forward_step_seconds.to_le_bytes());
    bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
    let digest = authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
    bytes[112..].copy_from_slice(&digest);
    Ok(BudgetPolicyV1::from_bytes(&bytes)?)
}

#[derive(Clone)]
struct DurableLookup {
    lookup: ReservationRequestLookupV1,
    binding: [u8; 32],
    session_id: dom_adaptor::SessionId,
}

impl DurableReservationLookupV1 for DurableLookup {
    fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.lookup
    }

    fn context_binding_digest(&self) -> &[u8; 32] {
        &self.binding
    }

    fn session_id(&self) -> &dom_adaptor::SessionId {
        &self.session_id
    }
}

#[derive(Clone)]
struct TestCustody(Arc<Mutex<Option<DurableLookup>>>);

impl TestCustody {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    fn from_durable(retained: DurableLookup) -> Self {
        Self(Arc::new(Mutex::new(Some(retained))))
    }

    fn durable(&self) -> Result<DurableLookup, TestError> {
        lock(&self.0)?
            .as_ref()
            .cloned()
            .ok_or(TestError("durable lookup missing"))
    }

    fn lookup(&self) -> Result<ReservationRequestLookupV1, TestError> {
        lock(&self.0)?
            .as_ref()
            .map(|retained| retained.lookup.clone())
            .ok_or(TestError("durable lookup missing"))
    }
}

impl ReservationLookupCustodyV1 for TestCustody {
    type Error = TestError;
    type DurableLookup = DurableLookup;

    fn persist_prepared_lookup(
        &mut self,
        prepared: &dom_adaptor::PreparedFreshReservationV1,
    ) -> Result<Self::DurableLookup, Self::Error> {
        let retained = DurableLookup {
            lookup: prepared.request_lookup().clone(),
            binding: *prepared.context_binding_digest(),
            session_id: prepared.session_id().clone(),
        };
        *lock(&self.0)? = Some(retained.clone());
        Ok(retained)
    }

    fn abandon_before_vault_claim(
        &mut self,
        _lookup: &ReservationRequestLookupV1,
        _session_id: &dom_adaptor::SessionId,
        _context_binding_digest: &[u8; 32],
    ) -> Result<(), Self::Error> {
        Err(TestError("unexpected reservation abandonment"))
    }
}

struct AcceptedSession {
    chain: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: ParticipantRosterV1,
    transaction: Transaction,
    transcript: [u8; 32],
    accepted_messages: Vec<Vec<u8>>,
}

impl AcceptedSigningSessionV1 for AcceptedSession {
    fn trusted_chain_id(&self) -> &TrustedChainIdV1 {
        &self.chain
    }

    fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    fn contract_kind(&self) -> ContractKindV1 {
        ContractKindV1::WitnessOrTimeout
    }

    fn purpose(&self) -> PurposeV1 {
        PurposeV1::Refund
    }

    fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }

    fn transaction_template(&self) -> &Transaction {
        &self.transaction
    }

    fn kernel_index(&self) -> usize {
        0
    }

    fn adaptor_point(&self) -> Option<&PublicKey> {
        None
    }

    fn initial_transcript_hash(&self) -> &[u8; 32] {
        &self.transcript
    }

    fn accepted_signing_messages(&self) -> impl Iterator<Item = &[u8]> {
        self.accepted_messages.iter().map(Vec::as_slice)
    }
}

struct SessionAuthority;

impl SigningSessionAuthorityV1 for SessionAuthority {
    type Error = TestError;
    type AcceptedSession = AcceptedSession;
}

struct ParticipantFixture {
    identity_secret: [u8; 32],
    signing_share: [u8; 32],
}

struct SessionFixture {
    chain: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: ParticipantRosterV1,
    transaction: Transaction,
    transcript: [u8; 32],
    participants: [ParticipantFixture; 2],
}

impl SessionFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            0x5031_3037,
            &Hash256::from_bytes([0x71; 32]),
        );
        let raw = [
            ([0x72; 32], [0x74; 32], dom_adaptor::DirectionV1::Initiator),
            ([0x73; 32], [0x75; 32], dom_adaptor::DirectionV1::Responder),
        ];
        let mut entries = Vec::new();
        for (identity_bytes, share_bytes, direction) in raw {
            let identity = SecretKey::from_bytes(&identity_bytes)?;
            let share = SigningShareV1::from_be_bytes(share_bytes)?;
            entries.push(ParticipantIdentityV1::new(
                &chain,
                identity.public_key(),
                share.public_key().clone(),
                direction,
            )?);
        }
        entries.sort_by_key(|entry| *entry.participant_id());
        let roster = ParticipantRosterV1::new(entries)?;
        let mut participant_fixtures = Vec::with_capacity(2);
        for entry in roster.entries() {
            let key = entry.signing_public_key();
            let source = raw
                .iter()
                .find(|(_, share_bytes, _)| {
                    SigningShareV1::from_be_bytes(*share_bytes)
                        .map(|share| share.public_key() == key)
                        .unwrap_or(false)
                })
                .ok_or(TestError("synthetic participant fixture is incomplete"))?;
            participant_fixtures.push(ParticipantFixture {
                identity_secret: source.0,
                signing_share: source.1,
            });
        }
        let participants: [ParticipantFixture; 2] = participant_fixtures
            .try_into()
            .map_err(|_| TestError("synthetic participant fixture has the wrong size"))?;
        let mut signing_keys: Vec<_> = roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
        let aggregate = aggregate_public_nonces_v1(&signing_keys)?;
        let transaction = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![TransactionKernel {
                features: 0,
                fee: Amount::ZERO,
                lock_height: 0,
                excess: Commitment::from_compressed_bytes(&aggregate.to_compressed_bytes())?,
                excess_signature: [0; 65],
            }],
            offset: [0x76; 32],
        };
        let session_id = [0x77; 32];
        let transcript = initial_transcript_hash_v1(
            &chain,
            &session_id,
            ContractKindV1::WitnessOrTimeout,
            &roster,
        );
        Ok(Self {
            chain,
            session_id,
            roster,
            transaction,
            transcript,
            participants,
        })
    }

    fn with_session_marker(marker: u8) -> Result<Self, Box<dyn Error>> {
        let mut fixture = Self::new()?;
        fixture.session_id = [marker; 32];
        fixture.transcript = initial_transcript_hash_v1(
            &fixture.chain,
            &fixture.session_id,
            ContractKindV1::WitnessOrTimeout,
            &fixture.roster,
        );
        Ok(fixture)
    }

    fn accepted(&self) -> AcceptedSession {
        AcceptedSession {
            chain: self.chain,
            session_id: self.session_id,
            roster: self.roster.clone(),
            transaction: self.transaction.clone(),
            transcript: self.transcript,
            accepted_messages: Vec::new(),
        }
    }

    fn accepted_with_messages(&self, messages: &[&[u8]]) -> AcceptedSession {
        AcceptedSession {
            chain: self.chain,
            session_id: self.session_id,
            roster: self.roster.clone(),
            transaction: self.transaction.clone(),
            transcript: self.transcript,
            accepted_messages: messages.iter().map(|message| message.to_vec()).collect(),
        }
    }

    fn share(&self, index: usize) -> Result<SigningShareV1, Box<dyn Error>> {
        Ok(SigningShareV1::from_be_bytes(
            self.participants[index].signing_share,
        )?)
    }

    fn identity(&self, index: usize) -> Result<SecretKey, Box<dyn Error>> {
        Ok(SecretKey::from_bytes(
            &self.participants[index].identity_secret,
        )?)
    }

    fn signing_index(&self, index: usize) -> Result<u16, Box<dyn Error>> {
        let participant = self
            .roster
            .entries()
            .get(index)
            .ok_or(TestError("synthetic participant index is out of bounds"))?;
        Ok(self.roster.signing_index(participant.participant_id())?)
    }
}

fn signed_message(
    fixture: &SessionFixture,
    sender_index: usize,
    sequence: u64,
    previous_transcript: [u8; 32],
    kind: u8,
    phase: SigningPhaseV1,
    payload: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), Box<dyn Error>> {
    let sender = &fixture.roster.entries()[sender_index];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"DSC1");
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.push(kind);
    bytes.push(0);
    bytes.extend_from_slice(fixture.chain.as_bytes());
    bytes.extend_from_slice(&fixture.session_id);
    bytes.extend_from_slice(sender.participant_id());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&previous_transcript);
    bytes.extend_from_slice(&u32::try_from(payload.len())?.to_le_bytes());
    bytes.extend_from_slice(payload);
    let digest = session_message_digest_v1(&bytes);
    let signature = schnorr_sign(
        &fixture.identity(sender_index)?,
        &digest,
        fixture.chain.as_bytes(),
    )?;
    bytes.extend_from_slice(&signature.to_bytes());
    let next = advance_transcript_hash_v1(&previous_transcript, &digest, sender.direction(), phase);
    Ok((bytes, next))
}

type Signer = VaultBackedSignerV1<ContractsNonceVaultV1, TestCustody, SessionAuthority>;

fn signer(
    vault: ContractsNonceVaultV1,
    custody: TestCustody,
    fixture: &SessionFixture,
    participant: usize,
) -> Result<Signer, Box<dyn Error>> {
    Ok(VaultBackedSignerV1::new(
        vault,
        custody,
        SessionAuthority,
        fixture.chain,
        fixture.share(participant)?,
    ))
}

struct CompletedPartialScenario {
    fixture: SessionFixture,
    custody: TestCustody,
    lookup: ReservationRequestLookupV1,
    accepted_prefix: Vec<Vec<u8>>,
    partial_bytes: [u8; 67],
    pre_partial_backup: Option<CompletedBackupV1>,
}

fn complete_partial_for_first_participant(
    directory: &TestDirectory,
    passphrase: &[u8],
    suffix: &str,
    create_pre_partial_backup: bool,
) -> Result<CompletedPartialScenario, Box<dyn Error>> {
    let fixture = SessionFixture::new()?;
    let peer = TestDirectory::create(&format!("{suffix}-peer"))?;
    let vault_a = ContractsNonceVaultV1::create_evidence_only(
        directory.capability()?,
        "contracts-store",
        StorageIdsV1::new([0x31; 32], [0x41; 32])?,
        &Passphrase::new(passphrase.to_vec())?,
        evidence_policy()?,
    )?;
    let vault_b = ContractsNonceVaultV1::create_evidence_only(
        peer.capability()?,
        "contracts-store",
        StorageIdsV1::new([0x32; 32], [0x42; 32])?,
        &Passphrase::new(b"partial-scenario-peer-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let custody_a = TestCustody::new();
    let mut signer_a = signer(vault_a, custody_a.clone(), &fixture, 0)?;
    let mut signer_b = signer(vault_b, TestCustody::new(), &fixture, 1)?;
    let mut round_a = signer_a.begin_accepted_signing_round(fixture.accepted())?;
    let mut round_b = signer_b.begin_accepted_signing_round(fixture.accepted())?;
    let reservation_a = signer_a.claim_fresh(round_a.take_derivation_base()?)?;
    let reservation_b = signer_b.claim_fresh(round_b.take_derivation_base()?)?;
    let (commitment_state_a, commitment_a) =
        signer_a.derive_and_export_commitment(reservation_a)?;
    let (commitment_state_b, commitment_b) =
        signer_b.derive_and_export_commitment(reservation_b)?;

    let mut transcript = fixture.transcript;
    let (commitment_message_a, next) = signed_message(
        &fixture,
        0,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_a.to_bytes(),
    )?;
    transcript = next;
    let (commitment_message_b, next) = signed_message(
        &fixture,
        1,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_b.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&commitment_message_a)?;
        round.accept_message(&commitment_message_b)?;
    }

    let reveal_authority_a = round_a.take_commitment_round()?;
    let (mut reveal_state_a, reveal_a) =
        signer_a.export_reveal(commitment_state_a, reveal_authority_a)?;
    let (reveal_message_a, next) = signed_message(
        &fixture,
        0,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_a.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&reveal_message_a)?;
    }
    let reveal_authority_b = round_b.take_commitment_round()?;
    let (reveal_state_b, reveal_b) =
        signer_b.export_reveal(commitment_state_b, reveal_authority_b)?;
    let (reveal_message_b, next) = signed_message(
        &fixture,
        1,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_b.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&reveal_message_b)?;
    }

    let pre_partial_backup = if create_pre_partial_backup {
        drop(reveal_state_a);
        // The accepted round retains the session-bound authority needed for
        // its local process. A restart fixture must release it before opening
        // the backup authority, then rebuild the public prefix after resume.
        drop(round_a);
        drop(signer_a);
        let mut backup_vault = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(passphrase.to_vec())?,
            evidence_policy()?,
        )?;
        let backup = backup_vault.create_backup_evidence_only(
            Passphrase::new(b"partial-old-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        drop(backup_vault);
        let reopened = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(passphrase.to_vec())?,
            evidence_policy()?,
        )?;
        signer_a = signer(reopened, custody_a.clone(), &fixture, 0)?;
        round_a = signer_a.begin_accepted_signing_round(fixture.accepted())?;
        let resume_base = round_a.take_derivation_base()?;
        let resumed = signer_a.resume_claimed(resume_base, custody_a.lookup()?)?;
        reveal_state_a = match resumed {
            ReservationResumeResultV1::Live(dom_adaptor::ResumedReservationV1::AfterReveal(
                state,
            )) => state,
            _ => {
                return Err(Box::new(TestError(
                    "pre-partial backup did not resume the reveal stage",
                )))
            }
        };
        for message in [
            &commitment_message_a,
            &commitment_message_b,
            &reveal_message_a,
            &reveal_message_b,
        ] {
            round_a.accept_message(message)?;
        }
        Some(backup)
    } else {
        None
    };

    if let Some(evidence_path) = std::env::var_os("DOM_G1B_PARTIAL_PRECOMMIT_EVIDENCE") {
        write_partial_precommit_evidence(
            Path::new(&evidence_path),
            &custody_a.durable()?,
            &transcript,
            &[
                commitment_message_a.clone(),
                commitment_message_b.clone(),
                reveal_message_a.clone(),
                reveal_message_b.clone(),
            ],
        )?;
    }

    let partial_authority_a = round_a.take_reveal_round()?;
    let (_terminal_a, partial_a) =
        signer_a.sign_and_export_partial(reveal_state_a, partial_authority_a)?;
    let partial_bytes = partial_a.to_bytes();
    let (partial_message_a, next) = signed_message(
        &fixture,
        0,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_bytes,
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&partial_message_a)?;
    }
    let partial_authority_b = round_b.take_reveal_round()?;
    let (_terminal_b, partial_b) =
        signer_b.sign_and_export_partial(reveal_state_b, partial_authority_b)?;
    let (partial_message_b, _) = signed_message(
        &fixture,
        1,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_b.to_bytes(),
    )?;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&partial_message_b)?;
    }

    Ok(CompletedPartialScenario {
        fixture,
        lookup: custody_a.lookup()?,
        custody: custody_a,
        accepted_prefix: vec![
            commitment_message_a,
            commitment_message_b,
            reveal_message_a,
            reveal_message_b,
            partial_message_a,
            partial_message_b,
        ],
        partial_bytes,
        pre_partial_backup,
    })
}

fn write_partial_precommit_evidence(
    path: &Path,
    durable: &DurableLookup,
    transcript: &[u8; 32],
    accepted_prefix: &[Vec<u8>; 4],
) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"P1PRE002");
    bytes.extend_from_slice(durable.lookup.as_bytes());
    bytes.extend_from_slice(&durable.binding);
    bytes.extend_from_slice(durable.session_id.as_bytes());
    bytes.extend_from_slice(transcript);
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    for message in accepted_prefix {
        bytes.extend_from_slice(&u32::try_from(message.len())?.to_le_bytes());
        bytes.extend_from_slice(message);
    }
    let mut file = File::options().create_new(true).write(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or(TestError("partial precommit evidence parent is missing"))?,
    )?
    .sync_all()?;
    Ok(())
}

type PartialPrecommitEvidence = (DurableLookup, [u8; 32], Vec<Vec<u8>>);

fn read_partial_precommit_evidence(
    path: &Path,
) -> Result<PartialPrecommitEvidence, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if bytes.get(..8) != Some(b"P1PRE002") {
        return Err(Box::new(TestError(
            "invalid partial precommit evidence magic",
        )));
    }
    let lookup = ReservationRequestLookupV1::from_bytes(
        bytes
            .get(8..40)
            .ok_or(TestError("partial precommit lookup is truncated"))?
            .try_into()?,
    )?;
    let binding = bytes
        .get(40..72)
        .ok_or(TestError("partial precommit binding is truncated"))?
        .try_into()?;
    let session_id = dom_adaptor::SessionId::from_bytes(
        bytes
            .get(72..104)
            .ok_or(TestError("partial precommit session is truncated"))?
            .try_into()?,
    )?;
    let transcript = bytes
        .get(104..136)
        .ok_or(TestError("partial precommit transcript is truncated"))?
        .try_into()?;
    let count = u32::from_le_bytes(
        bytes
            .get(136..140)
            .ok_or(TestError("partial precommit message count is truncated"))?
            .try_into()?,
    );
    if count != 4 {
        return Err(Box::new(TestError(
            "partial precommit evidence has the wrong message count",
        )));
    }
    let mut cursor = 140_usize;
    let mut messages = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        let length_end = cursor
            .checked_add(4)
            .ok_or(TestError("partial precommit evidence length overflow"))?;
        let length = u32::from_le_bytes(
            bytes
                .get(cursor..length_end)
                .ok_or(TestError("partial precommit message length is truncated"))?
                .try_into()?,
        );
        cursor = length_end;
        let message_end = cursor
            .checked_add(usize::try_from(length)?)
            .ok_or(TestError("partial precommit message overflow"))?;
        messages.push(
            bytes
                .get(cursor..message_end)
                .ok_or(TestError("partial precommit message is truncated"))?
                .to_vec(),
        );
        cursor = message_end;
    }
    if cursor != bytes.len() {
        return Err(Box::new(TestError(
            "partial precommit evidence has trailing bytes",
        )));
    }
    Ok((
        DurableLookup {
            lookup,
            binding,
            session_id,
        },
        transcript,
        messages,
    ))
}

fn read_unique_partial(
    root: &Path,
    required_state: ExposureStateV1,
) -> Result<[u8; 67], Box<dyn Error>> {
    let mut partial = None;
    for generation in fs::read_dir(root)? {
        let generation = generation?;
        if !generation.file_type()?.is_dir()
            || !generation
                .file_name()
                .to_string_lossy()
                .starts_with("generation-")
        {
            continue;
        }
        let exposures = generation.path().join("exposures");
        if !exposures.is_dir() {
            continue;
        }
        for identity in fs::read_dir(exposures)? {
            for sequence in fs::read_dir(identity?.path())? {
                let sequence = sequence?;
                if !sequence.file_type()?.is_dir() {
                    continue;
                }
                for exposure in fs::read_dir(sequence.path())? {
                    let exposure = exposure?;
                    if !exposure.file_type()?.is_file() {
                        continue;
                    }
                    let bytes = fs::read(exposure.path())?;
                    let structural = UnauthenticatedExposureRecordV1::parse_structural(&bytes)?;
                    if structural.artifact() == ArtifactKindV1::PartialSignature
                        && structural.state() == required_state
                    {
                        let exact: [u8; 67] = structural.outbound_bytes().try_into()?;
                        if partial.replace(exact).is_some() {
                            return Err(Box::new(TestError("duplicate partial exposure")));
                        }
                    }
                }
            }
        }
    }
    partial.ok_or_else(|| Box::new(TestError("required partial exposure is missing")) as _)
}

fn write_partial_restart_evidence(
    path: &Path,
    scenario: &CompletedPartialScenario,
) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"P1RSEV01");
    bytes.extend_from_slice(scenario.lookup.as_bytes());
    bytes.extend_from_slice(&scenario.partial_bytes);
    bytes.extend_from_slice(&u32::try_from(scenario.accepted_prefix.len())?.to_le_bytes());
    for message in &scenario.accepted_prefix {
        bytes.extend_from_slice(&u32::try_from(message.len())?.to_le_bytes());
        bytes.extend_from_slice(message);
    }
    let mut file = File::options().create_new(true).write(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

type PartialRestartEvidenceV1 = (ReservationRequestLookupV1, [u8; 67], Vec<Vec<u8>>);

fn read_partial_restart_evidence(path: &Path) -> Result<PartialRestartEvidenceV1, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if bytes.get(..8) != Some(b"P1RSEV01") {
        return Err(Box::new(TestError(
            "invalid partial restart evidence magic",
        )));
    }
    let lookup = ReservationRequestLookupV1::from_bytes(
        bytes
            .get(8..40)
            .ok_or(TestError("partial restart lookup is truncated"))?
            .try_into()?,
    )?;
    let partial_bytes: [u8; 67] = bytes
        .get(40..107)
        .ok_or(TestError("partial restart artifact is truncated"))?
        .try_into()?;
    let count = u32::from_le_bytes(
        bytes
            .get(107..111)
            .ok_or(TestError("partial restart message count is truncated"))?
            .try_into()?,
    );
    if count != 6 {
        return Err(Box::new(TestError(
            "partial restart evidence has the wrong message count",
        )));
    }
    let mut cursor = 111_usize;
    let mut messages = Vec::with_capacity(usize::try_from(count)?);
    for _ in 0..count {
        let length_end = cursor
            .checked_add(4)
            .ok_or(TestError("partial restart evidence length overflow"))?;
        let length = u32::from_le_bytes(
            bytes
                .get(cursor..length_end)
                .ok_or(TestError("partial restart message length is truncated"))?
                .try_into()?,
        );
        cursor = length_end;
        let message_end = cursor
            .checked_add(usize::try_from(length)?)
            .ok_or(TestError("partial restart evidence message overflow"))?;
        messages.push(
            bytes
                .get(cursor..message_end)
                .ok_or(TestError("partial restart message is truncated"))?
                .to_vec(),
        );
        cursor = message_end;
    }
    if cursor != bytes.len() {
        return Err(Box::new(TestError(
            "partial restart evidence has trailing bytes",
        )));
    }
    Ok((lookup, partial_bytes, messages))
}

#[test]
fn completed_restore_resume_rejects_one_bit_full_snapshot_mutations() -> Result<(), Box<dyn Error>>
{
    let fixture = SessionFixture::new()?;
    let directory = TestDirectory::create("restore-secret-corruption")?;
    let initial_passphrase = b"restore-secret-initial-passphrase".to_vec();
    let backup_passphrase = b"restore-secret-backup-passphrase".to_vec();
    let successor_passphrase = b"restore-secret-successor-passphrase".to_vec();
    let vault = ContractsNonceVaultV1::create_evidence_only(
        directory.capability()?,
        "contracts-store",
        StorageIdsV1::new([0x51; 32], [0x61; 32])?,
        &Passphrase::new(initial_passphrase.clone())?,
        evidence_policy()?,
    )?;
    let custody = TestCustody::new();
    let mut initial_signer = signer(vault, custody, &fixture, 0)?;
    let mut round = initial_signer.begin_accepted_signing_round(fixture.accepted())?;
    let base = round.take_derivation_base()?;
    let reservation = initial_signer.claim_fresh(base)?;
    let (_commitment_state, _commitment) =
        initial_signer.derive_and_export_commitment(reservation)?;
    drop(round);
    drop(initial_signer);

    let mut vault = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(initial_passphrase)?,
        evidence_policy()?,
    )?;
    let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
    let backup =
        vault.create_backup_evidence_only(Passphrase::new(backup_passphrase.clone())?, limits)?;
    let backup_name = format!(
        "backup-{:020}-{}",
        backup.backup_generation(),
        backup
            .backup_id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    vault.publish_existing_device_restore_evidence_only(
        &backup_name,
        Passphrase::new(backup_passphrase)?,
        Passphrase::new(successor_passphrase.clone())?,
        limits,
    )?;

    // Create a normal post-activation descendant through the same public
    // signer seam so the completed restore contains a live, canonical secret
    // record that no test can fabricate directly.
    let descendant_fixture = SessionFixture::with_session_marker(0x78)?;
    let descendant_vault = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(successor_passphrase.clone())?,
        evidence_policy()?,
    )?;
    let mut descendant_signer =
        signer(descendant_vault, TestCustody::new(), &descendant_fixture, 0)?;
    let mut descendant_round = descendant_signer
        .begin_accepted_signing_round(descendant_fixture.accepted())
        .map_err(|_| TestError("descendant accepted-session bootstrap failed"))?;
    let descendant_base = descendant_round
        .take_derivation_base()
        .map_err(|_| TestError("descendant derivation authority failed"))?;
    let descendant_reservation = descendant_signer
        .claim_fresh(descendant_base)
        .map_err(|_| TestError("descendant reservation failed"))?;
    let (_state, _commitment) = descendant_signer
        .derive_and_export_commitment(descendant_reservation)
        .map_err(|_| TestError("descendant commitment failed"))?;
    drop(descendant_round);
    drop(descendant_signer);

    let root = directory.path().join("contracts-store");
    let active_generation = fs::read_dir(&root)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("generation-")
        })
        .max_by_key(|entry| entry.file_name())
        .ok_or(TestError("active successor generation is missing"))?;
    let active_generation_name = active_generation.file_name();
    let clean = TestDirectory::create("restore-snapshot-clean")?;
    copy_directory_tree(&root, &clean.path().join("contracts-store"))?;
    let clean_target =
        ContractsNonceVaultV1::retain_restore_target(clean.capability()?, "contracts-store")?;
    ContractsNonceVaultV1::resume_restore(
        clean_target,
        Passphrase::new(successor_passphrase.clone())?,
    )?;
    for (case_index, namespace) in ["reservation-authorities", "budget-charges", "nonce-secrets"]
        .into_iter()
        .enumerate()
    {
        let case = TestDirectory::create(&format!("restore-snapshot-{case_index}"))?;
        copy_directory_tree(&root, &case.path().join("contracts-store"))?;
        let authenticated = ContractsNonceVaultV1::open_evidence_only(
            case.capability()?,
            "contracts-store",
            Passphrase::new(successor_passphrase.clone())?,
            evidence_policy()?,
        )?;
        drop(authenticated);
        let namespace_path = case
            .path()
            .join("contracts-store")
            .join(&active_generation_name)
            .join(namespace);
        let records = fs::read_dir(&namespace_path)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            records.len(),
            1,
            "one canonical {namespace} record is required"
        );
        let mut bytes = fs::read(records[0].path())?;
        let mutated = bytes
            .get_mut(32)
            .ok_or(TestError("canonical snapshot record is truncated"))?;
        *mutated ^= 0x01;
        fs::write(records[0].path(), bytes)?;
        let target =
            ContractsNonceVaultV1::retain_restore_target(case.capability()?, "contracts-store")?;
        assert!(ContractsNonceVaultV1::resume_restore(
            target,
            Passphrase::new(successor_passphrase.clone())?,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn resend_revalidates_full_store_across_lookup_interposition() -> Result<(), Box<dyn Error>> {
    for (case_index, component) in ["root", "active", "journal", "exposure"]
        .into_iter()
        .enumerate()
    {
        let case_marker = u8::try_from(case_index)?;
        let fixture = SessionFixture::with_session_marker(
            0x79_u8
                .checked_add(case_marker)
                .ok_or(TestError("resend case marker overflow"))?,
        )?;
        let directories = [
            TestDirectory::create(&format!("resend-{component}-control"))?,
            TestDirectory::create(&format!("resend-{component}-mutated"))?,
        ];
        let mut signers = Vec::new();
        let mut rounds = Vec::new();
        let mut states = Vec::new();
        let mut commitments = Vec::new();
        for (index, directory) in directories.iter().enumerate() {
            let participant_marker = u8::try_from(index)?;
            let storage_marker = case_marker
                .checked_mul(2)
                .and_then(|value| value.checked_add(participant_marker))
                .ok_or(TestError("resend storage marker overflow"))?;
            let vault = ContractsNonceVaultV1::create_evidence_only(
                directory.capability()?,
                "contracts-store",
                StorageIdsV1::new(
                    [0x81_u8
                        .checked_add(storage_marker)
                        .ok_or(TestError("resend wallet marker overflow"))?;
                        32],
                    [0x91_u8
                        .checked_add(storage_marker)
                        .ok_or(TestError("resend store marker overflow"))?; 32],
                )?,
                &Passphrase::new(format!("resend-interposition-{component}-{index}").into_bytes())?,
                evidence_policy()?,
            )?;
            let mut signer = signer(vault, TestCustody::new(), &fixture, index)?;
            let mut round = signer.begin_accepted_signing_round(fixture.accepted())?;
            let base = round.take_derivation_base()?;
            let reservation = signer.claim_fresh(base)?;
            let (state, commitment) = signer.derive_and_export_commitment(reservation)?;
            signers.push(signer);
            rounds.push(round);
            states.push(state);
            commitments.push(commitment);
        }
        let (message_a, next) = signed_message(
            &fixture,
            0,
            0,
            fixture.transcript,
            KIND_COMMITMENT,
            SigningPhaseV1::SigNonceCommit,
            &commitments[0].to_bytes(),
        )?;
        let (message_b, _) = signed_message(
            &fixture,
            1,
            0,
            next,
            KIND_COMMITMENT,
            SigningPhaseV1::SigNonceCommit,
            &commitments[1].to_bytes(),
        )?;
        for round in &mut rounds {
            round.accept_message(&message_a)?;
            round.accept_message(&message_b)?;
        }

        let control_authority = states[0].authorize_resend(&mut rounds[0])?;
        match signers[0].resend_commitment(&states[0], control_authority)? {
            ResentArtifactV1::NonceCommitment(value) => assert_eq!(value, commitments[0]),
            _ => return Err(Box::new(TestError("unexpected control resend artifact"))),
        }

        let root = directories[1].path().join("contracts-store");
        let active_generation = fs::read_dir(&root)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("generation-")
            })
            .max_by_key(|entry| entry.file_name())
            .ok_or(TestError("resend generation is missing"))?;
        let mutation_path = match component {
            "root" => root.join("store-root-identity.bin"),
            "active" => root.join("active-vault-generation"),
            "journal" => fs::read_dir(active_generation.path().join("journal"))?
                .filter_map(Result::ok)
                .find(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
                .ok_or(TestError("resend journal entry is missing"))?
                .path(),
            "exposure" => {
                canonical_exposure_record_paths(&active_generation.path().join("exposures"))?
                    .into_iter()
                    .next()
                    .ok_or(TestError("spent exposure is missing"))?
            }
            _ => return Err(Box::new(TestError("unknown resend mutation component"))),
        };
        let _resend_interposition = install_resend_interposition(Box::new(move || {
            let mut bytes = fs::read(&mutation_path).map_err(|_| InventoryError::Filesystem)?;
            let byte = bytes
                .get_mut(32)
                .ok_or(InventoryError::RestoreQuarantined)?;
            *byte ^= 0x01;
            fs::write(&mutation_path, bytes).map_err(|_| InventoryError::Filesystem)
        }))?;
        let mutated_authority = states[1].authorize_resend(&mut rounds[1])?;
        assert!(signers[1]
            .resend_commitment(&states[1], mutated_authority)
            .is_err());
    }
    Ok(())
}

#[test]
fn accepted_prefix_rejects_mutation_reorder_and_equivocating_duplicate(
) -> Result<(), Box<dyn Error>> {
    let fixture = SessionFixture::with_session_marker(0x7d)?;
    let directory = TestDirectory::create("accepted-prefix-negatives")?;
    let vault = ContractsNonceVaultV1::create_evidence_only(
        directory.capability()?,
        "contracts-store",
        StorageIdsV1::new([0x8d; 32], [0x9d; 32])?,
        &Passphrase::new(b"accepted-prefix-negative-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let custody = TestCustody::new();
    let mut signer = signer(vault, custody, &fixture, 0)?;
    let mut initial_round = signer.begin_accepted_signing_round(fixture.accepted())?;
    let reservation = signer.claim_fresh(initial_round.take_derivation_base()?)?;
    let (_local_commitment_state, local_commitment) =
        signer.derive_and_export_commitment(reservation)?;
    let payload_a = local_commitment.to_bytes();
    let payload_b =
        NonceCommitmentV1::new(PurposeV1::Refund, fixture.signing_index(1)?, [0xb1; 32]).to_bytes();
    let (message_a, next) = signed_message(
        &fixture,
        0,
        0,
        fixture.transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &payload_a,
    )?;
    let (message_b, _) = signed_message(
        &fixture,
        1,
        0,
        next,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &payload_b,
    )?;
    let mut mutated = message_a.clone();
    let payload_byte = mutated
        .get_mut(120)
        .ok_or(TestError("accepted message is unexpectedly short"))?;
    *payload_byte ^= 0x01;
    assert!(signer
        .begin_accepted_signing_round(
            fixture.accepted_with_messages(&[mutated.as_slice(), message_b.as_slice(),])
        )
        .is_err());
    assert!(signer
        .begin_accepted_signing_round(
            fixture.accepted_with_messages(&[message_b.as_slice(), message_a.as_slice(),])
        )
        .is_err());
    let conflicting_payload =
        NonceCommitmentV1::new(PurposeV1::Refund, fixture.signing_index(0)?, [0xa2; 32]).to_bytes();
    let (conflicting_duplicate, _) = signed_message(
        &fixture,
        0,
        0,
        fixture.transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &conflicting_payload,
    )?;
    assert!(signer
        .begin_accepted_signing_round(
            fixture
                .accepted_with_messages(&[message_a.as_slice(), conflicting_duplicate.as_slice(),])
        )
        .is_err());
    let _valid_begin = signer.begin_accepted_signing_round(
        fixture.accepted_with_messages(&[message_a.as_slice(), message_b.as_slice()]),
    )?;
    Ok(())
}

#[test]
fn budget_scopes_windows_clock_and_abort_states_fail_closed() -> Result<(), Box<dyn Error>> {
    let _clock_guard = set_evidence_test_clock(1_000);
    for (case_index, (name, policy)) in [
        (
            "global",
            evidence_policy_with_limits(1, 100, 10, 100, 100, 100)?,
        ),
        (
            "counterparty",
            evidence_policy_with_limits(100, 1, 10, 100, 100, 100)?,
        ),
        (
            "concurrent",
            evidence_policy_with_limits(100, 100, 1, 100, 100, 100)?,
        ),
        (
            "rolling",
            evidence_policy_with_limits(100, 100, 10, 1, 100, 100)?,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let directory = TestDirectory::create(&format!("budget-{name}"))?;
        let marker = u8::try_from(case_index)?;
        let first_fixture = SessionFixture::with_session_marker(
            0x90_u8
                .checked_add(marker.checked_mul(2).ok_or(TestError("budget marker"))?)
                .ok_or(TestError("budget marker overflow"))?,
        )?;
        let second_fixture = SessionFixture::with_session_marker(
            0x91_u8
                .checked_add(marker.checked_mul(2).ok_or(TestError("budget marker"))?)
                .ok_or(TestError("budget marker overflow"))?,
        )?;
        let vault = ContractsNonceVaultV1::create_evidence_only(
            directory.capability()?,
            "contracts-store",
            StorageIdsV1::new(
                [0xa0_u8
                    .checked_add(marker)
                    .ok_or(TestError("budget wallet marker overflow"))?; 32],
                [0xb0_u8
                    .checked_add(marker)
                    .ok_or(TestError("budget vault marker overflow"))?; 32],
            )?,
            &Passphrase::new(format!("budget-{name}-passphrase").into_bytes())?,
            policy,
        )?;
        let mut signer = signer(vault, TestCustody::new(), &first_fixture, 0)?;
        let mut first_round = signer.begin_accepted_signing_round(first_fixture.accepted())?;
        let first = signer.claim_fresh(first_round.take_derivation_base()?)?;
        let mut second_round = signer.begin_accepted_signing_round(second_fixture.accepted())?;
        assert!(signer
            .claim_fresh(second_round.take_derivation_base()?)
            .is_err());
        signer.cancel_reserved(first)?;
    }

    let expiry_directory = TestDirectory::create("budget-window-expiry")?;
    let expiry_first = SessionFixture::with_session_marker(0xa0)?;
    let expiry_second = SessionFixture::with_session_marker(0xa1)?;
    let expiry_vault = ContractsNonceVaultV1::create_evidence_only(
        expiry_directory.capability()?,
        "contracts-store",
        StorageIdsV1::new([0xc0; 32], [0xc1; 32])?,
        &Passphrase::new(b"budget-window-expiry-passphrase".to_vec())?,
        evidence_policy_with_limits(100, 100, 10, 1, 10, 100)?,
    )?;
    let mut expiry_signer = signer(expiry_vault, TestCustody::new(), &expiry_first, 0)?;
    let mut expiry_round = expiry_signer.begin_accepted_signing_round(expiry_first.accepted())?;
    let _first = expiry_signer.claim_fresh(expiry_round.take_derivation_base()?)?;
    ContractsNonceVaultV1::set_evidence_test_time(Some(1_010));
    let mut after_window = expiry_signer.begin_accepted_signing_round(expiry_second.accepted())?;
    let _second = expiry_signer.claim_fresh(after_window.take_derivation_base()?)?;

    for (case_index, (first_time, second_time, maximum_step)) in
        [(1_100_u64, 1_099_u64, 100_u64), (1_200, 1_202, 1)]
            .into_iter()
            .enumerate()
    {
        let directory = TestDirectory::create(&format!("budget-clock-{case_index}"))?;
        let case_marker = u8::try_from(case_index)?;
        let first_fixture = SessionFixture::with_session_marker(
            0xb0_u8
                .checked_add(case_marker)
                .ok_or(TestError("clock fixture marker overflow"))?,
        )?;
        let second_fixture = SessionFixture::with_session_marker(
            0xb2_u8
                .checked_add(case_marker)
                .ok_or(TestError("clock fixture marker overflow"))?,
        )?;
        ContractsNonceVaultV1::set_evidence_test_time(Some(first_time));
        let vault = ContractsNonceVaultV1::create_evidence_only(
            directory.capability()?,
            "contracts-store",
            StorageIdsV1::new(
                [0xd0_u8
                    .checked_add(case_marker)
                    .ok_or(TestError("clock wallet marker overflow"))?; 32],
                [0xe0_u8
                    .checked_add(case_marker)
                    .ok_or(TestError("clock vault marker overflow"))?; 32],
            )?,
            &Passphrase::new(format!("budget-clock-{case_index}-passphrase").into_bytes())?,
            evidence_policy_with_limits(100, 100, 10, 100, 100, maximum_step)?,
        )?;
        let mut signer = signer(vault, TestCustody::new(), &first_fixture, 0)?;
        let mut first_round = signer.begin_accepted_signing_round(first_fixture.accepted())?;
        let _first = signer.claim_fresh(first_round.take_derivation_base()?)?;
        ContractsNonceVaultV1::set_evidence_test_time(Some(second_time));
        let mut second_round = signer.begin_accepted_signing_round(second_fixture.accepted())?;
        assert!(signer
            .claim_fresh(second_round.take_derivation_base()?)
            .is_err());
    }

    for (case_index, stage) in ["reserved", "commitment", "reveal"].into_iter().enumerate() {
        let directory = TestDirectory::create(&format!("budget-abort-{stage}"))?;
        let marker = u8::try_from(case_index)?;
        let first_fixture = SessionFixture::with_session_marker(
            0xc0_u8
                .checked_add(marker.checked_mul(2).ok_or(TestError("abort marker"))?)
                .ok_or(TestError("abort marker overflow"))?,
        )?;
        let second_fixture = SessionFixture::with_session_marker(
            0xc1_u8
                .checked_add(marker.checked_mul(2).ok_or(TestError("abort marker"))?)
                .ok_or(TestError("abort marker overflow"))?,
        )?;
        ContractsNonceVaultV1::set_evidence_test_time(Some(1_300));
        let vault = ContractsNonceVaultV1::create_evidence_only(
            directory.capability()?,
            "contracts-store",
            StorageIdsV1::new(
                [0xf0_u8
                    .checked_add(marker)
                    .ok_or(TestError("abort wallet marker overflow"))?; 32],
                [0xf4_u8
                    .checked_add(marker)
                    .ok_or(TestError("abort vault marker overflow"))?; 32],
            )?,
            &Passphrase::new(format!("budget-abort-{stage}-passphrase").into_bytes())?,
            evidence_policy_with_limits(1, 100, 10, 100, 100, 100)?,
        )?;
        let mut signer = signer(vault, TestCustody::new(), &first_fixture, 0)?;
        let mut round = signer.begin_accepted_signing_round(first_fixture.accepted())?;
        let reserved = signer.claim_fresh(round.take_derivation_base()?)?;
        match stage {
            "reserved" => {
                signer.cancel_reserved(reserved)?;
            }
            "commitment" => {
                let (commitment_state, _commitment) =
                    signer.derive_and_export_commitment(reserved)?;
                signer.cancel_after_commitment(commitment_state)?;
            }
            "reveal" => {
                let (commitment_state, commitment) =
                    signer.derive_and_export_commitment(reserved)?;
                let (message_a, next) = signed_message(
                    &first_fixture,
                    0,
                    0,
                    first_fixture.transcript,
                    KIND_COMMITMENT,
                    SigningPhaseV1::SigNonceCommit,
                    &commitment.to_bytes(),
                )?;
                let peer = NonceCommitmentV1::new(
                    PurposeV1::Refund,
                    first_fixture.signing_index(1)?,
                    [0xd7; 32],
                )
                .to_bytes();
                let (message_b, _) = signed_message(
                    &first_fixture,
                    1,
                    0,
                    next,
                    KIND_COMMITMENT,
                    SigningPhaseV1::SigNonceCommit,
                    &peer,
                )?;
                round.accept_message(&message_a)?;
                round.accept_message(&message_b)?;
                let reveal_authority = round.take_commitment_round()?;
                let (reveal_state, _reveal) =
                    signer.export_reveal(commitment_state, reveal_authority)?;
                signer.cancel_after_reveal(reveal_state)?;
            }
            _ => return Err(Box::new(TestError("unknown abort stage"))),
        }
        let mut second_round = signer.begin_accepted_signing_round(second_fixture.accepted())?;
        assert!(signer
            .claim_fresh(second_round.take_derivation_base()?)
            .is_err());
    }
    Ok(())
}

#[test]
fn public_spent_artifact_retirement_and_budget_survive_three_restore_hops(
) -> Result<(), Box<dyn Error>> {
    let fixture = SessionFixture::with_session_marker(0x7e)?;
    let source = TestDirectory::create("retirement-source")?;
    let source_unlock = b"retirement-source-unlock".to_vec();
    let source_backup_passphrase = b"retirement-source-backup".to_vec();
    let source_vault = ContractsNonceVaultV1::create_evidence_only(
        source.capability()?,
        "contracts-store",
        StorageIdsV1::new([0x5e; 32], [0x6e; 32])?,
        &Passphrase::new(source_unlock.clone())?,
        evidence_policy()?,
    )?;
    let custody = TestCustody::new();
    let mut source_signer = signer(source_vault, custody.clone(), &fixture, 0)?;
    let mut source_round = source_signer.begin_accepted_signing_round(fixture.accepted())?;
    let derivation = source_round.take_derivation_base()?;
    let reservation = source_signer.claim_fresh(derivation)?;
    let (spent_state, commitment) = source_signer.derive_and_export_commitment(reservation)?;
    let (message_a, next) = signed_message(
        &fixture,
        0,
        0,
        fixture.transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment.to_bytes(),
    )?;
    let synthetic_peer =
        NonceCommitmentV1::new(PurposeV1::Refund, fixture.signing_index(1)?, [0xbe; 32]).to_bytes();
    let (message_b, _) = signed_message(
        &fixture,
        1,
        0,
        next,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &synthetic_peer,
    )?;
    source_round.accept_message(&message_a)?;
    source_round.accept_message(&message_b)?;
    let pre_restore_resend_authority = spent_state.authorize_resend(&mut source_round)?;
    let lookup = custody.lookup()?;
    drop(source_signer);

    let mut source_backup_vault = ContractsNonceVaultV1::open_evidence_only(
        source.capability()?,
        "contracts-store",
        Passphrase::new(source_unlock)?,
        evidence_policy()?,
    )?;
    let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
    let source_backup = source_backup_vault
        .create_backup_evidence_only(Passphrase::new(source_backup_passphrase.clone())?, limits)?;
    let mut backup_name = canonical_backup_name(&source_backup);
    drop(source_backup_vault);

    let mut generations = vec![source];
    let mut backup_passphrase = source_backup_passphrase;
    let mut expected_budget: Option<Vec<u8>> = None;
    let mut expected_retirement: Option<Vec<u8>> = None;
    let mut final_unlock = Vec::new();
    for hop in 0_u8..3 {
        let target = TestDirectory::create(&format!("retirement-hop-{hop}"))?;
        let initial_unlock = format!("retirement-hop-{hop}-initial").into_bytes();
        let successor_unlock = format!("retirement-hop-{hop}-successor").into_bytes();
        let target_vault = ContractsNonceVaultV1::create_evidence_only(
            target.capability()?,
            "contracts-store",
            StorageIdsV1::new(
                [0x5e; 32],
                [0x80_u8
                    .checked_add(hop)
                    .ok_or(TestError("retirement vault marker overflow"))?; 32],
            )?,
            &Passphrase::new(initial_unlock.clone())?,
            evidence_policy()?,
        )?;
        drop(target_vault);
        let predecessor = generations
            .last()
            .ok_or(TestError("retirement predecessor is missing"))?;
        copy_directory_tree(
            &predecessor
                .path()
                .join("contracts-store")
                .join(&backup_name),
            &target.path().join("contracts-store").join(&backup_name),
        )?;
        let target_vault = ContractsNonceVaultV1::open_evidence_only(
            target.capability()?,
            "contracts-store",
            Passphrase::new(initial_unlock)?,
            evidence_policy()?,
        )?;
        target_vault.publish_existing_device_restore_evidence_only(
            &backup_name,
            Passphrase::new(backup_passphrase)?,
            Passphrase::new(successor_unlock.clone())?,
            limits,
        )?;
        let mut restored = ContractsNonceVaultV1::open_evidence_only(
            target.capability()?,
            "contracts-store",
            Passphrase::new(successor_unlock.clone())?,
            evidence_policy()?,
        )?;
        let (budget_carries, retirement_carries) = restored.authenticated_lifetime_carry_bytes()?;
        assert_eq!(budget_carries.len(), 1);
        assert_eq!(retirement_carries.len(), 1);
        assert_eq!(budget_carries[0].len(), BUDGET_CHARGE_NO_ADAPTOR_LEN);
        assert_eq!(retirement_carries[0].len(), PERMIT_RETIREMENT_LEN);
        assert_eq!(PERMIT_RETIREMENT_LEN, 229);
        match (&expected_budget, &expected_retirement) {
            (Some(budget), Some(retirement)) => {
                assert_eq!(&budget_carries[0], budget);
                assert_eq!(&retirement_carries[0], retirement);
            }
            (None, None) => {
                expected_budget = Some(budget_carries[0].clone());
                expected_retirement = Some(retirement_carries[0].clone());
            }
            _ => return Err(Box::new(TestError("incomplete carry baseline"))),
        }
        let next_backup_passphrase = format!("retirement-hop-{hop}-backup").into_bytes();
        let next_backup = restored.create_backup_evidence_only(
            Passphrase::new(next_backup_passphrase.clone())?,
            limits,
        )?;
        backup_name = canonical_backup_name(&next_backup);
        backup_passphrase = next_backup_passphrase;
        final_unlock = successor_unlock;
        drop(restored);
        generations.push(target);
    }

    let final_target = generations
        .last()
        .ok_or(TestError("final retirement target is missing"))?;
    let final_vault = ContractsNonceVaultV1::open_evidence_only(
        final_target.capability()?,
        "contracts-store",
        Passphrase::new(final_unlock.clone())?,
        evidence_policy()?,
    )?;
    let mut final_signer = signer(final_vault, custody.clone(), &fixture, 0)?;
    let mut final_round = final_signer.begin_accepted_signing_round(fixture.accepted())?;
    let final_derivation = final_round.take_derivation_base()?;
    if let Ok(ReservationResumeResultV1::Live(_)) =
        final_signer.resume_claimed(final_derivation, lookup)
    {
        return Err(Box::new(TestError(
            "successor restore recreated a live spent reservation",
        )));
    }
    assert!(final_signer
        .resend_after_restart(pre_restore_resend_authority)
        .is_err());
    drop(final_round);
    if let Ok(mut second_round) = final_signer.begin_accepted_signing_round(
        fixture.accepted_with_messages(&[message_a.as_slice(), message_b.as_slice()]),
    ) {
        if let Ok(old_state_authority) = spent_state.authorize_resend(&mut second_round) {
            assert!(final_signer
                .resend_commitment(&spent_state, old_state_authority)
                .is_err());
        }
    }
    drop(final_signer);

    let root = final_target.path().join("contracts-store");
    let active_generation = fs::read_dir(&root)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("generation-")
        })
        .max_by_key(|entry| entry.file_name())
        .ok_or(TestError("final retirement generation is missing"))?;
    let mut carry_paths = Vec::new();
    for entry in fs::read_dir(active_generation.path().join("journal"))? {
        let path = entry?.path();
        let bytes = fs::read(&path)?;
        let structural = UnauthenticatedJournalEntryV1::parse_structural(&bytes)?;
        if matches!(
            structural.payload(),
            UnauthenticatedJournalPayloadV1::BudgetCarryForward(_)
                | UnauthenticatedJournalPayloadV1::PermitRetirementCarryForward(_)
        ) {
            carry_paths.push(path);
        }
    }
    assert_eq!(carry_paths.len(), 2);
    for (case_index, carry_path) in carry_paths.into_iter().enumerate() {
        let case = TestDirectory::create(&format!("retirement-conflict-{case_index}"))?;
        copy_directory_tree(&root, &case.path().join("contracts-store"))?;
        let relative = carry_path.strip_prefix(&root)?;
        let mutated_path = case.path().join("contracts-store").join(relative);
        let mut bytes = fs::read(&mutated_path)?;
        let byte = bytes
            .get_mut(32)
            .ok_or(TestError("carry journal entry is truncated"))?;
        *byte ^= 0x01;
        fs::write(mutated_path, bytes)?;
        assert!(ContractsNonceVaultV1::open_evidence_only(
            case.capability()?,
            "contracts-store",
            Passphrase::new(final_unlock.clone())?,
            evidence_policy()?,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn canonical_vault_drives_public_signer_restart_and_exact_resend() -> Result<(), Box<dyn Error>> {
    let fixture = SessionFixture::new()?;
    let directories = [TestDirectory::create("a")?, TestDirectory::create("b")?];
    let passphrases = [
        b"canonical-signer-a-passphrase".to_vec(),
        b"canonical-signer-b-passphrase".to_vec(),
    ];
    let vault_a = ContractsNonceVaultV1::create_evidence_only(
        directories[0].capability()?,
        "contracts-store",
        StorageIdsV1::new([0x31; 32], [0x41; 32])?,
        &Passphrase::new(passphrases[0].clone())?,
        evidence_policy()?,
    )?;
    let vault_b = ContractsNonceVaultV1::create_evidence_only(
        directories[1].capability()?,
        "contracts-store",
        StorageIdsV1::new([0x32; 32], [0x42; 32])?,
        &Passphrase::new(passphrases[1].clone())?,
        evidence_policy()?,
    )?;
    let custody_a = TestCustody::new();
    let custody_b = TestCustody::new();
    let mut signer_a = signer(vault_a, custody_a.clone(), &fixture, 0)?;
    let mut signer_b = signer(vault_b, custody_b.clone(), &fixture, 1)?;
    let mut round_a = signer_a.begin_accepted_signing_round(fixture.accepted())?;
    let mut round_b = signer_b.begin_accepted_signing_round(fixture.accepted())?;
    let derivation_a = round_a.take_derivation_base()?;
    let derivation_b = round_b.take_derivation_base()?;
    let reserved_a = signer_a.claim_fresh(derivation_a)?;
    let reserved_b = signer_b.claim_fresh(derivation_b)?;
    let (lost_state_a, commitment_a) = signer_a.derive_and_export_commitment(reserved_a)?;
    let (commitment_state_b, commitment_b) = signer_b.derive_and_export_commitment(reserved_b)?;

    let mut transcript = fixture.transcript;
    let (commitment_message_a, next) = signed_message(
        &fixture,
        0,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_a.to_bytes(),
    )?;
    transcript = next;
    let (commitment_message_b, next) = signed_message(
        &fixture,
        1,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_b.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        assert_eq!(
            round.accept_message(&commitment_message_a)?,
            AcceptedMessageDispositionV1::Advanced
        );
        assert_eq!(
            round.accept_message(&commitment_message_b)?,
            AcceptedMessageDispositionV1::Advanced
        );
    }

    let lookup_a = custody_a.lookup()?;
    // The opaque state retains the canonical reservation handle and therefore
    // its process lock. A restart test must drop it before opening a new
    // authority instance; the persisted commitment is the only recovery input.
    drop(lost_state_a);
    drop(round_a);
    drop(signer_a);
    let reopened_a = ContractsNonceVaultV1::open_evidence_only(
        directories[0].capability()?,
        "contracts-store",
        Passphrase::new(passphrases[0].clone())?,
        evidence_policy()?,
    )?;
    signer_a = signer(reopened_a, custody_a.clone(), &fixture, 0)?;
    round_a = signer_a.begin_accepted_signing_round(fixture.accepted())?;
    let resume_base = round_a.take_derivation_base()?;
    let resumed = signer_a.resume_claimed(resume_base, lookup_a)?;
    let commitment_state_a = match resumed {
        ReservationResumeResultV1::Live(dom_adaptor::ResumedReservationV1::AfterCommitment(
            state,
        )) => state,
        _ => return Err(Box::new(TestError("unexpected resumed reservation stage"))),
    };
    // Resume consumes the derivation base before replay. Replaying a prefix
    // first correctly refuses a second derivation authority.
    round_a.accept_message(&commitment_message_a)?;
    round_a.accept_message(&commitment_message_b)?;
    let resend = commitment_state_a.authorize_resend(&mut round_a)?;
    match signer_a.resend_commitment(&commitment_state_a, resend)? {
        ResentArtifactV1::NonceCommitment(value) => assert_eq!(value, commitment_a),
        _ => return Err(Box::new(TestError("unexpected resent artifact"))),
    }

    let reveal_authority_a = round_a.take_commitment_round()?;
    let (reveal_state_a, reveal_a) =
        signer_a.export_reveal(commitment_state_a, reveal_authority_a)?;
    let (reveal_message_a, next) = signed_message(
        &fixture,
        0,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_a.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&reveal_message_a)?;
    }
    let reveal_authority_b = round_b.take_commitment_round()?;
    let (reveal_state_b, reveal_b) =
        signer_b.export_reveal(commitment_state_b, reveal_authority_b)?;
    let (reveal_message_b, next) = signed_message(
        &fixture,
        1,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_b.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&reveal_message_b)?;
    }

    drop(reveal_state_a);
    drop(round_a);
    drop(signer_a);
    let reopened_after_reveal = ContractsNonceVaultV1::open_evidence_only(
        directories[0].capability()?,
        "contracts-store",
        Passphrase::new(passphrases[0].clone())?,
        evidence_policy()?,
    )?;
    signer_a = signer(reopened_after_reveal, custody_a.clone(), &fixture, 0)?;
    round_a = signer_a.begin_accepted_signing_round(fixture.accepted())?;
    let reveal_resume_base = round_a.take_derivation_base()?;
    let reveal_resumed = signer_a.resume_claimed(reveal_resume_base, custody_a.lookup()?)?;
    let reveal_state_a = match reveal_resumed {
        ReservationResumeResultV1::Live(dom_adaptor::ResumedReservationV1::AfterReveal(state)) => {
            state
        }
        _ => {
            return Err(Box::new(TestError(
                "unexpected post-reveal resumed reservation stage",
            )))
        }
    };
    round_a.accept_message(&commitment_message_a)?;
    round_a.accept_message(&commitment_message_b)?;
    round_a.accept_message(&reveal_message_a)?;
    round_a.accept_message(&reveal_message_b)?;
    let reveal_resend = reveal_state_a.authorize_resend(&mut round_a)?;
    match signer_a.resend_reveal(&reveal_state_a, reveal_resend)? {
        ResentArtifactV1::NonceReveal(value) => assert_eq!(value, reveal_a),
        _ => return Err(Box::new(TestError("unexpected resent reveal artifact"))),
    }

    let partial_authority_a = round_a.take_reveal_round()?;
    let (terminal_a, partial_a) =
        signer_a.sign_and_export_partial(reveal_state_a, partial_authority_a)?;
    let (partial_message_a, next) = signed_message(
        &fixture,
        0,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_a.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&partial_message_a)?;
    }
    let partial_authority_b = round_b.take_reveal_round()?;
    let (_terminal_b, partial_b) =
        signer_b.sign_and_export_partial(reveal_state_b, partial_authority_b)?;
    let (partial_message_b, _) = signed_message(
        &fixture,
        1,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_b.to_bytes(),
    )?;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&partial_message_b)?;
    }
    let partial_resend = terminal_a.authorize_resend(&mut round_a)?;
    match signer_a.resend_partial(&terminal_a, partial_resend)? {
        ResentArtifactV1::PartialSignature(value) => {
            assert_eq!(value.to_bytes(), partial_a.to_bytes());
        }
        _ => return Err(Box::new(TestError("unexpected resent partial"))),
    }
    assert!(terminal_a.authorize_resend(&mut round_a).is_err());
    assert!(directories[0].path().join("contracts-store").is_dir());
    Ok(())
}

#[test]
fn canonical_vault_authorizes_partial_restart_resend_through_the_public_seam(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("partial-restart-public-seam")?;
    let passphrase = b"partial-restart-public-seam-passphrase".to_vec();
    let scenario =
        complete_partial_for_first_participant(&directory, &passphrase, "partial-restart", false)?;
    let accepted_prefix = scenario
        .accepted_prefix
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();

    let reopened = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(passphrase.clone())?,
        evidence_policy()?,
    )?;
    let mut restarted = signer(reopened, scenario.custody.clone(), &scenario.fixture, 0)?;
    let mut restarted_round = restarted
        .begin_accepted_signing_round(scenario.fixture.accepted_with_messages(&accepted_prefix))?;
    let authorization = restarted
        .authorize_partial_resend_after_restart(&mut restarted_round, scenario.lookup.clone())?;
    match restarted.resend_after_restart(authorization)? {
        ResentArtifactV1::PartialSignature(partial) => {
            assert_eq!(partial.to_bytes(), scenario.partial_bytes);
        }
        _ => return Err(Box::new(TestError("unexpected restarted partial artifact"))),
    }
    assert!(restarted
        .authorize_partial_resend_after_restart(&mut restarted_round, scenario.lookup.clone())
        .is_err());
    drop(restarted);

    let reopened_again = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(passphrase)?,
        evidence_policy()?,
    )?;
    let mut second_process = signer(
        reopened_again,
        scenario.custody.clone(),
        &scenario.fixture,
        0,
    )?;
    let mut second_round = second_process
        .begin_accepted_signing_round(scenario.fixture.accepted_with_messages(&accepted_prefix))?;
    let second_authorization = second_process
        .authorize_partial_resend_after_restart(&mut second_round, scenario.lookup)?;
    match second_process.resend_after_restart(second_authorization)? {
        ResentArtifactV1::PartialSignature(partial) => {
            assert_eq!(partial.to_bytes(), scenario.partial_bytes);
        }
        _ => {
            return Err(Box::new(TestError(
                "unexpected second-process partial artifact",
            )))
        }
    }
    Ok(())
}

#[test]
fn partial_persistence_process_death_cuts_have_exact_fail_closed_outcomes(
) -> Result<(), Box<dyn Error>> {
    let cuts = [
        "partial-before-exposure-projection",
        "partial-after-exposure-before-tombstone",
        "partial-after-tombstone-before-journal",
        "partial-after-journal-before-secret-unlink",
        "partial-after-secret-unlink-before-active-head",
        "partial-after-terminal-commit-before-return",
    ];
    for cut in cuts {
        let directory = TestDirectory::create(&format!("partial-crash-{cut}"))?;
        let marker = directory.path().join("partial-crash-cut.marker");
        let precommit_evidence = directory.path().join("partial-precommit.evidence");
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::signer_e2e::child_partial_persistence_aborts_at_exact_cut")
            .env("DOM_G1B_PARTIAL_CRASH_ROOT", directory.path())
            .env("DOM_G1B_NORMAL_VAULT_CRASH_CUT", cut)
            .env("DOM_G1B_NORMAL_VAULT_CRASH_MARKER", &marker)
            .env("DOM_G1B_PARTIAL_PRECOMMIT_EVIDENCE", &precommit_evidence)
            .current_dir(directory.path())
            .status()?;
        assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
        assert_eq!(fs::read(marker)?, cut.as_bytes());

        let (durable_lookup, transcript, messages) =
            read_partial_precommit_evidence(&precommit_evidence)?;
        let lookup = durable_lookup.lookup.clone();
        let fixture = SessionFixture::new()?;
        let opened = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(b"partial-crash-passphrase".to_vec())?,
            evidence_policy()?,
        )?;
        if cut == "partial-before-exposure-projection" {
            assert!(read_unique_partial(
                &directory.path().join("contracts-store"),
                ExposureStateV1::Persisted,
            )
            .is_err());
            let mut restarted = signer(
                opened,
                TestCustody::from_durable(durable_lookup.clone()),
                &fixture,
                0,
            )?;
            let mut round = restarted.begin_accepted_signing_round(fixture.accepted())?;
            assert!(matches!(
                restarted.resume_claimed(round.take_derivation_base()?, lookup.clone())?,
                ReservationResumeResultV1::Terminal(terminal)
                    if terminal.state == dom_adaptor::ReservationState::Burned
            ));
            drop(restarted);
        } else {
            let exact_partial = read_unique_partial(
                &directory.path().join("contracts-store"),
                ExposureStateV1::Persisted,
            )?;
            let (partial_message, _) = signed_message(
                &fixture,
                0,
                2,
                transcript,
                KIND_PARTIAL,
                SigningPhaseV1::SigPartial,
                &exact_partial,
            )?;
            let mut accepted = messages;
            accepted.push(partial_message);
            let refs = accepted.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let mut restarted = signer(
                opened,
                TestCustody::from_durable(durable_lookup.clone()),
                &fixture,
                0,
            )?;
            let mut round =
                restarted.begin_accepted_signing_round(fixture.accepted_with_messages(&refs))?;
            assert!(restarted
                .authorize_partial_resend_after_restart(&mut round, lookup.clone())
                .is_err());
            drop(restarted);
        }

        let reopened = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(b"partial-crash-passphrase".to_vec())?,
            evidence_policy()?,
        )?;
        let mut no_recompute = signer(
            reopened,
            TestCustody::from_durable(durable_lookup),
            &fixture,
            0,
        )?;
        let mut fresh_round = no_recompute.begin_accepted_signing_round(fixture.accepted())?;
        assert!(no_recompute
            .claim_fresh(fresh_round.take_derivation_base()?)
            .is_err());
    }
    Ok(())
}

#[test]
fn partial_export_process_death_after_spent_before_return_resends_exactly(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("partial-export-spent-crash")?;
    let marker = directory.path().join("partial-export-spent-crash.marker");
    let precommit_evidence = directory.path().join("partial-precommit.evidence");
    let status = Command::new(std::env::current_exe()?)
        .arg("--ignored")
        .arg("--exact")
        .arg("runtime::linux::signer_e2e::child_partial_persistence_aborts_at_exact_cut")
        .env("DOM_G1B_PARTIAL_CRASH_ROOT", directory.path())
        .env(
            "DOM_G1B_NORMAL_VAULT_CRASH_CUT",
            "partial-export-after-durable-spent-before-return",
        )
        .env("DOM_G1B_NORMAL_VAULT_CRASH_MARKER", &marker)
        .env("DOM_G1B_PARTIAL_PRECOMMIT_EVIDENCE", &precommit_evidence)
        .current_dir(directory.path())
        .status()?;
    assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
    assert_eq!(
        fs::read(marker)?,
        b"partial-export-after-durable-spent-before-return"
    );

    let (durable_lookup, transcript, mut messages) =
        read_partial_precommit_evidence(&precommit_evidence)?;
    let lookup = durable_lookup.lookup.clone();
    let exact_partial = read_unique_partial(
        &directory.path().join("contracts-store"),
        ExposureStateV1::Spent,
    )?;
    let fixture = SessionFixture::new()?;
    let (partial_message, _) = signed_message(
        &fixture,
        0,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &exact_partial,
    )?;
    messages.push(partial_message);
    let refs = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let reopened = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(b"partial-crash-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let mut restarted = signer(
        reopened,
        TestCustody::from_durable(durable_lookup),
        &fixture,
        0,
    )?;
    let mut round =
        restarted.begin_accepted_signing_round(fixture.accepted_with_messages(&refs))?;
    let authorization =
        restarted.authorize_partial_resend_after_restart(&mut round, lookup.clone())?;
    match restarted.resend_after_restart(authorization)? {
        ResentArtifactV1::PartialSignature(partial) => {
            assert_eq!(partial.to_bytes(), exact_partial);
        }
        _ => {
            return Err(Box::new(TestError(
                "unexpected spent-crash partial artifact",
            )))
        }
    }
    assert!(restarted
        .authorize_partial_resend_after_restart(&mut round, lookup)
        .is_err());
    Ok(())
}

#[test]
fn partial_send_process_death_without_ack_preserves_only_exact_resend() -> Result<(), Box<dyn Error>>
{
    for cut in ["during-simulated-send", "after-send-before-ack"] {
        let directory = TestDirectory::create(&format!("partial-send-crash-{cut}"))?;
        let marker = directory.path().join("partial-send-crash.marker");
        let evidence = directory.path().join("partial-restart.evidence");
        let simulated_send = directory.path().join("simulated-send.bin");
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::signer_e2e::child_partial_send_aborts_without_ack")
            .env("DOM_G1B_PARTIAL_CRASH_ROOT", directory.path())
            .env("DOM_G1B_PARTIAL_SEND_CRASH_CUT", cut)
            .env("DOM_G1B_PARTIAL_SEND_CRASH_MARKER", &marker)
            .env("DOM_G1B_PARTIAL_RESTART_EVIDENCE", &evidence)
            .env("DOM_G1B_PARTIAL_SIMULATED_SEND", &simulated_send)
            .current_dir(directory.path())
            .status()?;
        assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
        assert_eq!(fs::read(marker)?, cut.as_bytes());

        let (lookup, expected_partial, messages) = read_partial_restart_evidence(&evidence)?;
        let sent = fs::read(simulated_send)?;
        if cut == "during-simulated-send" {
            assert_eq!(sent, expected_partial[..expected_partial.len() / 2]);
        } else {
            assert_eq!(sent, expected_partial);
        }
        let fixture = SessionFixture::new()?;
        let reopened = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(b"partial-send-crash-passphrase".to_vec())?,
            evidence_policy()?,
        )?;
        let mut signer = signer(reopened, TestCustody::new(), &fixture, 0)?;
        let message_refs = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut round =
            signer.begin_accepted_signing_round(fixture.accepted_with_messages(&message_refs))?;
        let authorization =
            signer.authorize_partial_resend_after_restart(&mut round, lookup.clone())?;
        match signer.resend_after_restart(authorization)? {
            ResentArtifactV1::PartialSignature(partial) => {
                assert_eq!(partial.to_bytes(), expected_partial);
            }
            _ => return Err(Box::new(TestError("unexpected crash-recovered partial"))),
        }
        assert!(signer
            .authorize_partial_resend_after_restart(&mut round, lookup)
            .is_err());
    }
    Ok(())
}

#[test]
fn terminal_partial_store_lock_rejects_a_second_process_and_then_resends_exactly(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("partial-concurrent-process")?;
    let passphrase = b"partial-concurrent-process-passphrase".to_vec();
    let scenario = complete_partial_for_first_participant(
        &directory,
        &passphrase,
        "partial-concurrent-process",
        false,
    )?;
    let held_vault = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(passphrase.clone())?,
        evidence_policy()?,
    )?;
    let status = Command::new(std::env::current_exe()?)
        .arg("--ignored")
        .arg("--exact")
        .arg("runtime::linux::signer_e2e::child_partial_store_observes_busy_authority")
        .env("DOM_G1B_PARTIAL_CRASH_ROOT", directory.path())
        .current_dir(directory.path())
        .status()?;
    assert!(status.success());
    drop(held_vault);

    let reopened = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(passphrase)?,
        evidence_policy()?,
    )?;
    let mut signer = signer(reopened, TestCustody::new(), &scenario.fixture, 0)?;
    let message_refs = scenario
        .accepted_prefix
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let mut round = signer
        .begin_accepted_signing_round(scenario.fixture.accepted_with_messages(&message_refs))?;
    let authorization =
        signer.authorize_partial_resend_after_restart(&mut round, scenario.lookup)?;
    match signer.resend_after_restart(authorization)? {
        ResentArtifactV1::PartialSignature(partial) => {
            assert_eq!(partial.to_bytes(), scenario.partial_bytes);
        }
        _ => return Err(Box::new(TestError("unexpected post-lock partial"))),
    }
    Ok(())
}

#[test]
fn old_pre_partial_backup_restore_preserves_terminal_tombstone_and_rejects_resend(
) -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("partial-old-backup-restore")?;
    let initial_passphrase = b"partial-old-backup-initial-passphrase".to_vec();
    let successor_passphrase = b"partial-old-backup-successor-passphrase".to_vec();
    let scenario = complete_partial_for_first_participant(
        &directory,
        &initial_passphrase,
        "partial-old-backup",
        true,
    )?;
    let backup_name = canonical_backup_name(
        scenario
            .pre_partial_backup
            .as_ref()
            .ok_or(TestError("pre-partial backup is missing"))?,
    );
    let current = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(initial_passphrase)?,
        evidence_policy()?,
    )?;
    current.publish_existing_device_restore_evidence_only(
        &backup_name,
        Passphrase::new(b"partial-old-backup-passphrase".to_vec())?,
        Passphrase::new(successor_passphrase.clone())?,
        BackupPolicyLimitsV1::new(64, 1_048_576)?,
    )?;

    let restored = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(successor_passphrase)?,
        evidence_policy()?,
    )?;
    let mut restored_signer = signer(restored, scenario.custody.clone(), &scenario.fixture, 0)?;
    let message_refs = scenario
        .accepted_prefix
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let mut round = restored_signer
        .begin_accepted_signing_round(scenario.fixture.accepted_with_messages(&message_refs))?;
    // A successor generation retains the predecessor tombstone as historical
    // anti-rollback evidence. It must not mint a resend capability for a
    // predecessor reservation, even if its partial bytes were exact.
    assert!(restored_signer
        .authorize_partial_resend_after_restart(&mut round, scenario.lookup.clone())
        .is_err());
    // The rejected authorization still owns the accepted-round reservation.
    // Release it before proving that the same persisted identity cannot be
    // resumed or claimed through a new public round.
    drop(round);
    drop(restored_signer);
    let retry = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(b"partial-old-backup-successor-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let mut retry_signer = signer(retry, scenario.custody.clone(), &scenario.fixture, 0)?;
    if let Ok(mut no_recompute) =
        retry_signer.begin_accepted_signing_round(scenario.fixture.accepted())
    {
        if let Ok(ReservationResumeResultV1::Live(_)) = retry_signer.resume_claimed(
            no_recompute.take_derivation_base()?,
            scenario.lookup.clone(),
        ) {
            return Err(Box::new(TestError(
                "predecessor backup recreated a live reservation",
            )));
        }
    }
    drop(retry_signer);
    let fresh = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(b"partial-old-backup-successor-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let mut fresh_signer = signer(fresh, scenario.custody.clone(), &scenario.fixture, 0)?;
    if let Ok(mut no_fresh_claim) =
        fresh_signer.begin_accepted_signing_round(scenario.fixture.accepted())
    {
        assert!(fresh_signer
            .claim_fresh(no_fresh_claim.take_derivation_base()?)
            .is_err());
    }
    Ok(())
}

#[test]
fn partial_restart_resend_revalidates_every_durable_authority_component(
) -> Result<(), Box<dyn Error>> {
    for component in ["root", "active", "journal", "partial-exposure"] {
        let directory = TestDirectory::create(&format!("partial-authority-{component}"))?;
        let passphrase = format!("partial-authority-{component}-passphrase").into_bytes();
        let scenario = complete_partial_for_first_participant(
            &directory,
            &passphrase,
            &format!("partial-authority-{component}"),
            false,
        )?;
        let reopened = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(passphrase)?,
            evidence_policy()?,
        )?;
        let mut signer = signer(reopened, TestCustody::new(), &scenario.fixture, 0)?;
        let message_refs = scenario
            .accepted_prefix
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut round = signer
            .begin_accepted_signing_round(scenario.fixture.accepted_with_messages(&message_refs))?;
        let authorization =
            signer.authorize_partial_resend_after_restart(&mut round, scenario.lookup)?;

        let root = directory.path().join("contracts-store");
        let active_generation = fs::read_dir(&root)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("generation-")
            })
            .max_by_key(|entry| entry.file_name())
            .ok_or(TestError("partial resend generation is missing"))?;
        let mutation_path = match component {
            "root" => root.join("store-root-identity.bin"),
            "active" => root.join("active-vault-generation"),
            "journal" => fs::read_dir(active_generation.path().join("journal"))?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
                .max_by_key(|entry| entry.file_name())
                .ok_or(TestError("partial resend journal entry is missing"))?
                .path(),
            "partial-exposure" => {
                let mut found = None;
                for exposure in
                    canonical_exposure_record_paths(&active_generation.path().join("exposures"))?
                {
                    let bytes = fs::read(&exposure)?;
                    let structural = UnauthenticatedExposureRecordV1::parse_structural(&bytes)?;
                    if structural.artifact() == ArtifactKindV1::PartialSignature
                        && structural.state() == ExposureStateV1::Spent
                        && found.replace(exposure).is_some()
                    {
                        return Err(Box::new(TestError("duplicate spent partial exposure")));
                    }
                }
                found.ok_or(TestError("spent partial exposure is missing"))?
            }
            _ => return Err(Box::new(TestError("unknown partial authority component"))),
        };
        let _resend_interposition = install_resend_interposition(Box::new(move || {
            let mut bytes = fs::read(&mutation_path).map_err(|_| InventoryError::Filesystem)?;
            let byte = bytes
                .get_mut(32)
                .ok_or(InventoryError::RestoreQuarantined)?;
            *byte ^= 0x01;
            fs::write(&mutation_path, bytes).map_err(|_| InventoryError::Filesystem)
        }))?;
        assert!(signer.resend_after_restart(authorization).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "subprocess helper for exact partial-persistence crash cuts"]
fn child_partial_persistence_aborts_at_exact_cut() -> Result<(), Box<dyn Error>> {
    let root = std::env::var_os("DOM_G1B_PARTIAL_CRASH_ROOT")
        .ok_or(TestError("partial crash root is missing"))?;
    let directory = TestDirectory(PathBuf::from(root));
    if std::env::var_os("DOM_G1B_PARTIAL_PRECOMMIT_EVIDENCE").is_none() {
        return Err(Box::new(TestError(
            "partial precommit evidence path is missing",
        )));
    }
    let result = complete_partial_for_first_participant(
        &directory,
        b"partial-crash-passphrase",
        "partial-crash-child",
        false,
    );
    std::mem::forget(directory);
    result?;
    Err(Box::new(TestError("partial crash hook was not reached")))
}

#[test]
#[ignore = "subprocess helper for simulated partial-send crash cuts"]
fn child_partial_send_aborts_without_ack() -> Result<(), Box<dyn Error>> {
    let root = std::env::var_os("DOM_G1B_PARTIAL_CRASH_ROOT")
        .ok_or(TestError("partial send crash root is missing"))?;
    let evidence_path = PathBuf::from(
        std::env::var_os("DOM_G1B_PARTIAL_RESTART_EVIDENCE")
            .ok_or(TestError("partial restart evidence path is missing"))?,
    );
    let simulated_send_path = PathBuf::from(
        std::env::var_os("DOM_G1B_PARTIAL_SIMULATED_SEND")
            .ok_or(TestError("partial simulated-send path is missing"))?,
    );
    let marker_path = PathBuf::from(
        std::env::var_os("DOM_G1B_PARTIAL_SEND_CRASH_MARKER")
            .ok_or(TestError("partial send crash marker is missing"))?,
    );
    let cut = std::env::var("DOM_G1B_PARTIAL_SEND_CRASH_CUT")?;
    let directory = TestDirectory(PathBuf::from(root));
    let scenario = complete_partial_for_first_participant(
        &directory,
        b"partial-send-crash-passphrase",
        "partial-send-child",
        false,
    )?;
    write_partial_restart_evidence(&evidence_path, &scenario)?;
    let reopened = ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(b"partial-send-crash-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let mut signer = signer(reopened, TestCustody::new(), &scenario.fixture, 0)?;
    let message_refs = scenario
        .accepted_prefix
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let mut round = signer
        .begin_accepted_signing_round(scenario.fixture.accepted_with_messages(&message_refs))?;
    let authorization =
        signer.authorize_partial_resend_after_restart(&mut round, scenario.lookup)?;
    let partial_bytes = scenario.partial_bytes;
    let _resend_interposition = install_resend_interposition(Box::new(move || {
        let sent = if cut == "during-simulated-send" {
            &partial_bytes[..partial_bytes.len() / 2]
        } else if cut == "after-send-before-ack" {
            partial_bytes.as_slice()
        } else {
            return Err(InventoryError::RestoreQuarantined);
        };
        let mut simulated_send = File::options()
            .create_new(true)
            .write(true)
            .open(simulated_send_path)
            .map_err(|_| InventoryError::Filesystem)?;
        simulated_send
            .write_all(sent)
            .and_then(|()| simulated_send.sync_all())
            .map_err(|_| InventoryError::Filesystem)?;
        let mut marker = File::options()
            .create_new(true)
            .write(true)
            .open(marker_path)
            .map_err(|_| InventoryError::Filesystem)?;
        marker
            .write_all(cut.as_bytes())
            .and_then(|()| marker.sync_all())
            .map_err(|_| InventoryError::Filesystem)?;
        process::abort();
    }))?;
    let result = signer.resend_after_restart(authorization);
    std::mem::forget(directory);
    result?;
    Err(Box::new(TestError(
        "partial send crash hook was not reached",
    )))
}

#[test]
#[ignore = "subprocess helper for terminal partial process-lock evidence"]
fn child_partial_store_observes_busy_authority() -> Result<(), Box<dyn Error>> {
    let root = std::env::var_os("DOM_G1B_PARTIAL_CRASH_ROOT")
        .ok_or(TestError("partial lock root is missing"))?;
    let directory = TestDirectory(PathBuf::from(root));
    assert!(ContractsNonceVaultV1::open_evidence_only(
        directory.capability()?,
        "contracts-store",
        Passphrase::new(b"partial-concurrent-process-passphrase".to_vec())?,
        evidence_policy()?,
    )
    .is_err());
    std::mem::forget(directory);
    Ok(())
}

/// G1A x G1B composition: two canonical Contracts vaults drive a complete
/// two-party signing round whose aggregated result is accepted by the real
/// DOM consensus verifier.
///
/// Every prior public-seam test stops at the partial-signature exchange. This
/// test closes the remaining link: the two vault-authorized partials are
/// bound, aggregated, and written into the transaction kernel, and the exact
/// transaction is then validated by `dom_consensus::validate_kernel_signatures`
/// — the same function the block pipeline calls — under the fixture chain
/// identifier. The aggregation runs only over public artifacts exported
/// through the seam (reveals and partials); no vault secret is touched.
#[test]
fn canonical_vaults_compose_into_a_consensus_verified_final_signature() -> Result<(), Box<dyn Error>>
{
    let fixture = SessionFixture::with_session_marker(0x7a)?;
    let directories = [
        TestDirectory::create("compose-a")?,
        TestDirectory::create("compose-b")?,
    ];
    let vault_a = ContractsNonceVaultV1::create_evidence_only(
        directories[0].capability()?,
        "contracts-store",
        StorageIdsV1::new([0x33; 32], [0x43; 32])?,
        &Passphrase::new(b"composition-signer-a-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let vault_b = ContractsNonceVaultV1::create_evidence_only(
        directories[1].capability()?,
        "contracts-store",
        StorageIdsV1::new([0x34; 32], [0x44; 32])?,
        &Passphrase::new(b"composition-signer-b-passphrase".to_vec())?,
        evidence_policy()?,
    )?;
    let mut signer_a = signer(vault_a, TestCustody::new(), &fixture, 0)?;
    let mut signer_b = signer(vault_b, TestCustody::new(), &fixture, 1)?;
    let mut round_a = signer_a.begin_accepted_signing_round(fixture.accepted())?;
    let mut round_b = signer_b.begin_accepted_signing_round(fixture.accepted())?;
    let reserved_a = signer_a.claim_fresh(round_a.take_derivation_base()?)?;
    let reserved_b = signer_b.claim_fresh(round_b.take_derivation_base()?)?;
    let (commitment_state_a, commitment_a) = signer_a.derive_and_export_commitment(reserved_a)?;
    let (commitment_state_b, commitment_b) = signer_b.derive_and_export_commitment(reserved_b)?;

    let mut transcript = fixture.transcript;
    let (commitment_message_a, next) = signed_message(
        &fixture,
        0,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_a.to_bytes(),
    )?;
    transcript = next;
    let (commitment_message_b, next) = signed_message(
        &fixture,
        1,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_b.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        assert_eq!(
            round.accept_message(&commitment_message_a)?,
            AcceptedMessageDispositionV1::Advanced
        );
        assert_eq!(
            round.accept_message(&commitment_message_b)?,
            AcceptedMessageDispositionV1::Advanced
        );
    }

    let (reveal_state_a, reveal_a) =
        signer_a.export_reveal(commitment_state_a, round_a.take_commitment_round()?)?;
    let (reveal_message_a, next) = signed_message(
        &fixture,
        0,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_a.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&reveal_message_a)?;
    }
    let (reveal_state_b, reveal_b) =
        signer_b.export_reveal(commitment_state_b, round_b.take_commitment_round()?)?;
    let (reveal_message_b, next) = signed_message(
        &fixture,
        1,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_b.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&reveal_message_b)?;
    }

    let (_terminal_a, partial_a) =
        signer_a.sign_and_export_partial(reveal_state_a, round_a.take_reveal_round()?)?;
    let (partial_message_a, next) = signed_message(
        &fixture,
        0,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_a.to_bytes(),
    )?;
    transcript = next;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&partial_message_a)?;
    }
    let (_terminal_b, partial_b) =
        signer_b.sign_and_export_partial(reveal_state_b, round_b.take_reveal_round()?)?;
    let (partial_message_b, _) = signed_message(
        &fixture,
        1,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_b.to_bytes(),
    )?;
    for round in [&mut round_a, &mut round_b] {
        round.accept_message(&partial_message_b)?;
    }

    // From here on the composition uses only public exported artifacts.
    let (_, template_hash) = canonical_template_v1(&fixture.transaction)?;
    // The canonical participant index addresses the signing keys in strictly
    // ascending compressed-byte order, which is not the roster entry order.
    let mut canonical_keys: Vec<PublicKey> = fixture
        .roster
        .entries()
        .iter()
        .map(|entry| entry.signing_public_key().clone())
        .collect();
    canonical_keys.sort_by_key(PublicKey::to_compressed_bytes);
    let reveals = [&reveal_a, &reveal_b];
    let mut participants = Vec::with_capacity(reveals.len());
    for reveal in reveals {
        participants.push(ParticipantPublicNoncesV1 {
            participant_index: reveal.participant_index(),
            signing_key: canonical_keys[usize::from(reveal.participant_index())].clone(),
            first_nonce: reveal.first().clone(),
            second_nonce: reveal.second().clone(),
        });
    }
    participants.sort_by_key(|participant| participant.participant_index);
    let binding = binding_factor_v1(
        &BindingContextV1 {
            chain_id: *fixture.chain.as_bytes(),
            session_id: fixture.session_id,
            purpose: PurposeV1::Refund,
            template_hash,
        },
        &participants,
        None,
    )?;
    let mut bound_nonces = Vec::with_capacity(participants.len());
    for participant in &participants {
        bound_nonces
            .push(binding.bind_public_nonces(&participant.first_nonce, &participant.second_nonce)?);
    }
    let aggregate_nonce = scriptless_add_public_points(&bound_nonces)?;
    let kernel = &fixture.transaction.kernels[0];
    let aggregate_signing_key = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())?;
    let kernel_message = scriptless_kernel_message_digest_v1(kernel);
    let challenge = schnorr_challenge(
        &aggregate_nonce.to_compressed_bytes(),
        &aggregate_signing_key,
        fixture.chain.as_bytes(),
        kernel_message.as_bytes(),
    );

    // Each vault-authorized partial satisfies s_i*G == R_i + e*X_i for its
    // own bound nonce and signing key before any aggregation happens.
    let mut scalars = Vec::with_capacity(2);
    for partial in [&partial_a, &partial_b] {
        let bytes = partial.to_bytes();
        let index = usize::from(u16::from_le_bytes([bytes[1], bytes[2]]));
        let scalar = PartialSig::from_bytes(&bytes[35..])?;
        assert!(
            scriptless_verify_bound_partial(
                &scalar,
                &bound_nonces[index],
                &participants[index].signing_key,
                challenge.as_bytes(),
            )?,
            "vault-authorized partial {index} fails its bound equation"
        );
        scalars.push(scalar);
    }

    let aggregate_scalar = scriptless_aggregate_partial_scalars(&scalars)?;
    let mut signature_bytes = [0u8; 65];
    signature_bytes[..33].copy_from_slice(&aggregate_nonce.to_compressed_bytes());
    signature_bytes[33..].copy_from_slice(&aggregate_scalar.to_bytes());
    let signature = SchnorrSignature::from_bytes(&signature_bytes)?;
    assert!(scriptless_verify_final_signature(
        &signature,
        &aggregate_signing_key,
        fixture.chain.as_bytes(),
        kernel_message.as_bytes(),
    )?);

    // The exact composed transaction passes the real block-pipeline verifier.
    let mut transaction = fixture.transaction.clone();
    transaction.kernels[0].excess_signature = signature.to_bytes();
    validate_kernel_signatures(&transaction, fixture.chain.as_bytes())?;

    // A different chain identifier must reject the same transaction.
    assert!(validate_kernel_signatures(&transaction, &[0x5c; 32]).is_err());

    // A single flipped bit in either partial's scalar must break the final
    // aggregate against the consensus verifier.
    for flip_index in 0..scalars.len() {
        let mut mutated_scalars = Vec::with_capacity(scalars.len());
        for (position, scalar) in scalars.iter().enumerate() {
            let mut bytes = scalar.to_bytes();
            if position == flip_index {
                bytes[31] ^= 0x01;
            }
            mutated_scalars.push(PartialSig::from_bytes(&bytes)?);
        }
        let mutated_aggregate = scriptless_aggregate_partial_scalars(&mutated_scalars)?;
        let mut mutated_signature = [0u8; 65];
        mutated_signature[..33].copy_from_slice(&aggregate_nonce.to_compressed_bytes());
        mutated_signature[33..].copy_from_slice(&mutated_aggregate.to_bytes());
        let mut mutated_transaction = fixture.transaction.clone();
        mutated_transaction.kernels[0].excess_signature = mutated_signature;
        assert!(
            validate_kernel_signatures(&mutated_transaction, fixture.chain.as_bytes()).is_err(),
            "mutated partial {flip_index} must not survive consensus validation"
        );
    }
    Ok(())
}

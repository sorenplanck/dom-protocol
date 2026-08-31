//! G-F1 E2E — full two-party 2-of-2 rounds driven THROUGH the vault to
//! signatures accepted by the real DOM consensus verifier.
//!
//! Both parties derive every nonce through their own `DurableNonceVault`
//! (never locally): commitment, reveal and partial all come out of the
//! contract via `VaultBackedSignerV1`. The parties exchange canonical DSC1
//! envelopes, each `ValidatedSigningRoundStateV1` validates the exchange and
//! hands out the stage authorities, and the two vault-produced partials are
//! combined into one DOM signature that the real verifier accepts.
//!
//! This is the missing G-F1 piece — both settlement directions with REAL
//! cryptography, nonces flowing through the durable vault, reaching the real
//! verifier (no mock, no `DurableVaultCore` shortcut):
//!
//! - `funding→refund` (plain): the two vault partials finalize via
//!   `finalize_plain_signature_v1` (verified inside), then the test re-checks
//!   with `validate_kernel_signatures` (real consensus).
//! - `funding→claim` (adaptor): the vault partials aggregate into the adaptor
//!   pre-signature; adding the committed secret `t` yields the DOM signature
//!   the verifier accepts, and observing that signature extracts `t` back
//!   (`t*G == T`) — the DOM side of the §1.3 secret flow.
//! - unilateral spend is cryptographically impossible: a single partial never
//!   finalizes a 2-of-2 signature.
//!
//! Composes with the merged single-party contract drive (`g_f1_contract.rs`),
//! the SCAD0 differential (`dom-leg`), and the durable-store crash suites. No
//! primitive, challenge or verifier is reimplemented (I15); the aggregate and
//! binding recipes use public API only, mirrored from `dom-leg::round`.

use dom_adaptor::{
    advance_transcript_hash_v1, aggregate_partial_signatures_v1, aggregate_public_nonces_v1,
    binding_factor_v1, canonical_template_v1, finalize_plain_signature_v1,
    initial_transcript_hash_v1, session_message_digest_v1, AdaptorPreSignatureV1, AdaptorSecret,
    BindingContextV1, ContractKindV1, DirectionV1, NonceCommitmentV1, NonceRevealV1,
    PartialSignatureV1, ParticipantIdentityV1, ParticipantPublicNoncesV1, ParticipantRosterV1,
    PurposeV1, SigningPhaseV1, SigningShareV1, TrustedChainIdV1, ValidatedSigningRoundStateV1,
    VaultBackedSignerV1,
};
use dom_consensus::{validate_kernel_signatures, Transaction, TransactionKernel};
use dom_core::Amount;
use dom_crypto::pedersen::Commitment;
use dom_crypto::{schnorr_sign, PublicKey, SecretKey};
use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
use dom_vault::{
    AcceptedSession, AcceptedSessionFreshRequestV1, DurableLookupCustody, DurableNonceVault,
    SessionAuthority,
};

const NETWORK_MAGIC: u32 = 0x0D01_0002;
const KIND_NONCE_COMMITMENT: u8 = 0x0c;
const KIND_NONCE_REVEAL: u8 = 0x0d;
const SIGNATURE_LEN: usize = 65;

fn chain() -> TrustedChainIdV1 {
    let genesis = dom_crypto::Hash256::from_bytes([0x11; 32]);
    TrustedChainIdV1::from_authenticated_genesis(NETWORK_MAGIC, &genesis)
}

fn share(byte: u8) -> SigningShareV1 {
    SigningShareV1::from_be_bytes([byte; 32]).expect("canonical signing share")
}

/// Immutable data shared by both parties of one accepted session.
struct Shared {
    chain: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: ParticipantRosterV1,
    template: Transaction,
    template_hash: [u8; 32],
    message_digest: [u8; 32],
    initial_transcript: [u8; 32],
    aggregate_signing_key: PublicKey,
    /// identity secret bytes and signing share bytes, in roster order.
    identities: Vec<SecretKey>,
    share_bytes: Vec<u8>,
}

fn build_shared(session_id: [u8; 32]) -> Shared {
    let chain = chain();
    // Two identities and two signing shares.
    let id_bytes = [[0x21u8; 32], [0x22u8; 32]];
    let share_seed = [0x31u8, 0x32u8];
    let identities: Vec<SecretKey> = id_bytes
        .iter()
        .map(|b| SecretKey::from_bytes(b).expect("identity secret"))
        .collect();
    let shares: Vec<SigningShareV1> = share_seed.iter().map(|b| share(*b)).collect();

    let mut entries = vec![
        ParticipantIdentityV1::new(
            &chain,
            identities[0].public_key(),
            shares[0].public_key().clone(),
            DirectionV1::Initiator,
        )
        .expect("initiator"),
        ParticipantIdentityV1::new(
            &chain,
            identities[1].public_key(),
            shares[1].public_key().clone(),
            DirectionV1::Responder,
        )
        .expect("responder"),
    ];
    // Pair (identity, share_seed) with each entry, then sort by participant id
    // so roster protocol order is canonical.
    let mut tagged: Vec<(ParticipantIdentityV1, SecretKey, u8)> = vec![
        (entries.remove(0), identities[0].clone(), share_seed[0]),
        (entries.remove(0), identities[1].clone(), share_seed[1]),
    ];
    tagged.sort_by_key(|(entry, _, _)| *entry.participant_id());
    let roster = ParticipantRosterV1::new(tagged.iter().map(|(e, _, _)| e.clone()).collect())
        .expect("roster");
    let identities: Vec<SecretKey> = tagged.iter().map(|(_, id, _)| id.clone()).collect();
    let share_bytes: Vec<u8> = tagged.iter().map(|(_, _, s)| *s).collect();

    // Canonical signing roster (sorted by signing key) → aggregate signing key.
    let mut signing_keys: Vec<PublicKey> = roster
        .entries()
        .iter()
        .map(|e| e.signing_public_key().clone())
        .collect();
    signing_keys.sort_by_key(|k| k.to_compressed_bytes());
    let aggregate_signing_key =
        aggregate_public_nonces_v1(&signing_keys).expect("aggregate signing key");

    let kernel = TransactionKernel {
        features: 0,
        fee: Amount::ZERO,
        lock_height: 0,
        excess: Commitment::from_compressed_bytes(&aggregate_signing_key.to_compressed_bytes())
            .expect("aggregate excess"),
        excess_signature: [0; 65],
    };
    let message_digest = *scriptless_kernel_message_digest_v1(&kernel).as_bytes();
    let template = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![kernel],
        offset: [0x2a; 32],
    };
    let (_, template_hash) = canonical_template_v1(&template).expect("template hash");
    let initial_transcript = initial_transcript_hash_v1(
        &chain,
        &session_id,
        ContractKindV1::WitnessOrTimeout,
        &roster,
    );

    Shared {
        chain,
        session_id,
        roster,
        template,
        template_hash,
        message_digest,
        initial_transcript,
        aggregate_signing_key,
        identities,
        share_bytes,
    }
}

fn accepted_session(
    shared: &Shared,
    purpose: PurposeV1,
    adaptor_point: Option<PublicKey>,
) -> AcceptedSession {
    AcceptedSession::fresh(AcceptedSessionFreshRequestV1 {
        trusted_chain_id: shared.chain,
        session_id: shared.session_id,
        contract_kind: ContractKindV1::WitnessOrTimeout,
        purpose,
        roster: shared.roster.clone(),
        transaction_template: shared.template.clone(),
        kernel_index: 0,
        adaptor_point,
    })
    .expect("accepted session")
}

#[allow(clippy::too_many_arguments)]
fn signed_envelope(
    chain: &[u8; 32],
    session: &[u8; 32],
    sender_id: &[u8; 32],
    sequence: u64,
    previous_transcript: &[u8; 32],
    kind: u8,
    payload: &[u8],
    identity_secret: &SecretKey,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(148 + payload.len() + SIGNATURE_LEN);
    bytes.extend_from_slice(b"DSC1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(kind);
    bytes.push(0);
    bytes.extend_from_slice(chain);
    bytes.extend_from_slice(session);
    bytes.extend_from_slice(sender_id);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(previous_transcript);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    let digest = session_message_digest_v1(&bytes);
    let signature = schnorr_sign(identity_secret, &digest, chain).expect("transport signature");
    bytes.extend_from_slice(&signature.to_bytes());
    bytes
}

/// Builds the two stage envelopes (roster order) and returns them plus the
/// transcript predecessor after the barrier.
fn stage_envelopes(
    shared: &Shared,
    sequence: u64,
    kind: u8,
    phase: SigningPhaseV1,
    payloads: &[Vec<u8>; 2],
    start_predecessor: [u8; 32],
) -> (Vec<Vec<u8>>, [u8; 32]) {
    let mut predecessor = start_predecessor;
    let mut envelopes = Vec::new();
    for (protocol_index, entry) in shared.roster.entries().iter().enumerate() {
        let env = signed_envelope(
            shared.chain.as_bytes(),
            &shared.session_id,
            entry.participant_id(),
            sequence,
            &predecessor,
            kind,
            &payloads[protocol_index],
            &shared.identities[protocol_index],
        );
        let unsigned = &env[..env.len() - SIGNATURE_LEN];
        predecessor = advance_transcript_hash_v1(
            &predecessor,
            &session_message_digest_v1(unsigned),
            entry.direction(),
            phase,
        );
        envelopes.push(env);
    }
    (envelopes, predecessor)
}

struct Rig {
    vault: std::path::PathBuf,
    custody: std::path::PathBuf,
}

/// Raw materials produced by a full vault-driven round, before finalization.
/// The finalize step differs by purpose (plain vs adaptor), so the tests do it.
struct RoundOutcome {
    partials: Vec<PartialSignatureV1>,
    aggregate_nonce: PublicKey,
}

/// Drives a full two-party round through both vaults for `purpose`, returning
/// the two vault-produced partials and the aggregate nonce. Every nonce flows
/// through the durable contract; nothing is generated locally.
fn drive_round(
    dir: &std::path::Path,
    shared: &Shared,
    purpose: PurposeV1,
    adaptor_point: Option<PublicKey>,
) -> RoundOutcome {
    let rigs = [
        Rig {
            vault: dir.join("a-vault.db"),
            custody: dir.join("a-custody.db"),
        },
        Rig {
            vault: dir.join("b-vault.db"),
            custody: dir.join("b-custody.db"),
        },
    ];

    // Per-party round state and vault-backed signer.
    let mut rounds: Vec<ValidatedSigningRoundStateV1> = (0..2)
        .map(|p| {
            ValidatedSigningRoundStateV1::from_session_authority::<SessionAuthority>(
                accepted_session(shared, purpose, adaptor_point.clone()),
                &share(shared.share_bytes[p]),
            )
            .expect("round entry")
        })
        .collect();
    let bases: Vec<_> = rounds
        .iter_mut()
        .map(|r| r.take_derivation_base().expect("derivation base"))
        .collect();

    let mut custody_stores: Vec<store::Store> = rigs
        .iter()
        .map(|rig| store::Store::open(&rig.custody).expect("custody store"))
        .collect();
    // Signers must outlive the round; build them holding their vault + custody.
    // (custody borrows its store; keep the stores alive alongside.)
    let mut commitments: Vec<NonceCommitmentV1> = Vec::new();
    let mut commit_exports = Vec::new();
    let mut reveal_exports = Vec::new();
    let mut reveals: Vec<NonceRevealV1> = Vec::new();
    let mut partials: Vec<PartialSignatureV1> = Vec::new();

    // Build both signers first (each borrows its own custody store).
    let (a_store, b_store) = custody_stores.split_at_mut(1);
    let mut signers = [
        VaultBackedSignerV1::new(
            DurableNonceVault::new(store::Store::open(&rigs[0].vault).expect("vault a")),
            DurableLookupCustody::new(&mut a_store[0]),
            SessionAuthority,
            shared.chain,
            share(shared.share_bytes[0]),
        ),
        VaultBackedSignerV1::new(
            DurableNonceVault::new(store::Store::open(&rigs[1].vault).expect("vault b")),
            DurableLookupCustody::new(&mut b_store[0]),
            SessionAuthority,
            shared.chain,
            share(shared.share_bytes[1]),
        ),
    ];

    // Stage 1: commitment through the vault.
    for (p, base) in bases.into_iter().enumerate() {
        let reserved = signers[p].claim_fresh(base).expect("claim fresh");
        let (exported, commitment) = signers[p]
            .derive_and_export_commitment(reserved)
            .expect("commitment through the contract");
        commit_exports.push(exported);
        commitments.push(commitment);
    }
    let commit_payloads = [
        commitments[0].to_bytes().to_vec(),
        commitments[1].to_bytes().to_vec(),
    ];
    let (commit_envs, after_commit) = stage_envelopes(
        shared,
        0,
        KIND_NONCE_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commit_payloads,
        shared.initial_transcript,
    );
    for round in rounds.iter_mut() {
        round
            .accept_message(&commit_envs[0])
            .expect("accept commit 0");
        round
            .accept_message(&commit_envs[1])
            .expect("accept commit 1");
    }

    // Stage 2: reveal through the vault — a strict pipeline in protocol order.
    // The party at protocol index k must have accepted the k prior reveals
    // before it takes its commitment-round authority (the pin binds the reveal
    // prefix count to the local protocol index). So each party reveals, then
    // its reveal is broadcast to all rounds before the next party proceeds.
    let mut predecessor = after_commit;
    for p in 0..2 {
        let authority = rounds[p].take_commitment_round().expect("commitment round");
        let export = commit_exports.remove(0);
        let (reveal_export, reveal) = signers[p]
            .export_reveal(export, authority)
            .expect("reveal through the contract");
        let entry = &shared.roster.entries()[p];
        let env = signed_envelope(
            shared.chain.as_bytes(),
            &shared.session_id,
            entry.participant_id(),
            1,
            &predecessor,
            KIND_NONCE_REVEAL,
            &reveal.to_bytes(),
            &shared.identities[p],
        );
        predecessor = advance_transcript_hash_v1(
            &predecessor,
            &session_message_digest_v1(&env[..env.len() - SIGNATURE_LEN]),
            entry.direction(),
            SigningPhaseV1::SigNonceReveal,
        );
        for round in rounds.iter_mut() {
            round.accept_message(&env).expect("accept reveal");
        }
        reveal_exports.push(reveal_export);
        reveals.push(reveal);
    }

    // Stage 3: partial signature through the vault. Every round now holds both
    // reveals, so each party can take its reveal-round authority.
    for p in 0..2 {
        let authority = rounds[p].take_reveal_round().expect("reveal round");
        let export = reveal_exports.remove(0);
        let (_terminal, partial) = signers[p]
            .sign_and_export_partial(export, authority)
            .expect("partial through the contract");
        partials.push(partial);
    }

    // Aggregate nonce from the vault-produced reveals (public binding recipe,
    // mirrored from dom-leg::round; no primitive is reimplemented — I15).
    let participants: Vec<ParticipantPublicNoncesV1> = {
        let mut signing_keys: Vec<PublicKey> = shared
            .roster
            .entries()
            .iter()
            .map(|e| e.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(|k| k.to_compressed_bytes());
        (0u16..2)
            .map(|index| {
                let reveal = reveals
                    .iter()
                    .find(|r| r.participant_index() == index)
                    .expect("reveal for signing index");
                ParticipantPublicNoncesV1 {
                    participant_index: index,
                    signing_key: signing_keys[usize::from(index)].clone(),
                    first_nonce: reveal.first().clone(),
                    second_nonce: reveal.second().clone(),
                }
            })
            .collect()
    };
    let binding_factor = binding_factor_v1(
        &BindingContextV1 {
            chain_id: *shared.chain.as_bytes(),
            session_id: shared.session_id,
            purpose,
            template_hash: shared.template_hash,
        },
        &participants,
        adaptor_point.as_ref(),
    )
    .expect("binding factor");
    let mut bound = Vec::new();
    for participant in &participants {
        bound.push(
            binding_factor
                .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)
                .expect("bound nonce"),
        );
    }
    let aggregate_nonce = aggregate_public_nonces_v1(&bound).expect("aggregate nonce");

    RoundOutcome {
        partials,
        aggregate_nonce,
    }
}

/// Finalizes a plain (Funding/Refund) round and returns the DOM signature,
/// verified by the DOM verifier inside `finalize_plain_signature_v1`.
fn finalize_plain(shared: &Shared, outcome: &RoundOutcome) -> dom_crypto::SchnorrSignature {
    finalize_plain_signature_v1(
        &outcome.partials,
        PurposeV1::Refund,
        &shared.template_hash,
        &outcome.aggregate_nonce,
        &shared.aggregate_signing_key,
        shared.chain.as_bytes(),
        &shared.message_digest,
    )
    .expect("finalized refund signature (verified by the DOM verifier)")
}

#[test]
fn two_party_refund_round_through_the_vault_reaches_the_real_consensus_verifier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = build_shared([0x61; 32]);
    let outcome = drive_round(dir.path(), &shared, PurposeV1::Refund, None);
    let signature = finalize_plain(&shared, &outcome);

    // Explicit consensus check: rebuild the kernel with the finalized excess
    // signature and run the real verifier.
    let kernel = TransactionKernel {
        features: 0,
        fee: Amount::ZERO,
        lock_height: 0,
        excess: Commitment::from_compressed_bytes(
            &shared.aggregate_signing_key.to_compressed_bytes(),
        )
        .expect("excess"),
        excess_signature: signature.to_bytes(),
    };
    let tx = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![kernel],
        offset: [0; 32],
    };
    validate_kernel_signatures(&tx, shared.chain.as_bytes())
        .expect("the real DOM consensus verifier accepts the vault-driven signature");
}

#[test]
fn a_single_partial_cannot_finalize_a_signature() {
    // "Unilateral spend is cryptographically impossible": one party's partial
    // alone must never finalize into a valid 2-of-2 signature. The aggregate
    // nonce and signing key are for the full roster, so a lone partial fails
    // to satisfy the verifier — enforced by the pin, reached for real here.
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = build_shared([0x62; 32]);
    let outcome = drive_round(dir.path(), &shared, PurposeV1::Refund, None);

    for lone in [&outcome.partials[..1], &outcome.partials[1..]] {
        let result = finalize_plain_signature_v1(
            lone,
            PurposeV1::Refund,
            &shared.template_hash,
            &outcome.aggregate_nonce,
            &shared.aggregate_signing_key,
            shared.chain.as_bytes(),
            &shared.message_digest,
        );
        assert!(
            result.is_err(),
            "a single partial must not finalize a 2-of-2 signature"
        );
    }
}

#[test]
fn two_party_claim_round_through_the_vault_adapts_reaches_the_verifier_and_extracts_t() {
    // funding→claim: a full ClaimAdaptor round driven through both vaults. The
    // vault-produced partials aggregate into the adaptor pre-signature; adding
    // the secret t yields the DOM signature the consensus verifier accepts, and
    // seeing that signature lets us extract t back (§1.3 secret flow). The
    // pre-signature transcript binding is a transport value; the Schnorr
    // equation itself is transcript-independent, so a fixed tag is consistent.
    const PRE_TRANSCRIPT: [u8; 32] = [0x33; 32];

    let dir = tempfile::tempdir().expect("tempdir");
    let shared = build_shared([0x63; 32]);

    let secret = AdaptorSecret::from_be_bytes([0x2b; 32]).expect("adaptor secret t");
    let adaptor_point = secret.public_point().expect("T = t*G");

    let outcome = drive_round(
        dir.path(),
        &shared,
        PurposeV1::ClaimAdaptor,
        Some(adaptor_point.clone()),
    );

    // R̂ = R + T; scalar_hat = aggregate of the vault-produced partials.
    let aggregate_nonce_hat =
        aggregate_public_nonces_v1(&[outcome.aggregate_nonce.clone(), adaptor_point.clone()])
            .expect("aggregate nonce hat");
    let scalar_hat = aggregate_partial_signatures_v1(
        &outcome.partials,
        PurposeV1::ClaimAdaptor,
        &shared.template_hash,
    )
    .expect("scalar hat");
    let pre = AdaptorPreSignatureV1::new(
        shared.template_hash,
        adaptor_point.clone(),
        aggregate_nonce_hat,
        scalar_hat,
        PRE_TRANSCRIPT,
    );

    // The pre-signature verifies against the DOM challenge.
    assert!(
        pre.verify(
            &shared.template_hash,
            &PRE_TRANSCRIPT,
            &shared.aggregate_signing_key,
            shared.chain.as_bytes(),
            &shared.message_digest,
        )
        .expect("pre-signature verify"),
        "vault-driven adaptor pre-signature must verify"
    );

    // Adapt with t → the final DOM signature (re-verified inside adapt).
    let signature = pre
        .adapt(
            &secret,
            &shared.template_hash,
            &PRE_TRANSCRIPT,
            &shared.aggregate_signing_key,
            shared.chain.as_bytes(),
            &shared.message_digest,
        )
        .expect("adapt to the final DOM signature");

    // Real consensus verifier accepts the adapted claim signature.
    let kernel = TransactionKernel {
        features: 0,
        fee: Amount::ZERO,
        lock_height: 0,
        excess: Commitment::from_compressed_bytes(
            &shared.aggregate_signing_key.to_compressed_bytes(),
        )
        .expect("excess"),
        excess_signature: signature.to_bytes(),
    };
    let tx = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![kernel],
        offset: [0; 32],
    };
    validate_kernel_signatures(&tx, shared.chain.as_bytes())
        .expect("the real DOM consensus verifier accepts the adapted claim signature");

    // Seeing the final signature, extract t and confirm it is the committed
    // secret (t*G == T). This is the DOM side of the §1.3 secret flow.
    let extracted = pre
        .extract(
            &signature,
            &shared.template_hash,
            &PRE_TRANSCRIPT,
            &shared.aggregate_signing_key,
            shared.chain.as_bytes(),
            &shared.message_digest,
        )
        .expect("extract t from the final signature");
    assert_eq!(
        extracted.public_point().expect("t*G"),
        adaptor_point,
        "extracted secret must be the committed t (t*G == T)"
    );
}

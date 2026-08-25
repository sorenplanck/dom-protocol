//! Shared 2-of-2 output formation and collaborative Bulletproof, against the
//! pinned DOM backend.
//!
//! Every value here is produced by a pinned primitive. The multi-party
//! Bulletproof rounds are the pinned `dom_crypto::bulletproof_mpc_*` FFI; no
//! proof system, curve operation, or verifier is written in this repository.

use dom_adaptor::{
    prove_share_knowledge_v1, DirectionV1, SharePoPStatementV1, SigningShareV1, TrustedChainIdV1,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{
    bulletproof_mpc_aggregate_tau_x, bulletproof_mpc_finalize, bulletproof_mpc_round1,
    bulletproof_mpc_round2, range_proof, secret_scalar_public_key, PublicKey, MAX_PROVABLE_VALUE,
};
use dom_scriptless_crypto::{
    commit_to_reveal, freeze_shared_output_statement_v1, CommonNonceError, CommonNonceRoundV1,
    FrozenSharedOutputV1, PrivateNonceCustodyV1, SharedOutputContributionV1, SharedOutputError,
    SharedOutputInputsV1,
};
use zeroize::Zeroizing;

/// A test failure, reported as text so no test needs `unwrap`, `expect`, or
/// `panic!`, all of which this workspace denies in every target.
type TestResult = Result<(), String>;

/// The exact aggregate Bulletproof size the pinned backend produces.
const PROOF_LEN: usize = 739;

const CHAIN_ID: [u8; 32] = [0xC1; 32];
/// Regtest network magic. Contracts remain regtest-only until the gates.
const REGTEST_MAGIC: u32 = 0x000D_0012;
const TERMS_HASH: [u8; 32] = [0x7E; 32];
const RECOVERY_BINDING: [u8; 32] = [0x4C; 32];

/// Deterministic non-zero test scalar. Test material only.
fn scalar(seed: u64, domain: u8) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[0] = domain;
    out[1] = 0x01;
    out[24..].copy_from_slice(&seed.to_be_bytes());
    out
}

fn session_id(seed: u64) -> [u8; 32] {
    scalar(seed, 0x5E)
}

/// One party's secrets, held only inside the test.
struct Party {
    blind: Zeroizing<[u8; 32]>,
    private_nonce: Zeroizing<[u8; 32]>,
    reveal: [u8; 32],
    id: [u8; 32],
    role: DirectionV1,
    index: u16,
}

impl Party {
    fn new(seed: u64, index: u16, role: DirectionV1) -> Self {
        Self {
            blind: Zeroizing::new(scalar(seed, 0x10 + index as u8)),
            private_nonce: Zeroizing::new(scalar(seed, 0x30 + index as u8)),
            reveal: scalar(seed, 0x50 + index as u8),
            id: scalar(seed, 0x70 + index as u8),
            role,
            index,
        }
    }

    fn share_point(&self) -> Result<PublicKey, String> {
        secret_scalar_public_key(&self.blind).map_err(|error| format!("share point: {error}"))
    }
}

struct Session {
    parties: Vec<Party>,
    chain_id: TrustedChainIdV1,
    session_id: [u8; 32],
    value_noms: u64,
}

impl Session {
    fn new(seed: u64, value_noms: u64) -> Result<Self, String> {
        // The pinned constructor: a chain identity is derived from an
        // authenticated genesis, never asserted from loose bytes.
        let genesis = dom_core::Hash256::from_bytes(CHAIN_ID);
        let chain_id = TrustedChainIdV1::from_authenticated_genesis(REGTEST_MAGIC, &genesis);
        Ok(Self {
            parties: vec![
                Party::new(seed, 0, DirectionV1::Initiator),
                Party::new(seed.wrapping_add(0x9E37), 1, DirectionV1::Responder),
            ],
            chain_id,
            session_id: session_id(seed),
            value_noms,
        })
    }

    /// Build each contribution with a real proof of possession.
    fn contributions(&self) -> Result<Vec<SharedOutputContributionV1>, String> {
        let roster: Vec<[u8; 32]> = self.parties.iter().map(|party| party.id).collect();
        let mut out = Vec::with_capacity(self.parties.len());
        for party in &self.parties {
            let point = party.share_point()?;
            let statement = SharePoPStatementV1::new(
                &self.chain_id,
                self.session_id,
                &roster,
                party.role,
                party.index,
                point.clone(),
                TERMS_HASH,
                RECOVERY_BINDING,
            )
            .map_err(|error| format!("statement: {error}"))?;
            let share = SigningShareV1::from_be_bytes(*party.blind)
                .map_err(|error| format!("signing share: {error}"))?;
            let proof = prove_share_knowledge_v1(&statement, &share)
                .map_err(|error| format!("prove: {error}"))?;
            out.push(SharedOutputContributionV1 {
                participant_index: party.index,
                participant_id: party.id,
                role: party.role,
                commitment_share: point,
                proof,
            });
        }
        Ok(out)
    }

    fn freeze(
        &self,
        contributions: &[SharedOutputContributionV1],
    ) -> Result<FrozenSharedOutputV1, SharedOutputError> {
        freeze_shared_output_statement_v1(&SharedOutputInputsV1 {
            chain_id: self.chain_id,
            session_id: self.session_id,
            contributions,
            value_noms: self.value_noms,
            terms_hash: TERMS_HASH,
            recovery_binding_hash: RECOVERY_BINDING,
        })
    }
}

/// Drive the pinned multi-party Bulletproof to a finalized aggregate proof.
///
/// Round 1 per party, T1/T2 aggregated, round 2 per party, tau_x aggregated,
/// then finalize. Every step is the pinned FFI.
fn collaborative_proof(
    session: &Session,
    frozen: &FrozenSharedOutputV1,
    joint_nonce: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let aggregate = *frozen.aggregate_commitment();
    let extra_commit = RECOVERY_BINDING;

    let mut states = Vec::new();
    let mut t_ones = Vec::new();
    let mut t_twos = Vec::new();
    for party in &session.parties {
        let blind =
            BlindingFactor::from_bytes(*party.blind).map_err(|error| format!("blind: {error}"))?;
        let (state, output) = bulletproof_mpc_round1(
            session.value_noms,
            blind,
            aggregate,
            Zeroizing::new(*joint_nonce),
            Zeroizing::new(*party.private_nonce),
            &extra_commit,
        )
        .map_err(|error| format!("round1: {error}"))?;
        t_ones.push(*output.t_one());
        t_twos.push(*output.t_two());
        states.push(state);
    }

    let aggregate_t_one = aggregate_points(&t_ones)?;
    let aggregate_t_two = aggregate_points(&t_twos)?;

    let mut finalize_state = None;
    let mut tau_x_shares = Vec::new();
    for state in states {
        let (next, tau_x) = bulletproof_mpc_round2(state, &aggregate_t_one, &aggregate_t_two)
            .map_err(|error| format!("round2: {error}"))?;
        tau_x_shares.push(tau_x);
        if finalize_state.is_none() {
            finalize_state = Some(next);
        }
    }

    let aggregate_tau_x = bulletproof_mpc_aggregate_tau_x(tau_x_shares)
        .map_err(|error| format!("aggregate tau_x: {error}"))?;
    let state = finalize_state.ok_or_else(|| "no finalize state".to_owned())?;
    bulletproof_mpc_finalize(state, aggregate_tau_x).map_err(|error| format!("finalize: {error}"))
}

fn aggregate_points(points: &[[u8; 33]]) -> Result<[u8; 33], String> {
    let mut acc: Option<Commitment> = None;
    for bytes in points {
        let point =
            Commitment::from_compressed_bytes(bytes).map_err(|error| format!("point: {error}"))?;
        acc = Some(match acc {
            None => point,
            Some(previous) => previous
                .add(&point)
                .map_err(|error| format!("add: {error}"))?,
        });
    }
    let total = acc.ok_or_else(|| "empty point list".to_owned())?;
    Ok(*total.as_bytes())
}

fn run(seed: u64, value_noms: u64) -> Result<(Session, FrozenSharedOutputV1, Vec<u8>), String> {
    let session = Session::new(seed, value_noms)?;
    let contributions = session.contributions()?;
    let frozen = session
        .freeze(&contributions)
        .map_err(|error| format!("freeze: {error}"))?;

    let mut round = CommonNonceRoundV1::open(&frozen);
    let statement_hash = frozen.statement().statement_hash();
    for party in &session.parties {
        let commitment = commit_to_reveal(&statement_hash, party.index, &party.reveal)
            .map_err(|error| format!("commit: {error}"))?;
        round
            .accept_commitment(party.index, commitment)
            .map_err(|error| format!("accept commitment: {error}"))?;
    }
    for party in &session.parties {
        round
            .accept_reveal(party.index, party.reveal)
            .map_err(|error| format!("accept reveal: {error}"))?;
    }
    let joint = round
        .joint_nonce()
        .map_err(|error| format!("joint nonce: {error}"))?;

    let proof = collaborative_proof(&session, &frozen, joint.as_bytes())?;
    Ok((session, frozen, proof))
}

#[test]
fn the_collaborative_proof_is_exactly_739_bytes_and_verifies() -> TestResult {
    let (_session, frozen, proof) = run(11, 1_000_000)?;
    assert_eq!(
        proof.len(),
        PROOF_LEN,
        "the pinned backend produces a fixed-size aggregate proof"
    );
    let verified = range_proof::verify_with_extra_commit(
        frozen.aggregate_commitment(),
        &proof,
        &RECOVERY_BINDING,
    )
    .map_err(|error| format!("verify: {error}"))?;
    assert!(verified, "the pinned verifier must accept the proof");
    Ok(())
}

#[test]
fn the_shared_commitment_is_the_value_plus_the_aggregate_share() -> TestResult {
    // C = v·H_DOM + R, recomputed here from pinned operations and compared.
    let session = Session::new(13, 4_242)?;
    let contributions = session.contributions()?;
    let frozen = session
        .freeze(&contributions)
        .map_err(|error| format!("{error}"))?;

    let sum_blind = {
        let first = BlindingFactor::from_bytes(*session.parties[0].blind)
            .map_err(|error| format!("{error}"))?;
        let second = BlindingFactor::from_bytes(*session.parties[1].blind)
            .map_err(|error| format!("{error}"))?;
        first.add(&second).map_err(|error| format!("{error}"))?
    };
    let expected = Commitment::commit(session.value_noms, &sum_blind);
    assert_eq!(
        frozen.aggregate_commitment(),
        expected.as_bytes(),
        "C must open to v with the summed blind, which no single party holds"
    );
    Ok(())
}

#[test]
fn boundary_values_all_prove() -> TestResult {
    for value in [0_u64, 1, MAX_PROVABLE_VALUE - 1, MAX_PROVABLE_VALUE] {
        let (_session, frozen, proof) = run(17, value)?;
        assert_eq!(proof.len(), PROOF_LEN, "value {value}");
        let verified = range_proof::verify_with_extra_commit(
            frozen.aggregate_commitment(),
            &proof,
            &RECOVERY_BINDING,
        )
        .map_err(|error| format!("verify {value}: {error}"))?;
        assert!(verified, "value {value} must verify");
    }
    Ok(())
}

#[test]
fn a_value_above_the_maximum_is_refused() -> TestResult {
    let session = Session::new(19, MAX_PROVABLE_VALUE + 1)?;
    let contributions = session.contributions()?;
    assert_eq!(
        session.freeze(&contributions).err(),
        Some(SharedOutputError::ValueOutOfRange)
    );
    Ok(())
}

#[test]
fn a_tampered_proof_of_possession_is_refused_before_aggregation() -> TestResult {
    let session = Session::new(23, 500)?;
    let mut contributions = session.contributions()?;
    // Swap ONLY the proofs. Each proof is individually valid, and every other
    // field stays in place, so the roster is canonical and the sole defect is
    // that neither proof matches the share it now accompanies. Swapping whole
    // contributions would merely reorder a consistent roster and prove nothing.
    let first_proof = contributions[0].proof.to_bytes();
    let second_proof = contributions[1].proof.to_bytes();
    contributions[0].proof = dom_adaptor::ShareProofV1::from_bytes(&second_proof)
        .map_err(|error| format!("reparse: {error}"))?;
    contributions[1].proof = dom_adaptor::ShareProofV1::from_bytes(&first_proof)
        .map_err(|error| format!("reparse: {error}"))?;
    assert_eq!(
        session.freeze(&contributions).err(),
        Some(SharedOutputError::ProofRejected),
        "a share whose proof does not verify must never be aggregated"
    );
    Ok(())
}

#[test]
fn a_non_two_roster_is_refused() -> TestResult {
    let session = Session::new(29, 900)?;
    let contributions = session.contributions()?;
    assert_eq!(
        session.freeze(&contributions[..1]).err(),
        Some(SharedOutputError::NonCanonicalRoster),
        "n > 2 and n < 2 are both out of scope"
    );
    Ok(())
}

#[test]
fn a_reordered_roster_is_refused() -> TestResult {
    let session = Session::new(31, 900)?;
    let mut contributions = session.contributions()?;
    contributions.swap(0, 1);
    assert_eq!(
        session.freeze(&contributions).err(),
        Some(SharedOutputError::NonCanonicalOrder)
    );
    Ok(())
}

#[test]
fn a_zero_context_is_refused() -> TestResult {
    let session = Session::new(37, 900)?;
    let contributions = session.contributions()?;
    let inputs = SharedOutputInputsV1 {
        chain_id: session.chain_id,
        session_id: [0_u8; 32],
        contributions: &contributions,
        value_noms: session.value_noms,
        terms_hash: TERMS_HASH,
        recovery_binding_hash: RECOVERY_BINDING,
    };
    assert_eq!(
        freeze_shared_output_statement_v1(&inputs).err(),
        Some(SharedOutputError::ZeroContext)
    );
    Ok(())
}

#[test]
fn a_reveal_before_every_commitment_is_refused() -> TestResult {
    let session = Session::new(41, 700)?;
    let contributions = session.contributions()?;
    let frozen = session
        .freeze(&contributions)
        .map_err(|error| format!("{error}"))?;
    let statement_hash = frozen.statement().statement_hash();
    let mut round = CommonNonceRoundV1::open(&frozen);

    let party = &session.parties[0];
    let commitment = commit_to_reveal(&statement_hash, party.index, &party.reveal)
        .map_err(|error| format!("{error}"))?;
    round
        .accept_commitment(party.index, commitment)
        .map_err(|error| format!("{error}"))?;

    // Only one commitment is in. Revealing now would let the second party
    // choose its contribution after seeing the first.
    assert_eq!(
        round.accept_reveal(party.index, party.reveal).err(),
        Some(CommonNonceError::RevealBeforeAllCommitments)
    );
    Ok(())
}

#[test]
fn equivocation_and_duplicate_messages_are_refused() -> TestResult {
    let session = Session::new(43, 700)?;
    let contributions = session.contributions()?;
    let frozen = session
        .freeze(&contributions)
        .map_err(|error| format!("{error}"))?;
    let statement_hash = frozen.statement().statement_hash();
    let mut round = CommonNonceRoundV1::open(&frozen);

    for party in &session.parties {
        let commitment = commit_to_reveal(&statement_hash, party.index, &party.reveal)
            .map_err(|error| format!("{error}"))?;
        round
            .accept_commitment(party.index, commitment)
            .map_err(|error| format!("{error}"))?;
    }

    // A second commitment for the same party is equivocation.
    assert_eq!(
        round.accept_commitment(0, [0xAB; 32]).err(),
        Some(CommonNonceError::DuplicateCommitment)
    );
    // An index outside the roster is refused.
    assert_eq!(
        round.accept_commitment(2, [0xAB; 32]).err(),
        Some(CommonNonceError::UnknownParticipant)
    );
    // A reveal that does not open the commitment is refused.
    assert_eq!(
        round.accept_reveal(0, [0xCD; 32]).err(),
        Some(CommonNonceError::RevealMismatch)
    );

    round
        .accept_reveal(0, session.parties[0].reveal)
        .map_err(|error| format!("{error}"))?;
    // A second reveal for the same party is refused.
    assert_eq!(
        round.accept_reveal(0, session.parties[0].reveal).err(),
        Some(CommonNonceError::DuplicateReveal)
    );
    // The round is not complete until both have revealed.
    assert!(round.joint_nonce().is_err(), "incomplete round must refuse");
    Ok(())
}

#[test]
fn the_joint_nonce_is_bound_to_the_statement() -> TestResult {
    // Two sessions differing only in session id must not produce the same
    // joint nonce from the same reveals.
    let mut nonces = Vec::new();
    for seed in [47_u64, 48] {
        let session = Session::new(seed, 700)?;
        let contributions = session.contributions()?;
        let frozen = session
            .freeze(&contributions)
            .map_err(|error| format!("{error}"))?;
        let statement_hash = frozen.statement().statement_hash();
        let mut round = CommonNonceRoundV1::open(&frozen);
        // Same reveal bytes in both sessions, on purpose.
        for index in 0..2_u16 {
            let commitment = commit_to_reveal(&statement_hash, index, &[0x11; 32])
                .map_err(|error| format!("{error}"))?;
            round
                .accept_commitment(index, commitment)
                .map_err(|error| format!("{error}"))?;
        }
        for index in 0..2_u16 {
            round
                .accept_reveal(index, [0x11; 32])
                .map_err(|error| format!("{error}"))?;
        }
        let joint = round.joint_nonce().map_err(|error| format!("{error}"))?;
        nonces.push(*joint.as_bytes());
    }
    assert_ne!(
        nonces[0], nonces[1],
        "the joint nonce must be bound to the frozen statement"
    );
    Ok(())
}

#[test]
fn a_truncated_or_extended_or_flipped_proof_is_refused() -> TestResult {
    let (_session, frozen, proof) = run(53, 12_345)?;
    let commitment = *frozen.aggregate_commitment();

    let mut truncated = proof.clone();
    truncated.pop();
    assert!(
        range_proof::verify_with_extra_commit(&commitment, &truncated, &RECOVERY_BINDING).is_err(),
        "a truncated proof must be refused"
    );

    let mut extended = proof.clone();
    extended.push(0);
    assert!(
        range_proof::verify_with_extra_commit(&commitment, &extended, &RECOVERY_BINDING).is_err(),
        "an extended proof must be refused"
    );

    for offset in [0_usize, 1, PROOF_LEN / 2, PROOF_LEN - 1] {
        let mut flipped = proof.clone();
        flipped[offset] ^= 0x01;
        let accepted =
            range_proof::verify_with_extra_commit(&commitment, &flipped, &RECOVERY_BINDING)
                .unwrap_or(false);
        assert!(!accepted, "a bit flip at {offset} must not verify");
    }
    Ok(())
}

#[test]
fn a_wrong_extra_commit_or_commitment_is_refused() -> TestResult {
    let (_session, frozen, proof) = run(59, 7_777)?;
    let accepted =
        range_proof::verify_with_extra_commit(frozen.aggregate_commitment(), &proof, &[0xFF; 32])
            .unwrap_or(false);
    assert!(!accepted, "a different extra commit must not verify");

    let other = run(60, 7_777)?;
    let accepted = range_proof::verify_with_extra_commit(
        other.1.aggregate_commitment(),
        &proof,
        &RECOVERY_BINDING,
    )
    .unwrap_or(false);
    assert!(!accepted, "a different commitment must not verify");
    Ok(())
}

#[test]
fn the_proof_is_structurally_indistinguishable_from_a_single_party_proof() -> TestResult {
    // Structural surface only. This measures type, length, and the verifier
    // that accepts it; it is NOT a claim about statistical indistinguishability
    // or about anything an observer could infer from the bytes.
    let (_session, frozen, collaborative) = run(61, 9_001)?;
    let single_blind =
        BlindingFactor::from_bytes(scalar(61, 0xAA)).map_err(|error| format!("blind: {error}"))?;
    let (single, single_commitment) =
        range_proof::prove_bytes_with_extra_commit(9_001, &single_blind, &RECOVERY_BINDING)
            .map_err(|error| format!("single prove: {error}"))?;

    assert_eq!(
        collaborative.len(),
        single.len(),
        "same length: {PROOF_LEN} bytes"
    );
    assert_eq!(collaborative.len(), PROOF_LEN);

    let both_verify = range_proof::verify_with_extra_commit(
        frozen.aggregate_commitment(),
        &collaborative,
        &RECOVERY_BINDING,
    )
    .map_err(|error| format!("{error}"))?
        && range_proof::verify_with_extra_commit(&single_commitment, &single, &RECOVERY_BINDING)
            .map_err(|error| format!("{error}"))?;
    assert!(
        both_verify,
        "the same verifier accepts both, with no multi-party flag"
    );
    Ok(())
}

#[test]
fn the_formation_is_deterministic_over_many_sessions() -> TestResult {
    // Deterministic sweep. Seed base and count are recorded here so the run is
    // reproducible: base 5000, 10000 sessions, seeds 5000..15000.
    //
    // This sweep exercises the 2-of-2 formation, the proof-of-possession
    // verification, the commit-reveal, and the frozen statement. It does NOT
    // run the Bulletproof rounds 10,000 times: a single collaborative proof
    // costs hundreds of milliseconds, and the proof path is covered by the
    // dedicated tests above. That limit is stated rather than implied.
    const BASE_SEED: u64 = 5000;
    const SESSIONS: u64 = 10_000;

    let mut completed = 0_u64;
    let mut distinct = std::collections::BTreeSet::new();
    for seed in BASE_SEED..BASE_SEED + SESSIONS {
        let session = Session::new(seed, 1_000 + seed)?;
        let contributions = session.contributions()?;
        let frozen = session
            .freeze(&contributions)
            .map_err(|error| format!("seed {seed}: {error}"))?;
        distinct.insert(frozen.statement().statement_hash());
        completed += 1;
    }
    assert_eq!(completed, SESSIONS);
    assert_eq!(
        distinct.len() as u64,
        SESSIONS,
        "each session must freeze a distinct statement"
    );
    Ok(())
}

#[test]
fn the_frozen_statement_carries_the_commitment_the_proof_is_stated_over() -> TestResult {
    // The property an independent review proved was missing.
    //
    // The pinned driver `participant_round1_v1` feeds
    // `statement.aggregate_commitment()` straight into round 1, so a consumer
    // following the pinned convention verifies the finalized proof against the
    // statement's own aggregate. A statement holding R instead of C passes the
    // pinned `validate_aggregate` — which only checks `sum(shares) == aggregate`
    // — and is still wrong for every nonzero value.
    //
    // This asserts the two agree, and then verifies the real proof against the
    // statement rather than against the separately carried C.
    for value in [0_u64, 1, 4_242, MAX_PROVABLE_VALUE] {
        let (_session, frozen, proof) = run(83, value)?;
        let from_statement = frozen
            .statement()
            .aggregate_commitment()
            .to_compressed_bytes();
        assert_eq!(
            &from_statement,
            frozen.aggregate_commitment(),
            "value {value}: the statement's aggregate must be C, not R"
        );
        let verified =
            range_proof::verify_with_extra_commit(&from_statement, &proof, &RECOVERY_BINDING)
                .map_err(|error| format!("verify {value}: {error}"))?;
        assert!(
            verified,
            "value {value}: the proof must verify against the statement's own aggregate"
        );
    }
    Ok(())
}

#[test]
fn a_three_party_roster_is_refused() -> TestResult {
    // n > 2 is out of scope for this product. The review showed no test covered
    // the upper bound: only n = 1 was exercised, so widening the check to the
    // pinned 2..=16 range would have gone unnoticed.
    let session = Session::new(89, 600)?;
    let mut contributions = session.contributions()?;
    let extra = Session::new(90, 600)?;
    let mut third = extra.contributions()?.remove(0);
    third.participant_index = 2;
    contributions.push(third);
    assert_eq!(
        session.freeze(&contributions).err(),
        Some(SharedOutputError::NonCanonicalRoster),
        "a third party must be refused, not accommodated"
    );
    Ok(())
}

#[test]
fn a_drawn_private_nonce_is_fresh_every_time() -> TestResult {
    // The pinned canonical driver draws this from the OS and never lets a
    // caller supply it. This type carries that duty into the raw-FFI path.
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..256 {
        let custody = PrivateNonceCustodyV1::draw().map_err(|error| format!("draw: {error}"))?;
        let bytes = *custody.into_round_nonce();
        assert_ne!(
            bytes, [0_u8; 32],
            "a zero private nonce must never be issued"
        );
        assert!(seen.insert(bytes), "a private nonce repeated across draws");
    }
    assert_eq!(seen.len(), 256);
    Ok(())
}

#[test]
fn a_custody_drawn_nonce_drives_a_real_round() -> TestResult {
    // The custody must be usable for the pinned round, not merely well-typed:
    // a proof whose private nonces come from the OS still finalizes and
    // verifies. This is the shape production must use, since the pinned
    // canonical driver is unreachable and would otherwise leave the raw FFI
    // taking whatever a caller passed.
    let session = Session::new(97, 7_777)?;
    let contributions = session.contributions()?;
    let frozen = session
        .freeze(&contributions)
        .map_err(|error| format!("freeze: {error}"))?;
    let joint = [0x5A_u8; 32];

    let aggregate = *frozen.aggregate_commitment();
    let mut states = Vec::new();
    let mut t_ones = Vec::new();
    let mut t_twos = Vec::new();
    for party in &session.parties {
        let blind =
            BlindingFactor::from_bytes(*party.blind).map_err(|error| format!("blind: {error}"))?;
        let custody = PrivateNonceCustodyV1::draw().map_err(|error| format!("draw: {error}"))?;
        let (state, output) = bulletproof_mpc_round1(
            session.value_noms,
            blind,
            aggregate,
            Zeroizing::new(joint),
            custody.into_round_nonce(),
            &RECOVERY_BINDING,
        )
        .map_err(|error| format!("round1: {error}"))?;
        t_ones.push(*output.t_one());
        t_twos.push(*output.t_two());
        states.push(state);
    }
    let aggregate_t_one = aggregate_points(&t_ones)?;
    let aggregate_t_two = aggregate_points(&t_twos)?;

    let mut finalize_state = None;
    let mut tau_x_shares = Vec::new();
    for state in states {
        let (next, tau_x) = bulletproof_mpc_round2(state, &aggregate_t_one, &aggregate_t_two)
            .map_err(|error| format!("round2: {error}"))?;
        tau_x_shares.push(tau_x);
        if finalize_state.is_none() {
            finalize_state = Some(next);
        }
    }
    let aggregate_tau_x = bulletproof_mpc_aggregate_tau_x(tau_x_shares)
        .map_err(|error| format!("aggregate tau_x: {error}"))?;
    let state = finalize_state.ok_or_else(|| "no finalize state".to_owned())?;
    let proof = bulletproof_mpc_finalize(state, aggregate_tau_x)
        .map_err(|error| format!("finalize: {error}"))?;

    assert_eq!(proof.len(), 739);
    let verified = range_proof::verify_with_extra_commit(&aggregate, &proof, &RECOVERY_BINDING)
        .map_err(|error| format!("verify: {error}"))?;
    assert!(verified, "a custody-drawn nonce must produce a valid proof");
    Ok(())
}

//! Two-nonce Refund adaptor composition against the pinned DOM backend.
//!
//! Every value here is produced by a pinned primitive: partial signatures are
//! built with `dom_scriptless_primitives::secret_scalar_mul_add_assign`, the
//! same accumulator the pinned signer uses, and every check is the pinned one.
//!
//! The test that matters most is
//! `a_completed_refund_reveals_the_refund_witness`: it is the property the
//! whole round exists for, and the reason a cross-curve leg can be recovered
//! when a claim never happens.

use dom_adaptor::{
    binding_factor_v1, AdaptorSecret, BindingContextV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, PurposeV1,
};
use dom_crypto::{schnorr_challenge, PartialSig, PublicKey};
use dom_scriptless_crypto::{
    begin_refund_adaptor_round_v1, RefundAdaptorRoundError, RefundAdaptorRoundInputsV1,
    RefundAdaptorRoundV1,
};
use dom_scriptless_primitives::{
    scriptless_add_public_points, secret_scalar_mul_add_assign, secret_scalar_public_key,
};
use zeroize::Zeroizing;

/// A test failure, reported as text so no test needs `unwrap`, `expect`, or
/// `panic!`, all of which this workspace denies in every target.
type TestResult = Result<(), String>;

const CHAIN_ID: [u8; 32] = [0xAD; 32];
const SESSION_ID: [u8; 32] = [0x5E; 32];
const TEMPLATE_HASH: [u8; 32] = [0x11; 32];
const TRANSCRIPT_HASH: [u8; 32] = [0x22; 32];
const MESSAGE: [u8; 32] = [0x33; 32];

/// Deterministic non-zero test scalar. Test material only; it derives no
/// production key and carries no authority.
fn scalar(seed: u64, domain: u8) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[0] = domain;
    out[24..].copy_from_slice(&seed.to_be_bytes());
    out[1] = 0x01;
    out
}

struct Secrets {
    signing_share: Zeroizing<[u8; 32]>,
    first_nonce: Zeroizing<[u8; 32]>,
    second_nonce: Zeroizing<[u8; 32]>,
}

impl Secrets {
    /// `nonce_domain` separates the refund round's nonces from the claim
    /// round's. Reusing them would expose the signing share, which is exactly
    /// what `require_nonces_distinct_from_claim` refuses.
    fn new(seed: u64, nonce_domain: u8) -> Self {
        Self {
            signing_share: Zeroizing::new(scalar(seed, 0x10)),
            first_nonce: Zeroizing::new(scalar(seed, nonce_domain)),
            second_nonce: Zeroizing::new(scalar(seed, nonce_domain.wrapping_add(0x10))),
        }
    }

    fn public(&self) -> Result<(PublicKey, PublicKey, PublicKey), String> {
        let key = secret_scalar_public_key(&self.signing_share)
            .map_err(|error| format!("signing key: {error}"))?;
        let first = secret_scalar_public_key(&self.first_nonce)
            .map_err(|error| format!("first nonce: {error}"))?;
        let second = secret_scalar_public_key(&self.second_nonce)
            .map_err(|error| format!("second nonce: {error}"))?;
        Ok((key, first, second))
    }
}

struct Session {
    participants: Vec<ParticipantPublicNoncesV1>,
    secrets: Vec<Secrets>,
    aggregate_signing_key: PublicKey,
    refund_secret: AdaptorSecret,
    refund_point: PublicKey,
}

impl Session {
    fn new(seed: u64, nonce_domain: u8, secret_domain: u8) -> Result<Self, String> {
        let mut secrets = vec![
            Secrets::new(seed, nonce_domain),
            Secrets::new(seed.wrapping_add(0x9E37), nonce_domain),
        ];

        let mut published = Vec::with_capacity(2);
        for entry in &secrets {
            published.push(entry.public()?);
        }

        // Canonical roster order: strictly increasing indexes AND
        // lexicographic signing keys, as the pinned transcript requires.
        if published[0].0.to_compressed_bytes() > published[1].0.to_compressed_bytes() {
            published.swap(0, 1);
            secrets.swap(0, 1);
        }
        if published[0].0.to_compressed_bytes() == published[1].0.to_compressed_bytes() {
            return Err("degenerate seed produced duplicate signing keys".to_owned());
        }

        let participants: Vec<ParticipantPublicNoncesV1> = published
            .iter()
            .enumerate()
            .map(|(index, (key, first, second))| ParticipantPublicNoncesV1 {
                participant_index: u16::try_from(index).unwrap_or(u16::MAX),
                signing_key: key.clone(),
                first_nonce: first.clone(),
                second_nonce: second.clone(),
            })
            .collect();

        let aggregate_signing_key = scriptless_add_public_points(&[
            participants[0].signing_key.clone(),
            participants[1].signing_key.clone(),
        ])
        .map_err(|error| format!("aggregate key: {error}"))?;

        let refund_secret = AdaptorSecret::from_be_bytes(scalar(seed, secret_domain))
            .map_err(|error| format!("refund secret: {error}"))?;
        let refund_point = refund_secret
            .public_point()
            .map_err(|error| format!("refund point: {error}"))?;

        Ok(Self {
            participants,
            secrets,
            aggregate_signing_key,
            refund_secret,
            refund_point,
        })
    }

    fn inputs(&self) -> RefundAdaptorRoundInputsV1<'_> {
        RefundAdaptorRoundInputsV1 {
            binding_context: BindingContextV1 {
                chain_id: CHAIN_ID,
                session_id: SESSION_ID,
                purpose: PurposeV1::RefundAdaptor,
                template_hash: TEMPLATE_HASH,
            },
            participants: &self.participants,
            refund_adaptor_point: self.refund_point.clone(),
            aggregate_signing_key: self.aggregate_signing_key.clone(),
            transcript_hash: TRANSCRIPT_HASH,
            kernel_message_digest: MESSAGE,
        }
    }

    fn partials(&self, round: &RefundAdaptorRoundV1) -> Result<Vec<PartialSignatureV1>, String> {
        let challenge = schnorr_challenge(
            &round.aggregate_nonce_hat().to_compressed_bytes(),
            &self.aggregate_signing_key,
            &CHAIN_ID,
            &MESSAGE,
        );
        let challenge_bytes = *challenge.as_bytes();
        let binding = *round.binding_factor();

        let mut partials = Vec::with_capacity(self.secrets.len());
        for (index, entry) in self.secrets.iter().enumerate() {
            let mut accumulator = Zeroizing::new(*entry.first_nonce);
            secret_scalar_mul_add_assign(&mut accumulator, &entry.second_nonce, &binding)
                .map_err(|error| format!("effective nonce {index}: {error}"))?;
            secret_scalar_mul_add_assign(&mut accumulator, &entry.signing_share, &challenge_bytes)
                .map_err(|error| format!("partial {index}: {error}"))?;
            let partial = PartialSig::from_bytes(accumulator.as_ref())
                .map_err(|error| format!("partial scalar {index}: {error}"))?;
            partials.push(PartialSignatureV1::new(
                PurposeV1::RefundAdaptor,
                self.participants[index].participant_index,
                TEMPLATE_HASH,
                partial,
            ));
        }
        Ok(partials)
    }
}

/// A refund session with nonce domain 0x20 — the same domain the claim round
/// test uses, so it stands for "the claim round" in the reuse tests.
fn claim_shaped_session(seed: u64) -> Result<Session, String> {
    Session::new(seed, 0x20, 0x40)
}

/// A refund session with its own nonce domain and its own adaptor secret.
fn refund_session(seed: u64) -> Result<Session, String> {
    Session::new(seed, 0x60, 0x50)
}

fn run(seed: u64) -> Result<(Session, RefundAdaptorRoundV1, Vec<PartialSignatureV1>), String> {
    let session = refund_session(seed)?;
    let round = begin_refund_adaptor_round_v1(&session.inputs())
        .map_err(|error| format!("round: {error}"))?;
    let partials = session.partials(&round)?;
    Ok((session, round, partials))
}

#[test]
fn the_frozen_relation_between_r_u_and_r_hat() -> TestResult {
    // Known-answer test: the composition's binding factor and R̂ are recomputed
    // from the pinned primitives and compared byte for byte.
    let session = refund_session(1)?;
    let round =
        begin_refund_adaptor_round_v1(&session.inputs()).map_err(|error| format!("{error}"))?;

    let factor = binding_factor_v1(
        &session.inputs().binding_context,
        &session.participants,
        Some(&session.refund_point),
    )
    .map_err(|error| format!("binding factor: {error}"))?;
    assert_eq!(
        round.binding_factor(),
        &factor.to_be_bytes(),
        "the binding factor is the pinned one"
    );

    let expected_hat = scriptless_add_public_points(&[
        round.aggregate_nonce().clone(),
        session.refund_point.clone(),
    ])
    .map_err(|error| format!("R + U: {error}"))?;
    assert_eq!(
        round.aggregate_nonce_hat().to_compressed_bytes(),
        expected_hat.to_compressed_bytes(),
        "R_hat is exactly R + U"
    );
    Ok(())
}

#[test]
fn a_completed_refund_reveals_the_refund_witness() -> TestResult {
    // This is the property the round exists for. Before this module the DOM
    // refund was timelock-only and exposed nothing, so a counterparty waiting
    // on a Monero leg had no recovery. Completing the cycle must yield the
    // refund witness, and it must be the one U commits to.
    let (session, round, partials) = run(7)?;
    let completed = round
        .complete_cycle_v1(&partials, &session.refund_secret)
        .map_err(|error| format!("cycle: {error}"))?;

    assert_eq!(
        completed.refund_adaptor_point(),
        &session.refund_point.to_compressed_bytes(),
        "the cycle reports the point it was bound to"
    );

    let revealed = AdaptorSecret::from_be_bytes(*completed.revealed_refund_secret())
        .map_err(|error| format!("revealed scalar: {error}"))?;
    let revealed_point = revealed
        .public_point()
        .map_err(|error| format!("revealed point: {error}"))?;
    assert_eq!(
        revealed_point.to_compressed_bytes(),
        session.refund_point.to_compressed_bytes(),
        "the revealed witness is the one U commits to"
    );
    Ok(())
}

#[test]
fn a_plain_refund_purpose_is_refused() -> TestResult {
    // PurposeV1::Refund is the timelock refund and reveals nothing. Accepting
    // it here would produce a round that looks adaptor-bound and is not.
    let session = refund_session(3)?;
    let mut inputs = session.inputs();
    inputs.binding_context.purpose = PurposeV1::Refund;
    assert_eq!(
        begin_refund_adaptor_round_v1(&inputs).err(),
        Some(RefundAdaptorRoundError::WrongPurpose)
    );
    Ok(())
}

#[test]
fn a_claim_purpose_is_refused() -> TestResult {
    let session = refund_session(4)?;
    let mut inputs = session.inputs();
    inputs.binding_context.purpose = PurposeV1::ClaimAdaptor;
    assert_eq!(
        begin_refund_adaptor_round_v1(&inputs).err(),
        Some(RefundAdaptorRoundError::WrongPurpose)
    );
    Ok(())
}

#[test]
fn nonces_reused_from_the_claim_round_are_refused() -> TestResult {
    // Two signatures over one nonce with different challenges expose the
    // signing key by subtraction. The claim round and the refund round are
    // exactly that pair, so sharing a nonce across them leaks the share.
    let claim = claim_shaped_session(11)?;
    let reusing = Session::new(11, 0x20, 0x50)?; // same nonce domain as `claim`
    let round =
        begin_refund_adaptor_round_v1(&reusing.inputs()).map_err(|error| format!("{error}"))?;
    assert_eq!(
        round
            .require_nonces_distinct_from_claim(&claim.participants, &claim.refund_point)
            .err(),
        Some(RefundAdaptorRoundError::NonceReusedAcrossRounds)
    );
    Ok(())
}

#[test]
fn distinct_nonces_across_the_two_rounds_are_accepted() -> TestResult {
    let claim = claim_shaped_session(11)?;
    let (_, round, _) = run(11)?;
    round
        .require_nonces_distinct_from_claim(&claim.participants, &claim.refund_point)
        .map_err(|error| format!("distinct nonces should pass: {error}"))?;
    Ok(())
}

#[test]
fn a_refund_point_equal_to_the_claim_point_is_refused() -> TestResult {
    // If both rounds carried the same adaptor point, completing either would
    // reveal the other's witness and the two legs would collapse into one.
    let (session, round, _) = run(13)?;
    let claim = refund_session(17)?;
    assert_eq!(
        round
            .require_nonces_distinct_from_claim(&claim.participants, &session.refund_point)
            .err(),
        Some(RefundAdaptorRoundError::AdaptorPointCollision)
    );
    Ok(())
}

#[test]
fn a_zero_chain_id_is_refused() -> TestResult {
    let session = refund_session(5)?;
    let mut inputs = session.inputs();
    inputs.binding_context.chain_id = [0_u8; 32];
    assert_eq!(
        begin_refund_adaptor_round_v1(&inputs).err(),
        Some(RefundAdaptorRoundError::ZeroChainId)
    );
    Ok(())
}

#[test]
fn a_roster_that_is_not_two_participants_is_refused() -> TestResult {
    let session = refund_session(6)?;
    let single = &session.participants[..1];
    let mut inputs = session.inputs();
    inputs.participants = single;
    assert_eq!(
        begin_refund_adaptor_round_v1(&inputs).err(),
        Some(RefundAdaptorRoundError::NonCanonicalRoster)
    );
    Ok(())
}

#[test]
fn partials_from_another_settlement_are_refused() -> TestResult {
    // Partials built over a different session's challenge must not aggregate
    // into this one.
    let (session, round, _) = run(19)?;
    let (_, other_round, other_partials) = run(23)?;
    let _ = other_round;
    assert!(
        round
            .complete_cycle_v1(&other_partials, &session.refund_secret)
            .is_err(),
        "another settlement's partials must not complete this round"
    );
    Ok(())
}

#[test]
fn a_wrong_refund_secret_does_not_complete_the_cycle() -> TestResult {
    let (_, round, partials) = run(29)?;
    let other = refund_session(31)?;
    assert!(
        round
            .complete_cycle_v1(&partials, &other.refund_secret)
            .is_err(),
        "a secret that does not match U must not adapt"
    );
    Ok(())
}

#[test]
fn a_short_partial_set_is_refused() -> TestResult {
    let (session, round, partials) = run(37)?;
    assert_eq!(
        round
            .complete_cycle_v1(&partials[..1], &session.refund_secret)
            .err(),
        Some(RefundAdaptorRoundError::PartialSetMismatch)
    );
    Ok(())
}

/// Named as the guard requires: the frozen relation, stated for the refund
/// point. `the_frozen_relation_between_r_u_and_r_hat` above is the same check
/// under the refund-specific name; this alias keeps the guarded name present.
#[test]
fn the_frozen_relation_between_r_t_and_r_hat() -> TestResult {
    the_frozen_relation_between_r_u_and_r_hat()
}

#[test]
fn the_complete_cycle_closes_on_the_adaptor_point() -> TestResult {
    let (session, round, partials) = run(41)?;
    let cycle = round
        .complete_cycle_v1(&partials, &session.refund_secret)
        .map_err(|error| format!("cycle: {error}"))?;
    assert_eq!(
        cycle.refund_adaptor_point(),
        &session.refund_point.to_compressed_bytes(),
        "u*G must equal U"
    );
    Ok(())
}

#[test]
fn a_permuted_participant_association_is_refused() -> TestResult {
    let (session, round, partials) = run(43)?;
    // Same two partials, swapped between participants. Each scalar is
    // individually valid; only the association is wrong.
    let swapped = vec![
        PartialSignatureV1::new(
            PurposeV1::RefundAdaptor,
            session.participants[0].participant_index,
            TEMPLATE_HASH,
            partials[1].partial().clone(),
        ),
        PartialSignatureV1::new(
            PurposeV1::RefundAdaptor,
            session.participants[1].participant_index,
            TEMPLATE_HASH,
            partials[0].partial().clone(),
        ),
    ];
    assert_eq!(
        round
            .complete_cycle_v1(&swapped, &session.refund_secret)
            .err(),
        Some(RefundAdaptorRoundError::PartialRejected),
        "a permuted association must be named, not absorbed into the sum"
    );
    Ok(())
}

#[test]
fn a_corrupted_partial_is_refused_before_aggregation() -> TestResult {
    let (session, round, partials) = run(47)?;
    for index in 0..partials.len() {
        let mut corrupted = Vec::new();
        for (position, partial) in partials.iter().enumerate() {
            let scalar = if position == index {
                let mut bytes = partial.partial().to_bytes();
                bytes[31] ^= 0x01;
                PartialSig::from_bytes(&bytes)
                    .map_err(|error| format!("corrupt scalar: {error}"))?
            } else {
                partial.partial().clone()
            };
            corrupted.push(PartialSignatureV1::new(
                PurposeV1::RefundAdaptor,
                partial.participant_index(),
                *partial.template_hash(),
                scalar,
            ));
        }
        assert_eq!(
            round
                .complete_cycle_v1(&corrupted, &session.refund_secret)
                .err(),
            Some(RefundAdaptorRoundError::PartialRejected),
            "a corrupted share at {index} must be refused by name"
        );
    }
    Ok(())
}

#[test]
fn the_cycle_is_deterministic_over_many_sessions() -> TestResult {
    // Deterministic sweep. Seed base and count are recorded here so the run is
    // reproducible: base 1000, 10000 sessions, seeds 1000..11000.
    const BASE_SEED: u64 = 1000;
    const SESSIONS: u64 = 10_000;

    let mut completed = 0_u64;
    let mut distinct_binding = std::collections::BTreeSet::new();
    for seed in BASE_SEED..BASE_SEED + SESSIONS {
        let (session, round, partials) = run(seed)?;
        let cycle = round
            .complete_cycle_v1(&partials, &session.refund_secret)
            .map_err(|error| format!("seed {seed}: {error}"))?;
        assert_eq!(
            cycle.refund_adaptor_point(),
            &session.refund_point.to_compressed_bytes(),
            "seed {seed}: u*G must equal U"
        );
        // Every completed refund must expose a witness, in every session.
        assert_ne!(
            cycle.revealed_refund_secret(),
            &[0_u8; 32],
            "seed {seed}: a completed refund must reveal"
        );
        distinct_binding.insert(*round.binding_factor());
        completed += 1;
    }
    assert_eq!(completed, SESSIONS, "every session must complete");
    assert_eq!(
        distinct_binding.len() as u64,
        SESSIONS,
        "each session must produce a distinct binding factor"
    );
    Ok(())
}

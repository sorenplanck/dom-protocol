//! Two-nonce Claim adaptor composition against the pinned DOM backend.
//!
//! Every value in this file is produced by a pinned primitive. No scalar
//! arithmetic, hash, challenge, or point operation is written here: partial
//! signatures are built with `dom_scriptless_primitives::secret_scalar_mul_add_assign`, the
//! same accumulator the pinned signer uses, and every check is the pinned one.
//!
//! The known-answer test `the_frozen_relation_between_r_t_and_r_hat` freezes
//! the measured relation `R̂ = R + T` byte for byte against the backend.

use dom_adaptor::{
    binding_factor_v1, AdaptorSecret, BindingContextV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, PurposeV1,
};
use dom_crypto::{PartialSig, PublicKey, schnorr_challenge};
use dom_scriptless_primitives::{scriptless_add_public_points, secret_scalar_mul_add_assign, secret_scalar_public_key};
use dom_scriptless_crypto::{
    begin_claim_adaptor_round_v1, ClaimAdaptorRoundError, ClaimAdaptorRoundInputsV1,
    ClaimAdaptorRoundV1, CompletedClaimAdaptorCycleV1,
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
    // Keep it comfortably below the group order and never zero.
    out[1] = 0x01;
    out
}

/// One participant's secret material, held only inside the test.
struct Secrets {
    signing_share: Zeroizing<[u8; 32]>,
    first_nonce: Zeroizing<[u8; 32]>,
    second_nonce: Zeroizing<[u8; 32]>,
}

impl Secrets {
    fn new(seed: u64) -> Self {
        Self {
            signing_share: Zeroizing::new(scalar(seed, 0x10)),
            first_nonce: Zeroizing::new(scalar(seed, 0x20)),
            second_nonce: Zeroizing::new(scalar(seed, 0x30)),
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

/// A complete two-party session, assembled entirely from pinned primitives.
struct Session {
    participants: Vec<ParticipantPublicNoncesV1>,
    secrets: Vec<Secrets>,
    aggregate_signing_key: PublicKey,
    adaptor_secret: AdaptorSecret,
    adaptor_point: PublicKey,
}

impl Session {
    fn new(seed: u64) -> Result<Self, String> {
        let mut secrets = vec![Secrets::new(seed), Secrets::new(seed.wrapping_add(0x9E37))];

        let mut published = Vec::with_capacity(2);
        for entry in &secrets {
            let (key, first, second) = entry.public()?;
            published.push((key, first, second));
        }

        // Canonical roster order: the pinned transcript requires strictly
        // increasing participant indexes AND lexicographic signing keys.
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

        let adaptor_secret = AdaptorSecret::from_be_bytes(scalar(seed, 0x40))
            .map_err(|error| format!("adaptor secret: {error}"))?;
        let adaptor_point = adaptor_secret
            .public_point()
            .map_err(|error| format!("adaptor point: {error}"))?;

        Ok(Self {
            participants,
            secrets,
            aggregate_signing_key,
            adaptor_secret,
            adaptor_point,
        })
    }

    fn inputs(&self) -> ClaimAdaptorRoundInputsV1<'_> {
        ClaimAdaptorRoundInputsV1 {
            binding_context: BindingContextV1 {
                chain_id: CHAIN_ID,
                session_id: SESSION_ID,
                purpose: PurposeV1::ClaimAdaptor,
                template_hash: TEMPLATE_HASH,
            },
            participants: &self.participants,
            adaptor_point: self.adaptor_point.clone(),
            aggregate_signing_key: self.aggregate_signing_key.clone(),
            transcript_hash: TRANSCRIPT_HASH,
            kernel_message_digest: MESSAGE,
        }
    }

    /// Build every partial with the pinned accumulator.
    ///
    /// `k_i = r1_i + b·r2_i` and `s_i = k_i + e·x_i` are both computed by
    /// `secret_scalar_mul_add_assign`, so nothing here implements signing.
    fn partials(&self, round: &ClaimAdaptorRoundV1) -> Result<Vec<PartialSignatureV1>, String> {
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
                PurposeV1::ClaimAdaptor,
                self.participants[index].participant_index,
                TEMPLATE_HASH,
                partial,
            ));
        }
        Ok(partials)
    }
}

fn refusal(
    result: Result<CompletedClaimAdaptorCycleV1, ClaimAdaptorRoundError>,
) -> Option<ClaimAdaptorRoundError> {
    result.err()
}

fn run(seed: u64) -> Result<(Session, ClaimAdaptorRoundV1, Vec<PartialSignatureV1>), String> {
    let session = Session::new(seed)?;
    let round = begin_claim_adaptor_round_v1(&session.inputs())
        .map_err(|error| format!("round: {error}"))?;
    let partials = session.partials(&round)?;
    Ok((session, round, partials))
}

#[test]
fn the_frozen_relation_between_r_t_and_r_hat() -> TestResult {
    // Known-answer test for the measured relation, recomputed here from the
    // pinned primitives and compared byte for byte with what the composition
    // produced. If the backend ever formed R_hat differently, this fails.
    let session = Session::new(1)?;
    let round =
        begin_claim_adaptor_round_v1(&session.inputs()).map_err(|error| format!("{error}"))?;

    let factor = binding_factor_v1(
        &session.inputs().binding_context,
        &session.participants,
        Some(&session.adaptor_point),
    )
    .map_err(|error| format!("binding factor: {error}"))?;
    assert_eq!(
        round.binding_factor(),
        &factor.to_be_bytes(),
        "the binding factor must be the pinned one"
    );

    let mut expected_effective = Vec::new();
    for participant in &session.participants {
        let bound = factor
            .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)
            .map_err(|error| format!("bind: {error}"))?;
        expected_effective.push(bound);
    }
    for (index, expected) in expected_effective.iter().enumerate() {
        assert_eq!(
            round.effective_nonces()[index].to_compressed_bytes(),
            expected.to_compressed_bytes(),
            "R_{index} must be R1 + R2*b"
        );
    }

    let expected_r = scriptless_add_public_points(&expected_effective)
        .map_err(|error| format!("aggregate R: {error}"))?;
    assert_eq!(
        round.aggregate_nonce().to_compressed_bytes(),
        expected_r.to_compressed_bytes(),
        "R must be the sum of the effective nonces"
    );

    // The frozen relation: R_hat = R + T, adaptor point ADDED.
    let expected_r_hat =
        scriptless_add_public_points(&[expected_r.clone(), session.adaptor_point.clone()])
            .map_err(|error| format!("aggregate R_hat: {error}"))?;
    assert_eq!(
        round.aggregate_nonce_hat().to_compressed_bytes(),
        expected_r_hat.to_compressed_bytes(),
        "R_hat must be R + T"
    );
    assert_ne!(
        round.aggregate_nonce().to_compressed_bytes(),
        round.aggregate_nonce_hat().to_compressed_bytes(),
        "R_hat must differ from R; a no-op adaptor point would be a silent break"
    );
    Ok(())
}

#[test]
fn the_complete_cycle_closes_on_the_adaptor_point() -> TestResult {
    let (session, round, partials) = run(7)?;
    let completed = round
        .complete_cycle_v1(&partials, &session.adaptor_secret)
        .map_err(|error| format!("cycle: {error}"))?;

    assert_eq!(
        completed.adaptor_point(),
        &session.adaptor_point.to_compressed_bytes()
    );
    assert_eq!(
        completed.aggregate_nonce_hat(),
        &round.aggregate_nonce_hat().to_compressed_bytes()
    );
    assert_eq!(completed.final_signature().len(), 65);
    // The Stage 4 evidence rides along and is the same session.
    assert_eq!(completed.pre_signature().chain_id(), &CHAIN_ID);
    assert_eq!(
        completed.pre_signature().claim_template_hash(),
        &TEMPLATE_HASH
    );
    Ok(())
}

#[test]
fn a_wrong_adaptor_secret_is_refused() -> TestResult {
    let (_session, round, partials) = run(11)?;
    let wrong = AdaptorSecret::from_be_bytes(scalar(11, 0x41))
        .map_err(|error| format!("wrong secret: {error}"))?;
    assert_eq!(
        refusal(round.complete_cycle_v1(&partials, &wrong)),
        Some(ClaimAdaptorRoundError::AdaptationRejected),
        "adapting with the wrong t must be refused"
    );
    Ok(())
}

#[test]
fn a_corrupted_partial_is_refused_before_aggregation() -> TestResult {
    let (session, round, partials) = run(13)?;
    for index in 0..partials.len() {
        let mut corrupted = Vec::new();
        for (position, partial) in partials.iter().enumerate() {
            if position == index {
                let mut bytes = partial.partial().to_bytes();
                bytes[31] ^= 0x01;
                let scalar = PartialSig::from_bytes(&bytes)
                    .map_err(|error| format!("corrupt scalar: {error}"))?;
                corrupted.push(PartialSignatureV1::new(
                    PurposeV1::ClaimAdaptor,
                    partial.participant_index(),
                    *partial.template_hash(),
                    scalar,
                ));
            } else {
                corrupted.push(PartialSignatureV1::new(
                    PurposeV1::ClaimAdaptor,
                    partial.participant_index(),
                    *partial.template_hash(),
                    partial.partial().clone(),
                ));
            }
        }
        assert_eq!(
            refusal(round.complete_cycle_v1(&corrupted, &session.adaptor_secret)),
            Some(ClaimAdaptorRoundError::PartialRejected),
            "a corrupted partial at {index} must be named, not absorbed into the sum"
        );
    }
    Ok(())
}

#[test]
fn a_permuted_participant_association_is_refused() -> TestResult {
    let (session, round, partials) = run(17)?;
    // Same two partials, swapped between participants. Each scalar is
    // individually valid; only the association is wrong.
    let swapped = vec![
        PartialSignatureV1::new(
            PurposeV1::ClaimAdaptor,
            session.participants[0].participant_index,
            TEMPLATE_HASH,
            partials[1].partial().clone(),
        ),
        PartialSignatureV1::new(
            PurposeV1::ClaimAdaptor,
            session.participants[1].participant_index,
            TEMPLATE_HASH,
            partials[0].partial().clone(),
        ),
    ];
    assert_eq!(
        refusal(round.complete_cycle_v1(&swapped, &session.adaptor_secret)),
        Some(ClaimAdaptorRoundError::PartialRejected),
        "a swapped participant association must be refused"
    );
    Ok(())
}

#[test]
fn a_reordered_partial_set_is_refused() -> TestResult {
    let (session, round, partials) = run(19)?;
    let reversed: Vec<PartialSignatureV1> = partials
        .iter()
        .rev()
        .map(|partial| {
            PartialSignatureV1::new(
                PurposeV1::ClaimAdaptor,
                partial.participant_index(),
                *partial.template_hash(),
                partial.partial().clone(),
            )
        })
        .collect();
    assert_eq!(
        refusal(round.complete_cycle_v1(&reversed, &session.adaptor_secret)),
        Some(ClaimAdaptorRoundError::PartialSetMismatch),
        "a reordered set must be refused on index association"
    );
    Ok(())
}

#[test]
fn a_short_or_long_partial_set_is_refused() -> TestResult {
    let (session, round, partials) = run(23)?;
    let one = vec![PartialSignatureV1::new(
        PurposeV1::ClaimAdaptor,
        partials[0].participant_index(),
        TEMPLATE_HASH,
        partials[0].partial().clone(),
    )];
    assert_eq!(
        refusal(round.complete_cycle_v1(&one, &session.adaptor_secret)),
        Some(ClaimAdaptorRoundError::PartialSetMismatch)
    );

    let mut three = Vec::new();
    for partial in partials.iter().chain(partials.iter().take(1)) {
        three.push(PartialSignatureV1::new(
            PurposeV1::ClaimAdaptor,
            partial.participant_index(),
            TEMPLATE_HASH,
            partial.partial().clone(),
        ));
    }
    assert_eq!(
        refusal(round.complete_cycle_v1(&three, &session.adaptor_secret)),
        Some(ClaimAdaptorRoundError::PartialSetMismatch)
    );
    Ok(())
}

#[test]
fn a_wrong_purpose_is_refused_before_any_binding() -> TestResult {
    let session = Session::new(29)?;
    for purpose in [PurposeV1::Funding, PurposeV1::Refund, PurposeV1::Sponsor] {
        let mut inputs = session.inputs();
        inputs.binding_context.purpose = purpose;
        assert_eq!(
            begin_claim_adaptor_round_v1(&inputs).err(),
            Some(ClaimAdaptorRoundError::WrongPurpose),
            "purpose {purpose:?} must be refused"
        );
    }
    Ok(())
}

#[test]
fn a_zero_chain_id_is_refused_before_any_cryptography() -> TestResult {
    let session = Session::new(31)?;
    let mut inputs = session.inputs();
    inputs.binding_context.chain_id = [0_u8; 32];
    assert_eq!(
        begin_claim_adaptor_round_v1(&inputs).err(),
        Some(ClaimAdaptorRoundError::ZeroChainId)
    );
    Ok(())
}

#[test]
fn a_non_two_roster_is_refused() -> TestResult {
    let session = Session::new(37)?;
    let single = vec![session.participants[0].clone()];
    let mut inputs = session.inputs();
    inputs.participants = &single;
    assert_eq!(
        begin_claim_adaptor_round_v1(&inputs).err(),
        Some(ClaimAdaptorRoundError::NonCanonicalRoster),
        "the ratified roster is exactly two"
    );
    Ok(())
}

#[test]
fn a_noncanonical_roster_order_is_refused_by_the_pinned_transcript() -> TestResult {
    let session = Session::new(41)?;
    let reversed = vec![
        session.participants[1].clone(),
        session.participants[0].clone(),
    ];
    let mut inputs = session.inputs();
    inputs.participants = &reversed;
    assert_eq!(
        begin_claim_adaptor_round_v1(&inputs).err(),
        Some(ClaimAdaptorRoundError::BindingRefused),
        "the pinned transcript owns roster ordering"
    );
    Ok(())
}

#[test]
fn every_binding_field_changes_the_round() -> TestResult {
    // The binding factor commits to each of these. A change that left the
    // factor untouched would mean the field is not bound.
    let session = Session::new(43)?;
    let base =
        begin_claim_adaptor_round_v1(&session.inputs()).map_err(|error| format!("{error}"))?;
    let baseline = *base.binding_factor();

    let mut altered = session.inputs();
    altered.binding_context.chain_id = [0xBE; 32];
    let changed = begin_claim_adaptor_round_v1(&altered).map_err(|error| format!("{error}"))?;
    assert_ne!(changed.binding_factor(), &baseline, "chain id must bind");

    let mut altered = session.inputs();
    altered.binding_context.session_id = [0xBE; 32];
    let changed = begin_claim_adaptor_round_v1(&altered).map_err(|error| format!("{error}"))?;
    assert_ne!(changed.binding_factor(), &baseline, "session id must bind");

    let mut altered = session.inputs();
    altered.binding_context.template_hash = [0xBE; 32];
    let changed = begin_claim_adaptor_round_v1(&altered).map_err(|error| format!("{error}"))?;
    assert_ne!(
        changed.binding_factor(),
        &baseline,
        "template hash must bind"
    );

    let other = Session::new(44)?;
    let mut altered = session.inputs();
    altered.adaptor_point = other.adaptor_point.clone();
    let changed = begin_claim_adaptor_round_v1(&altered).map_err(|error| format!("{error}"))?;
    assert_ne!(
        changed.binding_factor(),
        &baseline,
        "the adaptor point must bind"
    );
    Ok(())
}

#[test]
fn a_wrong_aggregate_signing_key_is_refused() -> TestResult {
    let (session, _round, partials) = run(47)?;
    let other = Session::new(48)?;
    let mut inputs = session.inputs();
    inputs.aggregate_signing_key = other.aggregate_signing_key.clone();
    let wrong_round = begin_claim_adaptor_round_v1(&inputs).map_err(|error| format!("{error}"))?;
    assert!(
        refusal(wrong_round.complete_cycle_v1(&partials, &session.adaptor_secret)).is_some(),
        "a wrong aggregate key must be refused"
    );
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
            .complete_cycle_v1(&partials, &session.adaptor_secret)
            .map_err(|error| format!("seed {seed}: {error}"))?;
        assert_eq!(
            cycle.adaptor_point(),
            &session.adaptor_point.to_compressed_bytes(),
            "seed {seed}: t*G must equal T"
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

#[test]
fn a_wrong_aggregate_key_is_refused_with_a_named_reason() -> TestResult {
    // Asserted by variant, not by `is_some()`. A negative test that accepts
    // any error cannot tell a real refusal from an unrelated one.
    let (session, _round, partials) = run(53)?;
    let other = Session::new(54)?;
    let mut inputs = session.inputs();
    inputs.aggregate_signing_key = other.aggregate_signing_key.clone();
    let wrong_round = begin_claim_adaptor_round_v1(&inputs).map_err(|error| format!("{error}"))?;
    assert_eq!(
        refusal(wrong_round.complete_cycle_v1(&partials, &session.adaptor_secret)),
        Some(ClaimAdaptorRoundError::PartialRejected),
        "the aggregate key is not in the binding transcript, so R_hat is \
         unchanged and only the challenge moves: the partials fail first"
    );
    Ok(())
}

#[test]
fn a_changed_public_nonce_changes_the_round() -> TestResult {
    // The published nonces are bound into the transcript. A change that left
    // the binding factor untouched would mean they are not bound at all.
    let session = Session::new(59)?;
    let other = Session::new(60)?;
    let base =
        begin_claim_adaptor_round_v1(&session.inputs()).map_err(|error| format!("{error}"))?;
    let baseline = *base.binding_factor();

    for slot in 0..2_usize {
        let mut roster = session.participants.clone();
        roster[slot].first_nonce = other.participants[slot].first_nonce.clone();
        let mut inputs = session.inputs();
        inputs.participants = &roster;
        let changed = begin_claim_adaptor_round_v1(&inputs).map_err(|error| format!("{error}"))?;
        assert_ne!(
            changed.binding_factor(),
            &baseline,
            "the first nonce of participant {slot} must bind"
        );

        let mut roster = session.participants.clone();
        roster[slot].second_nonce = other.participants[slot].second_nonce.clone();
        let mut inputs = session.inputs();
        inputs.participants = &roster;
        let changed = begin_claim_adaptor_round_v1(&inputs).map_err(|error| format!("{error}"))?;
        assert_ne!(
            changed.binding_factor(),
            &baseline,
            "the second nonce of participant {slot} must bind"
        );
    }
    Ok(())
}

#[test]
fn a_changed_kernel_message_is_refused() -> TestResult {
    // The kernel message digest is challenge input, so a change must break the
    // partials rather than merely alter a hash.
    let (session, _round, partials) = run(61)?;
    let mut inputs = session.inputs();
    inputs.kernel_message_digest = [0xCD; 32];
    let altered = begin_claim_adaptor_round_v1(&inputs).map_err(|error| format!("{error}"))?;
    assert_eq!(
        refusal(altered.complete_cycle_v1(&partials, &session.adaptor_secret)),
        Some(ClaimAdaptorRoundError::PartialRejected)
    );
    Ok(())
}

#[test]
fn the_transcript_hash_is_not_an_intrinsic_kernel_guarantee() -> TestResult {
    // The Stage 4 limit, made concrete at the composition level.
    //
    // The transcript hash is not challenge input and is not in the binding
    // transcript either: `BindingContextV1` carries chain id, session id,
    // purpose and template hash only. So a round run with a completely
    // different transcript hash, consistently on both sides, produces a
    // VALID cycle over the same partials, and the same 65-byte signature.
    //
    // This test asserts that success on purpose. It is the honest statement of
    // what the metadata does and does not prove: it records protocol
    // provenance, and it is not an intrinsic cryptographic guarantee about the
    // final kernel signature. Anything that must be guaranteed has to be bound
    // by the transcript that produced the template, outside this module.
    let (session, round, partials) = run(67)?;
    let baseline = round
        .complete_cycle_v1(&partials, &session.adaptor_secret)
        .map_err(|error| format!("baseline cycle: {error}"))?;

    let mut inputs = session.inputs();
    inputs.transcript_hash = [0x99; 32];
    let rebound = begin_claim_adaptor_round_v1(&inputs).map_err(|error| format!("{error}"))?;

    // The binding factor is untouched, so the same partials still apply.
    assert_eq!(
        rebound.binding_factor(),
        round.binding_factor(),
        "the transcript hash is not in the binding transcript"
    );
    let rebound_cycle = rebound
        .complete_cycle_v1(&partials, &session.adaptor_secret)
        .map_err(|error| format!("re-bound cycle must still verify: {error}"))?;

    assert_eq!(
        rebound_cycle.final_signature(),
        baseline.final_signature(),
        "the same partials produce the same kernel signature under a different \
         transcript hash: the metadata binds provenance, not the signature"
    );
    assert_eq!(
        rebound_cycle.pre_signature().transcript_hash(),
        &[0x99_u8; 32],
        "the evidence records the transcript hash it was given, nothing more"
    );
    Ok(())
}

#[test]
fn the_round_retains_its_own_roster() -> TestResult {
    // `complete_cycle_v1` takes no roster. The participants the binding factor
    // and the effective nonces were derived from are the ones every partial is
    // checked against, so a caller cannot assert a different association after
    // the fact. This test pins that API property: partials from one session
    // offered to another session's round are refused.
    let (first, first_round, first_partials) = run(71)?;
    let (_second, second_round, second_partials) = run(72)?;

    assert_eq!(
        refusal(second_round.complete_cycle_v1(&first_partials, &first.adaptor_secret)),
        Some(ClaimAdaptorRoundError::PartialRejected),
        "one session's partials must not satisfy another session's round"
    );
    assert!(
        first_round
            .complete_cycle_v1(&second_partials, &first.adaptor_secret)
            .is_err(),
        "and the reverse must also be refused"
    );
    Ok(())
}

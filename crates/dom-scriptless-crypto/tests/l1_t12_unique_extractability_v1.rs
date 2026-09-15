//! L1-T12 (DR-PRIV-001 L1 package §3.1/§8.2): unique-extractability
//! vectors for the leg Claim and Refund adaptor rounds, against the
//! [GSST24] strengthened property set.
//!
//! What is exercised, per round:
//!
//! - **one verifying pre-signature commits to one full-signature
//!   outcome**: completing the same cycle twice yields byte-identical
//!   final signatures, and every single-bit mutation of the final 65
//!   bytes either fails canonical decode, fails the pinned final
//!   verifier, or fails extraction against the committed adaptor point —
//!   no mutation yields a second (signature, witness) pair;
//! - **no pair-shaped or otherwise malleable pre-signature encoding
//!   decodes**: the payload is exactly 162 bytes; doubled (pair-shaped),
//!   truncated and extended encodings refuse before any cryptography;
//! - **pre-verify soundness at the byte level**: every single-bit
//!   mutation of the 162-byte payload refuses through the Stage 4
//!   verifier.
//!
//! Honest note carried from the package: on the discrete-log relation a
//! statement has a unique witness, so extraction ambiguity collapses for
//! honest statements — these vectors pin the ENCODINGS and the pinned
//! verification chain, which is where [GSST24]'s counterexample lives
//! (a pair of pre-signatures smuggled through one payload).
//!
//! The session fixture follows the sibling suites byte for byte: every
//! value is produced by a pinned primitive; nothing here implements
//! signing.

use dom_adaptor::{
    aggregate_partial_signatures_v1, AdaptorPreSignatureV1, AdaptorSecret, BindingContextV1,
    PartialSignatureV1, ParticipantPublicNoncesV1, PurposeV1,
};
use dom_crypto::{schnorr_challenge, PartialSig, PublicKey, SchnorrSignature};
use dom_scriptless_crypto::{
    begin_claim_adaptor_round_v1, begin_refund_adaptor_round_v1,
    verify_claim_adaptor_pre_signature_v1, ClaimAdaptorRoundInputsV1,
    ClaimAdaptorVerificationRequestV1, RefundAdaptorRoundInputsV1, CLAIM_ADAPTOR_PRE_SIGNATURE_LEN,
};
use dom_scriptless_primitives::{
    scriptless_add_public_points, scriptless_verify_final_signature, secret_scalar_mul_add_assign,
    secret_scalar_public_key,
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
    adaptor_secret: AdaptorSecret,
    adaptor_point: PublicKey,
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

        let adaptor_secret = AdaptorSecret::from_be_bytes(scalar(seed, secret_domain))
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

    fn claim_inputs(&self) -> ClaimAdaptorRoundInputsV1<'_> {
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

    fn refund_inputs(&self) -> RefundAdaptorRoundInputsV1<'_> {
        RefundAdaptorRoundInputsV1 {
            binding_context: BindingContextV1 {
                chain_id: CHAIN_ID,
                session_id: SESSION_ID,
                purpose: PurposeV1::RefundAdaptor,
                template_hash: TEMPLATE_HASH,
            },
            participants: &self.participants,
            refund_adaptor_point: self.adaptor_point.clone(),
            aggregate_signing_key: self.aggregate_signing_key.clone(),
            transcript_hash: TRANSCRIPT_HASH,
            kernel_message_digest: MESSAGE,
        }
    }

    /// Build every partial with the pinned accumulator, for either purpose.
    fn partials(
        &self,
        purpose: PurposeV1,
        binding: &[u8; 32],
        aggregate_nonce_hat: &PublicKey,
    ) -> Result<Vec<PartialSignatureV1>, String> {
        let challenge = schnorr_challenge(
            &aggregate_nonce_hat.to_compressed_bytes(),
            &self.aggregate_signing_key,
            &CHAIN_ID,
            &MESSAGE,
        );
        let challenge_bytes = *challenge.as_bytes();

        let mut partials = Vec::with_capacity(self.secrets.len());
        for (index, entry) in self.secrets.iter().enumerate() {
            let mut accumulator = Zeroizing::new(*entry.first_nonce);
            secret_scalar_mul_add_assign(&mut accumulator, &entry.second_nonce, binding)
                .map_err(|error| format!("effective nonce {index}: {error}"))?;
            secret_scalar_mul_add_assign(&mut accumulator, &entry.signing_share, &challenge_bytes)
                .map_err(|error| format!("partial {index}: {error}"))?;
            let partial = PartialSig::from_bytes(accumulator.as_ref())
                .map_err(|error| format!("partial scalar {index}: {error}"))?;
            partials.push(PartialSignatureV1::new(
                purpose,
                self.participants[index].participant_index,
                TEMPLATE_HASH,
                partial,
            ));
        }
        Ok(partials)
    }
}

/// Rebuild the exact 162-byte pre-signature the round assembles, through
/// the same pinned aggregation, so extraction can be exercised directly.
fn assemble_pre_signature(
    purpose: PurposeV1,
    partials: &[PartialSignatureV1],
    adaptor_point: &PublicKey,
    aggregate_nonce_hat: &PublicKey,
) -> Result<AdaptorPreSignatureV1, String> {
    let aggregate = aggregate_partial_signatures_v1(partials, purpose, &TEMPLATE_HASH)
        .map_err(|error| format!("aggregation: {error}"))?;
    let scalar_hat = PartialSig::from_bytes(&aggregate.to_bytes())
        .map_err(|error| format!("scalar hat: {error}"))?;
    Ok(AdaptorPreSignatureV1::new(
        TEMPLATE_HASH,
        adaptor_point.clone(),
        aggregate_nonce_hat.clone(),
        scalar_hat,
        TRANSCRIPT_HASH,
    ))
}

/// The uniqueness sweep: every single-bit mutation of the final 65 bytes
/// must fail canonical decode, the pinned final verifier, or extraction.
/// Returns the (decode, verify, extract) refusal counts for the record.
fn sweep_final_signature(
    pre_signature: &AdaptorPreSignatureV1,
    final_signature: &[u8; 65],
    aggregate_signing_key: &PublicKey,
) -> Result<(u32, u32, u32), String> {
    let mut refused_decode = 0_u32;
    let mut refused_verify = 0_u32;
    let mut refused_extract = 0_u32;
    for position in 0..final_signature.len() {
        for bit in 0..8_u8 {
            let mut mutated = *final_signature;
            mutated[position] ^= 1 << bit;
            let candidate = match SchnorrSignature::from_bytes(&mutated) {
                Err(_) => {
                    refused_decode += 1;
                    continue;
                }
                Ok(candidate) => candidate,
            };
            match scriptless_verify_final_signature(
                &candidate,
                aggregate_signing_key,
                &CHAIN_ID,
                &MESSAGE,
            ) {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    refused_verify += 1;
                    continue;
                }
            }
            // A mutation that still verifies as a DOM signature must not
            // ALSO extract a witness for the committed point — that pair
            // would be exactly the [GSST24] break.
            if pre_signature
                .extract(
                    &candidate,
                    &TEMPLATE_HASH,
                    &TRANSCRIPT_HASH,
                    aggregate_signing_key,
                    &CHAIN_ID,
                    &MESSAGE,
                )
                .is_err()
            {
                refused_extract += 1;
            } else {
                return Err(format!(
                    "byte {position} bit {bit}: a second (signature, witness) pair \
                     extracted — unique extractability is broken"
                ));
            }
        }
    }
    Ok((refused_decode, refused_verify, refused_extract))
}

#[test]
fn claim_round_one_pre_signature_commits_to_one_signature() -> TestResult {
    let session = Session::new(101, 0x20, 0x40)?;
    let round = begin_claim_adaptor_round_v1(&session.claim_inputs())
        .map_err(|error| format!("round: {error}"))?;
    let partials = session.partials(
        PurposeV1::ClaimAdaptor,
        round.binding_factor(),
        round.aggregate_nonce_hat(),
    )?;

    // Determinism: the same cycle completes to byte-identical signatures.
    let first = round
        .complete_cycle_v1(&partials, &session.adaptor_secret)
        .map_err(|error| format!("first cycle: {error}"))?;
    let second = round
        .complete_cycle_v1(&partials, &session.adaptor_secret)
        .map_err(|error| format!("second cycle: {error}"))?;
    if first.final_signature() != second.final_signature() {
        return Err("the same cycle produced two distinct completing signatures".to_owned());
    }

    // The honest signature extracts the witness of the committed point.
    let pre_signature = assemble_pre_signature(
        PurposeV1::ClaimAdaptor,
        &partials,
        &session.adaptor_point,
        round.aggregate_nonce_hat(),
    )?;
    let honest = SchnorrSignature::from_bytes(first.final_signature())
        .map_err(|error| format!("honest signature decode: {error}"))?;
    pre_signature
        .extract(
            &honest,
            &TEMPLATE_HASH,
            &TRANSCRIPT_HASH,
            &session.aggregate_signing_key,
            &CHAIN_ID,
            &MESSAGE,
        )
        .map_err(|error| format!("honest extraction: {error}"))?;

    // Every single-bit mutation refuses somewhere in the pinned chain.
    let (decode, verify, extract) = sweep_final_signature(
        &pre_signature,
        first.final_signature(),
        &session.aggregate_signing_key,
    )?;
    if decode + verify + extract != 65 * 8 {
        return Err(format!(
            "sweep accounting is wrong: {decode} + {verify} + {extract} != 520"
        ));
    }
    Ok(())
}

#[test]
fn refund_round_one_pre_signature_commits_to_one_signature() -> TestResult {
    let session = Session::new(103, 0x60, 0x50)?;
    let round = begin_refund_adaptor_round_v1(&session.refund_inputs())
        .map_err(|error| format!("round: {error}"))?;
    let partials = session.partials(
        PurposeV1::RefundAdaptor,
        round.binding_factor(),
        round.aggregate_nonce_hat(),
    )?;

    let first = round
        .complete_cycle_v1(&partials, &session.adaptor_secret)
        .map_err(|error| format!("first cycle: {error}"))?;
    let second = round
        .complete_cycle_v1(&partials, &session.adaptor_secret)
        .map_err(|error| format!("second cycle: {error}"))?;
    if first.final_signature() != second.final_signature() {
        return Err("the same refund cycle produced two distinct signatures".to_owned());
    }

    let pre_signature = assemble_pre_signature(
        PurposeV1::RefundAdaptor,
        &partials,
        &session.adaptor_point,
        round.aggregate_nonce_hat(),
    )?;
    let (decode, verify, extract) = sweep_final_signature(
        &pre_signature,
        first.final_signature(),
        &session.aggregate_signing_key,
    )?;
    if decode + verify + extract != 65 * 8 {
        return Err(format!(
            "sweep accounting is wrong: {decode} + {verify} + {extract} != 520"
        ));
    }
    Ok(())
}

#[test]
fn no_pair_shaped_pre_signature_encoding_decodes() -> TestResult {
    let session = Session::new(107, 0x20, 0x40)?;
    let round = begin_claim_adaptor_round_v1(&session.claim_inputs())
        .map_err(|error| format!("round: {error}"))?;
    let partials = session.partials(
        PurposeV1::ClaimAdaptor,
        round.binding_factor(),
        round.aggregate_nonce_hat(),
    )?;
    let pre_signature = assemble_pre_signature(
        PurposeV1::ClaimAdaptor,
        &partials,
        &session.adaptor_point,
        round.aggregate_nonce_hat(),
    )?;
    let payload = pre_signature.to_bytes();
    if payload.len() != CLAIM_ADAPTOR_PRE_SIGNATURE_LEN {
        return Err("the canonical payload is not the pinned width".to_owned());
    }

    // A pair of valid pre-signatures glued into one payload (the exact
    // [GSST24] wrapper shape), a truncation and an extension: every one
    // must refuse at decode, before any cryptography.
    let mut pair_shaped = Vec::with_capacity(payload.len() * 2);
    pair_shaped.extend_from_slice(&payload);
    pair_shaped.extend_from_slice(&payload);
    for bad in [
        &pair_shaped[..],
        &payload[..CLAIM_ADAPTOR_PRE_SIGNATURE_LEN - 1],
        &pair_shaped[..CLAIM_ADAPTOR_PRE_SIGNATURE_LEN + 1],
    ] {
        if AdaptorPreSignatureV1::from_bytes(bad).is_ok() {
            return Err(format!("a {}-byte payload decoded", bad.len()));
        }
        let request = ClaimAdaptorVerificationRequestV1 {
            pre_signature: bad,
            claim_template_hash: TEMPLATE_HASH,
            transcript_hash: TRANSCRIPT_HASH,
            aggregate_signing_key: session.aggregate_signing_key.to_compressed_bytes(),
            chain_id: CHAIN_ID,
            kernel_message_digest: MESSAGE,
        };
        if verify_claim_adaptor_pre_signature_v1(&request).is_ok() {
            return Err(format!("a {}-byte payload verified", bad.len()));
        }
    }
    Ok(())
}

#[test]
fn every_mutated_pre_signature_payload_refuses() -> TestResult {
    let session = Session::new(109, 0x20, 0x40)?;
    let round = begin_claim_adaptor_round_v1(&session.claim_inputs())
        .map_err(|error| format!("round: {error}"))?;
    let partials = session.partials(
        PurposeV1::ClaimAdaptor,
        round.binding_factor(),
        round.aggregate_nonce_hat(),
    )?;
    let pre_signature = assemble_pre_signature(
        PurposeV1::ClaimAdaptor,
        &partials,
        &session.adaptor_point,
        round.aggregate_nonce_hat(),
    )?;
    let payload = pre_signature.to_bytes();

    // The untouched payload verifies — the mutations below fail for a
    // real reason, not because the baseline was already refused.
    let baseline = ClaimAdaptorVerificationRequestV1 {
        pre_signature: &payload,
        claim_template_hash: TEMPLATE_HASH,
        transcript_hash: TRANSCRIPT_HASH,
        aggregate_signing_key: session.aggregate_signing_key.to_compressed_bytes(),
        chain_id: CHAIN_ID,
        kernel_message_digest: MESSAGE,
    };
    verify_claim_adaptor_pre_signature_v1(&baseline)
        .map_err(|error| format!("baseline payload must verify: {error}"))?;

    for position in 0..payload.len() {
        let mut mutated = payload;
        mutated[position] ^= 0x01;
        let request = ClaimAdaptorVerificationRequestV1 {
            pre_signature: &mutated,
            claim_template_hash: TEMPLATE_HASH,
            transcript_hash: TRANSCRIPT_HASH,
            aggregate_signing_key: session.aggregate_signing_key.to_compressed_bytes(),
            chain_id: CHAIN_ID,
            kernel_message_digest: MESSAGE,
        };
        if verify_claim_adaptor_pre_signature_v1(&request).is_ok() {
            return Err(format!(
                "payload byte {position} mutated and still verified — the \
                 encoding admits malleability"
            ));
        }
    }
    Ok(())
}

//! Claim adaptor pre-signature verification against the frozen SCAD0 corpus.
//!
//! The vectors are imported from the pinned DOM Protocol revision and are never
//! regenerated here; see `tests/fixtures/PROVENANCE.md`. Every positive result
//! in this file comes from the pinned verifier, and no test constructs
//! acceptance evidence by any other route.

use dom_consensus::TransactionKernel;
use dom_crypto::SchnorrSignature;
use dom_scriptless_crypto::{
    verify_claim_adaptor_pre_signature_v1, ClaimAdaptorVerificationError,
    ClaimAdaptorVerificationRequestV1, VerifiedClaimAdaptorPreSignatureV1,
    CLAIM_ADAPTOR_PRE_SIGNATURE_LEN,
};
use dom_serialization::DomDeserialize;

/// The frozen chain identifier the upstream fixture consumer verifies against.
const CHAIN_ID: [u8; 32] = [0xAD; 32];

/// The frozen kernel message digest the upstream fixture consumer signs over.
const MESSAGE: [u8; 32] = [
    0x10, 0xd4, 0x3a, 0x5a, 0xc3, 0x16, 0x0f, 0xdb, 0xc6, 0x7a, 0x1f, 0x8a, 0x29, 0x3f, 0x97, 0x50,
    0x55, 0x8e, 0x53, 0xc1, 0x8f, 0xa3, 0x7f, 0x58, 0xd3, 0x40, 0xdf, 0x3f, 0xdd, 0x41, 0xaa, 0x34,
];

const FIXTURE: &str = include_str!("fixtures/scad0_adaptor_vectors_v1.txt");

/// Field offsets inside the canonical payload, restated so a mutation names the
/// component it corrupts rather than a bare integer.
const TEMPLATE_RANGE: std::ops::Range<usize> = 0..32;
const ADAPTOR_POINT_RANGE: std::ops::Range<usize> = 32..65;
const NONCE_HAT_RANGE: std::ops::Range<usize> = 65..98;
const SCALAR_RANGE: std::ops::Range<usize> = 98..130;
const TRANSCRIPT_RANGE: std::ops::Range<usize> = 130..162;

/// A test failure, reported as text so no test needs `unwrap`, `expect`, or
/// `panic!`, all of which this workspace denies in every target.
type TestResult = Result<(), String>;

/// One frozen vector, reduced to what the verification path needs.
struct Vector {
    id: String,
    /// The canonical 162-byte payload assembled from the frozen fields.
    payload: [u8; CLAIM_ADAPTOR_PRE_SIGNATURE_LEN],
    signing_key: [u8; 33],
    claim_template_hash: [u8; 32],
    transcript_hash: [u8; 32],
    /// SEC1 prefixes of `T`, `X` and `R̂`, recorded for parity coverage.
    parity: (u8, u8, u8),
}

/// The refusal a call produced, or `None` when it produced evidence.
///
/// `Result::unwrap_err` and `assert_eq!` over the whole `Result` both require
/// `Debug` on the success type, and `VerifiedClaimAdaptorPreSignatureV1`
/// deliberately implements neither `Debug` nor `PartialEq`. That opacity is
/// itself under test, so the tests reduce the result to its error instead of
/// weakening the type to make comparison possible.
fn refusal(
    result: Result<VerifiedClaimAdaptorPreSignatureV1, ClaimAdaptorVerificationError>,
) -> Option<ClaimAdaptorVerificationError> {
    result.err()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

/// Session bindings are derived from the vector id so each vector belongs to a
/// distinct session. They are test bindings and carry no authority.
fn binding(id: &str, salt: u8) -> [u8; 32] {
    let mut out = [salt; 32];
    for (slot, byte) in out.iter_mut().zip(id.as_bytes()) {
        *slot = *byte;
    }
    out
}

fn vectors() -> Result<Vec<Vector>, String> {
    let mut parsed = Vec::new();
    for line in FIXTURE.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        if fields.len() != 5 {
            return Err(format!(
                "fixture line has {} fields, expected 5",
                fields.len()
            ));
        }

        let id = fields[0].to_owned();
        let t_point: [u8; 33] = decode_hex(fields[2])
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{id}: adaptor point is not 33 hex-encoded bytes"))?;
        let s_hat: [u8; 32] = decode_hex(fields[3])
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{id}: scalar is not 32 hex-encoded bytes"))?;
        let kernel_bytes =
            decode_hex(fields[4]).ok_or_else(|| format!("{id}: kernel field is not hex"))?;
        if kernel_bytes.len() != 115 {
            return Err(format!(
                "{id}: kernel is {} bytes, the frozen wire size is 115",
                kernel_bytes.len()
            ));
        }

        // The canonical consensus codec reads the kernel; nothing here parses
        // it by offset.
        let kernel = TransactionKernel::from_bytes(&kernel_bytes)
            .map_err(|error| format!("{id}: fixture kernel is not canonical: {error}"))?;
        let signature = SchnorrSignature::from_bytes(&kernel.excess_signature)
            .map_err(|error| format!("{id}: fixture signature is not canonical: {error}"))?;

        let signing_key: [u8; 33] = *kernel.excess.as_bytes();
        let r_hat: [u8; 33] = *signature.r_compressed();

        let claim_template_hash = binding(&id, 0x11);
        let transcript_hash = binding(&id, 0x22);

        let mut payload = [0_u8; CLAIM_ADAPTOR_PRE_SIGNATURE_LEN];
        payload[TEMPLATE_RANGE].copy_from_slice(&claim_template_hash);
        payload[ADAPTOR_POINT_RANGE].copy_from_slice(&t_point);
        payload[NONCE_HAT_RANGE].copy_from_slice(&r_hat);
        payload[SCALAR_RANGE].copy_from_slice(&s_hat);
        payload[TRANSCRIPT_RANGE].copy_from_slice(&transcript_hash);

        parsed.push(Vector {
            id,
            payload,
            signing_key,
            claim_template_hash,
            transcript_hash,
            parity: (t_point[0], signing_key[0], r_hat[0]),
        });
    }
    Ok(parsed)
}

/// The first vector, for the single-vector mutation tests.
fn first() -> Result<(Vector, Vector), String> {
    let mut all = vectors()?;
    if all.len() < 2 {
        return Err(format!(
            "expected at least two vectors, found {}",
            all.len()
        ));
    }
    let second = all.remove(1);
    let first = all.remove(0);
    Ok((first, second))
}

fn request<'a>(vector: &'a Vector, payload: &'a [u8]) -> ClaimAdaptorVerificationRequestV1<'a> {
    ClaimAdaptorVerificationRequestV1 {
        pre_signature: payload,
        claim_template_hash: vector.claim_template_hash,
        transcript_hash: vector.transcript_hash,
        aggregate_signing_key: vector.signing_key,
        chain_id: CHAIN_ID,
        kernel_message_digest: MESSAGE,
    }
}

#[test]
fn the_corpus_is_the_frozen_eight() -> TestResult {
    let vectors = vectors()?;
    assert_eq!(
        vectors.len(),
        8,
        "the permanent SCAD0 corpus is frozen at 8"
    );
    let mut ids: Vec<&str> = vectors.iter().map(|vector| vector.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        ["V01", "V02", "V03", "V04", "V05", "V06", "V07", "V08"]
    );
    Ok(())
}

#[test]
fn the_declared_length_matches_the_pinned_codec() {
    // A local constant that drifted from the pinned one would size buffers
    // wrongly while every fixture still passed.
    assert_eq!(
        CLAIM_ADAPTOR_PRE_SIGNATURE_LEN,
        dom_adaptor::AdaptorPreSignatureV1::ENCODED_LEN
    );
}

#[test]
fn every_frozen_vector_verifies_through_the_pinned_verifier() -> TestResult {
    let vectors = vectors()?;
    let mut parities = Vec::new();
    for vector in &vectors {
        let verified = verify_claim_adaptor_pre_signature_v1(&request(vector, &vector.payload))
            .map_err(|error| format!("{}: {error}", vector.id))?;

        assert_eq!(verified.claim_template_hash(), &vector.claim_template_hash);
        assert_eq!(verified.transcript_hash(), &vector.transcript_hash);
        assert_eq!(verified.aggregate_signing_key(), &vector.signing_key);
        assert_eq!(verified.chain_id(), &CHAIN_ID);
        assert_eq!(verified.kernel_message_digest(), &MESSAGE);
        assert_eq!(
            verified.adaptor_point().as_slice(),
            &vector.payload[ADAPTOR_POINT_RANGE]
        );
        assert_eq!(
            verified.aggregate_nonce_hat().as_slice(),
            &vector.payload[NONCE_HAT_RANGE]
        );

        parities.push(vector.parity);
    }

    assert_eq!(parities.len(), 8);

    // Recorded parity coverage, stated as the exact measured set.
    //
    // `distinct.len() > 1` would have been a tautology over a frozen corpus,
    // and the per-prefix `0x02 || 0x03` assertions cannot fail because
    // `PublicKey::from_compressed_bytes` already enforced them during parsing.
    // Pinning the exact set instead makes this a real record: it is the
    // assertion that fails, loudly and with the new value, if the fixture is
    // ever re-imported with different coverage.
    //
    // The measured coverage is four triples, not sixteen. `X` and `R_hat` carry
    // the same parity in every vector, so no vector exercises a signing key and
    // an aggregate nonce of differing parity. `tests/fixtures/PROVENANCE.md`
    // records the same table.
    let distinct: std::collections::BTreeSet<_> = parities.iter().copied().collect();
    let measured: Vec<(u8, u8, u8)> = distinct.into_iter().collect();
    assert_eq!(
        measured,
        vec![
            (0x02, 0x02, 0x02),
            (0x02, 0x03, 0x03),
            (0x03, 0x02, 0x02),
            (0x03, 0x03, 0x03),
        ],
        "the corpus's (T, X, R_hat) parity coverage changed"
    );
    assert!(
        parities.iter().all(|(_, x, r)| x == r),
        "X and R_hat parity are correlated in this corpus; a vector broke that"
    );
    Ok(())
}

#[test]
fn a_cross_session_core_swap_is_refused_by_the_verifier() -> TestResult {
    // The strong form of the swap. `a_cross_session_swap_is_refused_for_every_pair`
    // offers another vector's *whole* payload, so it carries that vector's
    // template hash and is refused at the first binding comparison — the pinned
    // verifier is never reached, and that test would pass against a stubbed
    // verifier.
    //
    // Here only the cryptographic core is taken from the other vector — T, R_hat
    // and s_hat — while the template and transcript hashes stay this session's.
    // Every binding comparison now succeeds, so the refusal can only come from
    // the pinned equation.
    let vectors = vectors()?;
    let mut pairs = 0_usize;
    for (index, vector) in vectors.iter().enumerate() {
        for (other_index, other) in vectors.iter().enumerate() {
            if index == other_index {
                continue;
            }
            let mut payload = vector.payload;
            payload[ADAPTOR_POINT_RANGE].copy_from_slice(&other.payload[ADAPTOR_POINT_RANGE]);
            payload[NONCE_HAT_RANGE].copy_from_slice(&other.payload[NONCE_HAT_RANGE]);
            payload[SCALAR_RANGE].copy_from_slice(&other.payload[SCALAR_RANGE]);
            assert_eq!(
                refusal(verify_claim_adaptor_pre_signature_v1(&request(
                    vector, &payload
                ))),
                Some(ClaimAdaptorVerificationError::VerificationRejected),
                "{} accepted {}'s cryptographic core",
                vector.id,
                other.id
            );
            pairs += 1;
        }
    }
    assert_eq!(pairs, 56, "every ordered pair of the eight must be tried");
    Ok(())
}

#[test]
fn the_session_bindings_are_byte_equality_not_challenge_input() -> TestResult {
    // A property a reader must not have to discover for themselves.
    //
    // The pinned `scriptless_verify_pre_signature` computes the challenge over
    // R_hat, X, the chain identifier and the kernel message. The Claim template
    // hash and the transcript hash are not in it; the pinned `verify` only
    // compares them for equality. So a valid core can be re-bound to any
    // template and transcript a caller chooses, and it verifies.
    //
    // This test exists to state that limit, not to endorse it. Whatever
    // guarantees a template hash is the right one comes from the transcript
    // that produced it, which is outside this module.
    let (vector, _) = first()?;

    let rebound_template = [0x77_u8; 32];
    let rebound_transcript = [0x88_u8; 32];

    let mut payload = vector.payload;
    payload[TEMPLATE_RANGE].copy_from_slice(&rebound_template);
    payload[TRANSCRIPT_RANGE].copy_from_slice(&rebound_transcript);

    let rebound = ClaimAdaptorVerificationRequestV1 {
        pre_signature: &payload,
        claim_template_hash: rebound_template,
        transcript_hash: rebound_transcript,
        aggregate_signing_key: vector.signing_key,
        chain_id: CHAIN_ID,
        kernel_message_digest: MESSAGE,
    };

    let verified = verify_claim_adaptor_pre_signature_v1(&rebound)
        .map_err(|error| format!("re-binding must still verify, and did not: {error}"))?;
    assert_eq!(verified.claim_template_hash(), &rebound_template);
    assert_eq!(verified.transcript_hash(), &rebound_transcript);

    // The chain identifier and the kernel message ARE in the challenge, so the
    // same freedom does not extend to them.
    let mut altered = rebound;
    altered.chain_id = [0xBE; 32];
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&altered)),
        Some(ClaimAdaptorVerificationError::VerificationRejected),
        "the chain identifier is challenge input and must not be re-bindable"
    );
    Ok(())
}

#[test]
fn a_wrong_length_payload_is_refused() -> TestResult {
    let (vector, _) = first()?;
    for length in [0_usize, 1, 32, 161, 163, 324] {
        let mut payload = vec![0_u8; length];
        let copy = length.min(CLAIM_ADAPTOR_PRE_SIGNATURE_LEN);
        payload[..copy].copy_from_slice(&vector.payload[..copy]);
        assert_eq!(
            refusal(verify_claim_adaptor_pre_signature_v1(&request(
                &vector, &payload
            ))),
            Some(ClaimAdaptorVerificationError::MalformedPreSignature),
            "a {length}-byte payload must be refused"
        );
    }
    Ok(())
}

#[test]
fn a_noncanonical_point_is_refused() -> TestResult {
    let (vector, _) = first()?;
    // Both embedded points, and both codec-level failure shapes.
    for offset in [ADAPTOR_POINT_RANGE.start, NONCE_HAT_RANGE.start] {
        // An SEC1 prefix that is not a compressed-point prefix.
        for prefix in [0x00_u8, 0x01, 0x04, 0x05, 0xFF] {
            let mut payload = vector.payload;
            payload[offset] = prefix;
            assert_eq!(
                refusal(verify_claim_adaptor_pre_signature_v1(&request(
                    &vector, &payload
                ))),
                Some(ClaimAdaptorVerificationError::MalformedPreSignature),
                "prefix {prefix:#04x} at {offset} must be refused"
            );
        }

        // An x coordinate outside the field. secp256k1's prime is
        // 2^256 - 2^32 - 977, so an all-ones x is not a field element at all
        // and cannot name a point on any curve over that field.
        //
        // Flipping a single x byte is deliberately NOT used here: roughly half
        // of all field elements are the x of some curve point, so a one-byte
        // flip usually yields a different *valid* point. The codec then accepts
        // it and the verifier refuses it, which is the case covered by
        // `a_parity_flip_is_refused_by_the_verifier` below.
        let mut payload = vector.payload;
        payload[offset + 1..offset + 33].copy_from_slice(&[0xFF_u8; 32]);
        assert_eq!(
            refusal(verify_claim_adaptor_pre_signature_v1(&request(
                &vector, &payload
            ))),
            Some(ClaimAdaptorVerificationError::MalformedPreSignature),
            "an x coordinate outside the field at {offset} must be refused"
        );
    }
    Ok(())
}

#[test]
fn a_parity_flip_is_refused_by_the_verifier() -> TestResult {
    let (vector, _) = first()?;
    // Flipping the SEC1 parity byte keeps the x coordinate, so the result is a
    // canonical point: the negation of the original. The codec must accept it
    // and the verifier must refuse it, which proves the y parity of both points
    // is bound into the equation rather than merely parsed.
    for offset in [ADAPTOR_POINT_RANGE.start, NONCE_HAT_RANGE.start] {
        let mut payload = vector.payload;
        payload[offset] = if payload[offset] == 0x02 { 0x03 } else { 0x02 };
        assert_eq!(
            refusal(verify_claim_adaptor_pre_signature_v1(&request(
                &vector, &payload
            ))),
            Some(ClaimAdaptorVerificationError::VerificationRejected),
            "a negated point at {offset} must be refused by the verifier"
        );
    }
    Ok(())
}

#[test]
fn a_noncanonical_scalar_is_refused() -> TestResult {
    let (vector, _) = first()?;
    // All-ones exceeds the curve order, so it is not a canonical scalar.
    let mut payload = vector.payload;
    payload[SCALAR_RANGE].copy_from_slice(&[0xFF_u8; 32]);
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&request(
            &vector, &payload
        ))),
        Some(ClaimAdaptorVerificationError::MalformedPreSignature)
    );
    Ok(())
}

#[test]
fn a_false_equation_is_refused_as_a_typed_error() -> TestResult {
    let (vector, _) = first()?;
    // A canonical but wrong scalar: the payload parses, so the refusal comes
    // from the verifier rather than the codec. The refusal is a typed variant,
    // never a boolean a caller could store or forward as evidence.
    let mut payload = vector.payload;
    payload[SCALAR_RANGE.end - 1] ^= 0x01;
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&request(
            &vector, &payload
        ))),
        Some(ClaimAdaptorVerificationError::VerificationRejected),
        "a false equation must be a typed refusal, never boolean evidence"
    );
    Ok(())
}

#[test]
fn every_bound_field_mutation_is_refused() -> TestResult {
    let (vector, other) = first()?;

    // Claim template hash: the payload no longer matches the request.
    let mut payload = vector.payload;
    payload[TEMPLATE_RANGE.start] ^= 0x01;
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&request(
            &vector, &payload
        ))),
        Some(ClaimAdaptorVerificationError::ClaimTemplateMismatch)
    );

    // Transcript hash: the payload no longer matches the request.
    let mut payload = vector.payload;
    payload[TRANSCRIPT_RANGE.end - 1] ^= 0x01;
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&request(
            &vector, &payload
        ))),
        Some(ClaimAdaptorVerificationError::TranscriptMismatch)
    );

    // Adaptor point: canonical, but not this vector's T.
    let mut payload = vector.payload;
    payload[ADAPTOR_POINT_RANGE].copy_from_slice(&other.payload[ADAPTOR_POINT_RANGE]);
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&request(
            &vector, &payload
        ))),
        Some(ClaimAdaptorVerificationError::VerificationRejected)
    );

    // Aggregate nonce: canonical, but not this vector's R_hat.
    let mut payload = vector.payload;
    payload[NONCE_HAT_RANGE].copy_from_slice(&other.payload[NONCE_HAT_RANGE]);
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&request(
            &vector, &payload
        ))),
        Some(ClaimAdaptorVerificationError::VerificationRejected)
    );

    // Pre-signature scalar: canonical, but not this vector's s_hat.
    let mut payload = vector.payload;
    payload[SCALAR_RANGE].copy_from_slice(&other.payload[SCALAR_RANGE]);
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&request(
            &vector, &payload
        ))),
        Some(ClaimAdaptorVerificationError::VerificationRejected)
    );

    // Signing key: canonical, but not this vector's X.
    let mut altered = request(&vector, &vector.payload);
    altered.aggregate_signing_key = other.signing_key;
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&altered)),
        Some(ClaimAdaptorVerificationError::VerificationRejected)
    );

    // Chain identifier: bound into the challenge.
    let mut altered = request(&vector, &vector.payload);
    altered.chain_id = [0xBE; 32];
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&altered)),
        Some(ClaimAdaptorVerificationError::VerificationRejected)
    );

    // Kernel message digest: bound into the challenge.
    let mut altered = request(&vector, &vector.payload);
    altered.kernel_message_digest = [0xCD; 32];
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&altered)),
        Some(ClaimAdaptorVerificationError::VerificationRejected)
    );

    Ok(())
}

#[test]
fn a_zero_chain_id_is_refused_before_any_cryptography() -> TestResult {
    let (vector, _) = first()?;
    let mut altered = request(&vector, &vector.payload);
    altered.chain_id = [0_u8; 32];
    assert_eq!(
        refusal(verify_claim_adaptor_pre_signature_v1(&altered)),
        Some(ClaimAdaptorVerificationError::ZeroChainId)
    );
    Ok(())
}

#[test]
fn a_noncanonical_signing_key_is_refused() -> TestResult {
    let (vector, _) = first()?;
    for key in [[0x04_u8; 33], [0x00_u8; 33], [0xFF_u8; 33]] {
        let mut altered = request(&vector, &vector.payload);
        altered.aggregate_signing_key = key;
        assert_eq!(
            refusal(verify_claim_adaptor_pre_signature_v1(&altered)),
            Some(ClaimAdaptorVerificationError::NonCanonicalSigningKey),
            "a signing key of {:#04x} repeated must be refused",
            key[0]
        );
    }
    Ok(())
}

#[test]
fn a_cross_session_swap_is_refused_for_every_pair() -> TestResult {
    let vectors = vectors()?;
    let mut pairs = 0_usize;
    for (index, vector) in vectors.iter().enumerate() {
        for (other_index, other) in vectors.iter().enumerate() {
            if index == other_index {
                continue;
            }
            // Another vector's complete payload offered against this vector's
            // session bindings. The payload carries the other session's template
            // hash, so this is refused at the first binding comparison and the
            // pinned verifier is never reached — the refusal is asserted exactly,
            // rather than as "some error", so the test states which stage
            // rejected it. `a_cross_session_core_swap_is_refused_by_the_verifier`
            // is the form that reaches the equation.
            assert_eq!(
                refusal(verify_claim_adaptor_pre_signature_v1(&request(
                    vector,
                    &other.payload
                ))),
                Some(ClaimAdaptorVerificationError::ClaimTemplateMismatch),
                "{} accepted {}'s payload",
                vector.id,
                other.id
            );
            pairs += 1;
        }
    }
    assert_eq!(pairs, 56, "every ordered pair of the eight must be tried");
    Ok(())
}

#[test]
fn the_verified_capability_is_not_a_funding_authority() {
    // The type carries no one-time semantics and no funding vocabulary. This
    // asserts the naming boundary NAR-DC-P1-007 §4 draws, at the source level,
    // because a rename is exactly how the distinction would be lost.
    let source = include_str!("../src/claim_adaptor.rs");
    for forbidden in [
        "ReadyToFund",
        "FundingAuthorization",
        "BroadcastAuthorization",
    ] {
        let declarations = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(forbidden))
            .count();
        assert_eq!(
            declarations, 0,
            "{forbidden} must not name anything in this module"
        );
    }
}

#[test]
fn the_fixture_still_carries_its_upstream_header() {
    // Deliberately NOT named "is the imported corpus": this asserts that two
    // strings appear in the file, and both are lines of that same file, so a
    // regenerated corpus that copied the four header lines would pass. It is a
    // cheap smoke check that the header was not dropped, nothing more.
    //
    // The real anchor is the SHA-256 over the whole file, which cannot live in
    // the file it covers. `scripts/check-claim-adaptor-provenance.sh` holds it,
    // compares it against `PROVENANCE.md`, and runs in CI.
    assert!(FIXTURE.contains(
        "Origin report SHA-256: 037e21269c9929ab01ff50ea773fe3685de735fc0fe874b40fdcc12c1a2a1b17"
    ));
    assert!(FIXTURE.contains(
        "Extract SHA-256: e99ad8a32edc3db52941e6729c032893d2b864ab995821debf574468b7beaa4b"
    ));
}

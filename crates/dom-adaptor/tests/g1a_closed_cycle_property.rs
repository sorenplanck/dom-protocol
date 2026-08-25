//! G1 exit-gate closed-cycle property evidence.
//!
//! The implementation schedule requires, for the Phase 1 exit gate, a
//! closed-cycle property test proving `extract(adapt(presign)) == t` over at
//! least ten thousand random cases. This file provides exactly that, against
//! the authoritative DOM primitives and with no reimplemented arithmetic.
//!
//! Cases are drawn from a seeded hash chain rather than an ambient RNG so the
//! campaign is reproducible: the seed is a recorded constant, and a failure
//! reports the case index and the exact scalars that produced it. Adding an
//! ambient RNG dependency would make the recorded evidence unreproducible.

use dom_adaptor::{AdaptorPreSignatureV1, AdaptorSecret};
use dom_crypto::{
    blake2b_256_tagged, schnorr_challenge, scriptless_add_public_points,
    scriptless_verify_final_signature, secret_scalar_mul_add_assign, secret_scalar_public_key,
    PartialSig, PublicKey,
};
use zeroize::Zeroizing;

/// Cases required by the Phase 1 exit gate.
const REQUIRED_CASES: usize = 10_000;

/// Recorded seed for the deterministic case stream.
const CASE_SEED: [u8; 32] = [
    0x47, 0x31, 0x41, 0x2d, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x2d, 0x63, 0x79, 0x63, 0x6c, 0x65,
    0x2d, 0x76, 0x31, 0x2d, 0x64, 0x6f, 0x6d, 0x2d, 0x61, 0x64, 0x61, 0x70, 0x74, 0x6f, 0x72, 0x21,
];

const CHAIN_ID: [u8; 32] = [0xAD; 32];
const CLAIM_TEMPLATE_HASH: [u8; 32] = [0x22; 32];
const TRANSCRIPT_HASH: [u8; 32] = [0x33; 32];

/// Deterministic scalar stream bound to the recorded seed.
struct CaseStream {
    state: [u8; 32],
}

impl CaseStream {
    fn new(seed: [u8; 32]) -> Self {
        Self { state: seed }
    }

    /// Draw the next candidate scalar, skipping values the curve rejects.
    ///
    /// Rejection sampling keeps the stream inside the canonical nonzero range
    /// without biasing it the way clamping would.
    fn next_scalar(&mut self, label: &str) -> Zeroizing<[u8; 32]> {
        loop {
            self.state = *blake2b_256_tagged(label, &self.state).as_bytes();
            let candidate = Zeroizing::new(self.state);
            if secret_scalar_public_key(&candidate).is_ok() {
                return candidate;
            }
        }
    }
}

/// Build a valid pre-signature from secrets using only authoritative helpers.
///
/// The adaptor relation the DOM verifier checks is `s_hat*G == R_hat + e*X - T`.
/// With `R_hat = k*G + T` and `s_hat = k + e*x` that identity holds by
/// construction, so a case that fails here is a real defect and not a test that
/// assembled the wrong equation.
fn build_case(
    signing_secret: &Zeroizing<[u8; 32]>,
    nonce_secret: &Zeroizing<[u8; 32]>,
    adaptor_secret_bytes: &Zeroizing<[u8; 32]>,
    message: &[u8],
) -> (AdaptorPreSignatureV1, AdaptorSecret, PublicKey) {
    let signing_key = secret_scalar_public_key(signing_secret).expect("signing key");
    let adaptor_secret = AdaptorSecret::from_be_bytes(**adaptor_secret_bytes).expect("secret");
    let adaptor_point = adaptor_secret.public_point().expect("adaptor point");
    let nonce_point = secret_scalar_public_key(nonce_secret).expect("nonce point");

    let aggregate_nonce_hat = scriptless_add_public_points(&[
        nonce_point,
        adaptor_secret.public_point().expect("adaptor point"),
    ])
    .expect("R_hat = kG + T");

    let challenge = schnorr_challenge(
        &aggregate_nonce_hat.to_compressed_bytes(),
        &signing_key,
        &CHAIN_ID,
        message,
    );

    let mut scalar_hat = nonce_secret.clone();
    secret_scalar_mul_add_assign(&mut scalar_hat, signing_secret, challenge.as_bytes())
        .expect("s_hat = k + e*x");

    let pre_signature = AdaptorPreSignatureV1::new(
        CLAIM_TEMPLATE_HASH,
        adaptor_point,
        aggregate_nonce_hat,
        PartialSig::from_bytes(&*scalar_hat).expect("s_hat is canonical"),
        TRANSCRIPT_HASH,
    );

    (pre_signature, adaptor_secret, signing_key)
}

#[test]
fn closed_cycle_extract_adapt_holds_over_ten_thousand_random_cases() {
    let mut stream = CaseStream::new(CASE_SEED);
    let mut completed = 0_usize;

    for case in 0..REQUIRED_CASES {
        let signing_secret = stream.next_scalar("DOM:g1a-closed-cycle-signing:v1");
        let nonce_secret = stream.next_scalar("DOM:g1a-closed-cycle-nonce:v1");
        let adaptor_secret_bytes = stream.next_scalar("DOM:g1a-closed-cycle-adaptor:v1");
        let message =
            *blake2b_256_tagged("DOM:g1a-closed-cycle-message:v1", &stream.state).as_bytes();

        let (pre_signature, adaptor_secret, signing_key) = build_case(
            &signing_secret,
            &nonce_secret,
            &adaptor_secret_bytes,
            &message,
        );

        assert!(
            pre_signature
                .verify(
                    &CLAIM_TEMPLATE_HASH,
                    &TRANSCRIPT_HASH,
                    &signing_key,
                    &CHAIN_ID,
                    &message,
                )
                .unwrap_or_else(|error| panic!("case {case} pre-signature verify: {error}")),
            "case {case} adaptor equation"
        );

        let adapted = pre_signature
            .adapt(
                &adaptor_secret,
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &signing_key,
                &CHAIN_ID,
                &message,
            )
            .unwrap_or_else(|error| panic!("case {case} adaptation: {error}"));

        // The adapted value must satisfy the ordinary DOM signature relation,
        // not merely the adaptor one.
        assert!(
            scriptless_verify_final_signature(&adapted, &signing_key, &CHAIN_ID, &message)
                .unwrap_or_else(|error| panic!("case {case} final verify: {error}")),
            "case {case} adapted signature is a valid DOM signature"
        );

        let extracted = pre_signature
            .extract(
                &adapted,
                &CLAIM_TEMPLATE_HASH,
                &TRANSCRIPT_HASH,
                &signing_key,
                &CHAIN_ID,
                &message,
            )
            .unwrap_or_else(|error| panic!("case {case} extraction: {error}"));

        // The closed cycle. `AdaptorSecret` is deliberately opaque and exposes
        // no byte accessor, so equality is proven through the public point:
        // on a prime-order group `t_out*G == t*G` implies `t_out == t`, which
        // is exactly the property the exit gate asks for.
        assert_eq!(
            extracted.public_point().expect("extracted point"),
            adaptor_secret.public_point().expect("adaptor point"),
            "case {case} extract(adapt(presign)) == t"
        );

        completed += 1;
    }

    assert_eq!(
        completed, REQUIRED_CASES,
        "the exit gate requires at least {REQUIRED_CASES} executed cases"
    );
}

#[test]
fn closed_cycle_rejects_a_wrong_adaptor_secret_across_the_case_stream() {
    // A cycle that accepts any secret would pass the test above vacuously, so
    // prove the negative on the same construction.
    let mut stream = CaseStream::new(CASE_SEED);

    for case in 0..64 {
        let signing_secret = stream.next_scalar("DOM:g1a-closed-cycle-signing:v1");
        let nonce_secret = stream.next_scalar("DOM:g1a-closed-cycle-nonce:v1");
        let adaptor_secret_bytes = stream.next_scalar("DOM:g1a-closed-cycle-adaptor:v1");
        let message =
            *blake2b_256_tagged("DOM:g1a-closed-cycle-message:v1", &stream.state).as_bytes();

        let (pre_signature, adaptor_secret, signing_key) = build_case(
            &signing_secret,
            &nonce_secret,
            &adaptor_secret_bytes,
            &message,
        );

        let wrong_bytes = stream.next_scalar("DOM:g1a-closed-cycle-wrong:v1");
        let wrong_secret = AdaptorSecret::from_be_bytes(*wrong_bytes).expect("wrong secret");
        assert_ne!(
            wrong_secret.public_point().expect("wrong point"),
            adaptor_secret.public_point().expect("adaptor point"),
            "case {case} the negative case must use a different secret"
        );

        assert!(
            pre_signature
                .adapt(
                    &wrong_secret,
                    &CLAIM_TEMPLATE_HASH,
                    &TRANSCRIPT_HASH,
                    &signing_key,
                    &CHAIN_ID,
                    &message,
                )
                .is_err(),
            "case {case} adaptation with a wrong secret must fail closed"
        );
    }
}

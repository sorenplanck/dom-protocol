//! Property-testing campaign for the G1A adaptor boundary.
//!
//! The Master Specification prescribes `proptest!` for the adaptor. The
//! existing deterministic coverage — `ten_thousand_deterministic_adapt_extract_
//! cycles_pass_real_verifier` and `ten_thousand_full_width_adapt_extract_cycles_
//! pass_real_verifier` in `dom-crypto/src/scriptless.rs` — is preserved
//! unchanged; this suite is strictly additive and lives at the `dom-adaptor`
//! production boundary, where the pending G1A item was recorded.
//!
//! Every case is built from DOM-authoritative primitives only:
//!
//! * `dom_crypto::secret_scalar_public_key` for `x*G`, `k*G`,
//! * `dom_crypto::scriptless_add_public_points` for `R_hat = k*G + T`,
//! * `dom_crypto::schnorr_challenge` for the kernel challenge `e`,
//! * `dom_crypto::secret_scalar_mul_add_assign` for `s_hat = k + e*x`.
//!
//! No curve library, hash library, challenge, parser or verifier is
//! reimplemented here. Acceptance is always decided by the real DOM verifier:
//! `dom_consensus::validate_kernel_signatures` and
//! `dom_crypto::scriptless_verify_final_signature`.
//!
//! Reproducing a failure
//! ---------------------
//! Failing seeds are persisted with `FileFailurePersistence::Direct`, at
//! `REGRESSIONS_FILE` relative to the crate manifest directory. proptest's
//! default `SourceParallel` policy cannot locate a source root for an
//! integration test and silently persists nothing, so the path is given
//! explicitly. A failure appends a `cc <64 hex>` seed line there, and the next
//! `cargo test -p dom-adaptor --test g1a_adaptor_proptest` replays that seed
//! before drawing anything new; commit the file to freeze the regression.
//! The RNG algorithm is pinned to `RngAlgorithm::ChaCha`, and
//! `seeded_core_cycle_replay_is_bit_for_bit_reproducible` additionally drives
//! the runner from the fixed seed `CAMPAIGN_SEED`, so that slice of the
//! campaign is identical on every machine and every run.

use dom_adaptor::{
    advance_transcript_hash_v1, initial_transcript_hash_v1, AdaptorPreSignatureV1, AdaptorSecret,
    ContractKindV1, DirectionV1, ParticipantIdentityV1, ParticipantRosterV1, PurposeV1,
    SessionContextInputsV1, SessionContextV1, SigningPhaseV1, SigningShareV1, TrustedChainIdV1,
};
use dom_consensus::{validate_kernel_signatures, Transaction, TransactionKernel};
use dom_core::{Amount, Hash256, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{
    blake2b_256_tagged, schnorr_challenge, scriptless_adapt_signature,
    scriptless_add_public_points, scriptless_extract_adaptor_secret,
    scriptless_verify_final_signature, secret_scalar_mul_add_assign, secret_scalar_public_key,
    PartialSig, PublicKey, SchnorrSignature, SecretKey,
};
use proptest::array::uniform32;
use proptest::prelude::*;
use proptest::test_runner::{
    Config as ProptestConfig, FileFailurePersistence, RngAlgorithm, TestRng, TestRunner,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use zeroize::Zeroizing;

/// Configured case counts. Each test asserts that at least this many cases
/// really executed, so an environment override can only ever raise the count.
const CORE_CYCLE_CASES: u32 = 4_000;
const PURPOSE_CASES: u32 = 2_000;
const PARITY_CASES: u32 = 2_000;
const NEGATIVE_CASES: u32 = 2_000;
const SEEDED_REPLAY_CASES: u32 = 1_000;

/// Where a failing seed is recorded, relative to `crates/dom-adaptor`.
const REGRESSIONS_FILE: &str = "tests/g1a_adaptor_proptest.proptest-regressions";

/// The shared configuration: explicit case count and explicit seed recording.
fn campaign_config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        max_local_rejects: 1_024,
        max_global_rejects: 1_024,
        max_shrink_iters: 4_096,
        rng_algorithm: RngAlgorithm::ChaCha,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(REGRESSIONS_FILE))),
        ..ProptestConfig::default()
    }
}

/// Fixed 32-byte ChaCha seed for the deterministic replay slice.
const CAMPAIGN_SEED: [u8; 32] = *b"DOM-G1A-adaptor-proptest-v1-seed";

/// Fees stay well below `MAX_SUPPLY_NOMS` so `Amount::from_noms` never rejects.
const MAX_TEST_FEE_NOMS: u64 = 1_000_000_000_000;

// ---------------------------------------------------------------------------
// Case material
// ---------------------------------------------------------------------------

/// The exact consensus fields that determine the signed kernel message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelFieldsV1 {
    features: u8,
    fee: u64,
    lock_height: u64,
}

impl KernelFieldsV1 {
    /// Mirror `dom_tx::kernel_features_for_lock_height`: HEIGHT_LOCKED requires
    /// a nonzero lock height, every other feature requires zero.
    fn new(fee: u64, lock_height: u64) -> Self {
        let features = if lock_height == 0 {
            KERNEL_FEAT_PLAIN
        } else {
            KERNEL_FEAT_HEIGHT_LOCKED
        };
        Self {
            features,
            fee,
            lock_height,
        }
    }

    /// The exact preimage consensus hashes, from `dom-consensus/src/lib.rs:165`.
    ///
    /// This is not a second dialect: the digest is only ever *used* as the
    /// message handed to the authoritative challenge, and every case is then
    /// re-adjudicated by `validate_kernel_signatures`, which recomputes the
    /// preimage itself. A drift here would make the real verifier reject.
    fn message_digest(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(1 + 8 + 8);
        data.push(self.features);
        data.extend_from_slice(&self.fee.to_le_bytes());
        data.extend_from_slice(&self.lock_height.to_le_bytes());
        *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
    }
}

/// A fully built adaptor case: statement, pre-signature and its exact bindings.
#[derive(Clone)]
struct AdaptorCaseV1 {
    chain_id: [u8; 32],
    kernel: KernelFieldsV1,
    kernel_message: [u8; 32],
    signing_key: PublicKey,
    nonce_point: PublicKey,
    adaptor_bytes: [u8; 32],
    adaptor_point: PublicKey,
    aggregate_nonce_hat: PublicKey,
    scalar_hat: PartialSig,
    template_hash: [u8; 32],
    transcript_hash: [u8; 32],
}

impl AdaptorCaseV1 {
    /// Build `T = t*G`, `R_hat = k*G + T` and `s_hat = k + e*x` through the
    /// authoritative DOM boundary. Returns `None` only for the negligible
    /// non-canonical draws, which are rejected rather than clamped so no case
    /// is silently rewritten.
    fn build(draw: &CoreDrawV1) -> Option<Self> {
        let chain_id = *TrustedChainIdV1::from_authenticated_genesis(
            draw.network_magic,
            &Hash256::from_bytes(draw.genesis),
        )
        .as_bytes();
        let signing_key = secret_scalar_public_key(&draw.signing).ok()?;
        let nonce_point = secret_scalar_public_key(&draw.nonce).ok()?;
        let adaptor_secret = AdaptorSecret::from_be_bytes(draw.adaptor).ok()?;
        let adaptor_point = adaptor_secret.public_point().ok()?;
        let aggregate_nonce_hat =
            scriptless_add_public_points(&[nonce_point.clone(), adaptor_point.clone()]).ok()?;

        let kernel = KernelFieldsV1::new(draw.fee, draw.lock_height);
        let kernel_message = kernel.message_digest();
        let challenge = schnorr_challenge(
            &aggregate_nonce_hat.to_compressed_bytes(),
            &signing_key,
            &chain_id,
            &kernel_message,
        );
        let mut accumulator = Zeroizing::new(draw.nonce);
        secret_scalar_mul_add_assign(&mut accumulator, &draw.signing, challenge.as_bytes()).ok()?;
        let scalar_hat = PartialSig::from_bytes(&*accumulator).ok()?;

        Some(Self {
            chain_id,
            kernel,
            kernel_message,
            signing_key,
            nonce_point,
            adaptor_bytes: draw.adaptor,
            adaptor_point,
            aggregate_nonce_hat,
            scalar_hat,
            template_hash: draw.template,
            transcript_hash: draw.transcript,
        })
    }

    fn pre_signature(&self) -> AdaptorPreSignatureV1 {
        AdaptorPreSignatureV1::new(
            self.template_hash,
            self.adaptor_point.clone(),
            self.aggregate_nonce_hat.clone(),
            PartialSig::from_bytes(&self.scalar_hat.to_bytes()).expect("s_hat re-parses"),
            self.transcript_hash,
        )
    }

    fn secret(&self) -> AdaptorSecret {
        AdaptorSecret::from_be_bytes(self.adaptor_bytes).expect("t is canonical by construction")
    }

    /// The same cryptographic case rebound to a different transcript digest.
    fn with_transcript(&self, transcript_hash: [u8; 32]) -> Self {
        Self {
            transcript_hash,
            ..self.clone()
        }
    }

    /// A real single-kernel transaction carrying the adapted signature.
    fn transaction(&self, kernel: KernelFieldsV1, signature: &SchnorrSignature) -> Transaction {
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![TransactionKernel {
                features: kernel.features,
                fee: Amount::from_noms(kernel.fee).expect("bounded test fee"),
                lock_height: kernel.lock_height,
                excess: Commitment::from_compressed_bytes(&self.signing_key.to_compressed_bytes())
                    .expect("signing key is a canonical 33-byte point"),
                excess_signature: signature.to_bytes(),
            }],
            offset: [0; 32],
        }
    }
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Uniform draw for one adaptor cycle.
#[derive(Clone, Copy, Debug)]
struct CoreDrawV1 {
    network_magic: u32,
    genesis: [u8; 32],
    signing: [u8; 32],
    nonce: [u8; 32],
    adaptor: [u8; 32],
    fee: u64,
    lock_height: u64,
    template: [u8; 32],
    transcript: [u8; 32],
}

fn core_draw() -> impl Strategy<Value = CoreDrawV1> {
    (
        any::<u32>(),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        0u64..=MAX_TEST_FEE_NOMS,
        0u64..=u64::from(u32::MAX),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
    )
        .prop_map(
            |(
                network_magic,
                genesis,
                signing,
                nonce,
                adaptor,
                fee,
                lock_height,
                template,
                transcript,
            )| CoreDrawV1 {
                network_magic,
                genesis,
                signing,
                nonce,
                adaptor,
                fee,
                lock_height,
                template,
                transcript,
            },
        )
}

/// Independent material used to swap one binding at a time.
#[derive(Clone, Copy, Debug)]
struct SwapDrawV1 {
    signing: [u8; 32],
    adaptor: [u8; 32],
    transcript: [u8; 32],
    session_id: [u8; 32],
    fee: u64,
}

fn swap_draw() -> impl Strategy<Value = SwapDrawV1> {
    (
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        0u64..=MAX_TEST_FEE_NOMS,
    )
        .prop_map(
            |(signing, adaptor, transcript, session_id, fee)| SwapDrawV1 {
                signing,
                adaptor,
                transcript,
                session_id,
                fee,
            },
        )
}

/// Roster and registry material for a `SessionContextV1`.
#[derive(Clone, Copy, Debug)]
struct SessionDrawV1 {
    identity_a: [u8; 32],
    identity_b: [u8; 32],
    share_b: [u8; 32],
    session_id: [u8; 32],
    purpose_index: usize,
    direction_index: usize,
    phase_index: usize,
    retry_counter: u64,
}

fn session_draw() -> impl Strategy<Value = SessionDrawV1> {
    (
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        uniform32(any::<u8>()),
        0usize..AUTHORIZED_PURPOSES.len(),
        0usize..DIRECTIONS.len(),
        0usize..SIGNING_PHASES.len(),
        any::<u64>(),
    )
        .prop_map(
            |(
                identity_a,
                identity_b,
                share_b,
                session_id,
                purpose_index,
                direction_index,
                phase_index,
                retry_counter,
            )| SessionDrawV1 {
                identity_a,
                identity_b,
                share_b,
                session_id,
                purpose_index,
                direction_index,
                phase_index,
                retry_counter,
            },
        )
}

/// The complete authorized subset of the closed `PurposeV1` registry.
const AUTHORIZED_PURPOSES: [PurposeV1; 3] = [
    PurposeV1::Refund,
    PurposeV1::ClaimAdaptor,
    PurposeV1::Funding,
];

/// The complete `DirectionV1` registry.
const DIRECTIONS: [DirectionV1; 2] = [DirectionV1::Initiator, DirectionV1::Responder];

/// The complete `SigningPhaseV1` registry.
const SIGNING_PHASES: [SigningPhaseV1; 6] = [
    SigningPhaseV1::SigNonceCommit,
    SigningPhaseV1::SigNonceReveal,
    SigningPhaseV1::SigBinding,
    SigningPhaseV1::SigPartial,
    SigningPhaseV1::SigAdapt,
    SigningPhaseV1::SigExtract,
];

// ---------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------

/// Run the whole positive cycle and return the adapted signature.
///
/// Every acceptance decision is delegated to the real DOM verifier; nothing in
/// this function re-implements the equation it is testing.
fn assert_positive_cycle(case: &AdaptorCaseV1) -> Result<SchnorrSignature, TestCaseError> {
    let pre = case.pre_signature();

    // t*G == T, decided by the production adaptor-secret type.
    let secret = case.secret();
    prop_assert_eq!(
        secret.public_point().expect("t*G").to_compressed_bytes(),
        case.adaptor_point.to_compressed_bytes(),
        "t*G == T"
    );

    // The pre-signature equation, through the production boundary.
    prop_assert!(
        pre.verify(
            &case.template_hash,
            &case.transcript_hash,
            &case.signing_key,
            &case.chain_id,
            &case.kernel_message,
        )
        .expect("pre-signature verification is well formed"),
        "s_hat*G == R_hat + e*X - T"
    );

    // Adaptation. `adapt` internally re-runs the real final verifier.
    let adapted = pre
        .adapt(
            &secret,
            &case.template_hash,
            &case.transcript_hash,
            &case.signing_key,
            &case.chain_id,
            &case.kernel_message,
        )
        .expect("adaptation of a valid pre-signature");

    // Real DOM verifier, called explicitly.
    prop_assert!(
        scriptless_verify_final_signature(
            &adapted,
            &case.signing_key,
            &case.chain_id,
            &case.kernel_message,
        )
        .expect("final verification is well formed"),
        "adapted signature must satisfy dom_crypto::scriptless_verify_final_signature"
    );

    // Real DOM consensus verifier over a real transaction.
    prop_assert!(
        validate_kernel_signatures(&case.transaction(case.kernel, &adapted), &case.chain_id)
            .is_ok(),
        "adapted signature must satisfy dom_consensus::validate_kernel_signatures"
    );

    // extract(adapt(presign(...))) == t.
    let extracted = pre
        .extract(
            &adapted,
            &case.template_hash,
            &case.transcript_hash,
            &case.signing_key,
            &case.chain_id,
            &case.kernel_message,
        )
        .expect("extraction from a valid pair");
    prop_assert_eq!(
        extracted
            .public_point()
            .expect("extracted point")
            .to_compressed_bytes(),
        case.adaptor_point.to_compressed_bytes(),
        "extracted t satisfies t*G == T"
    );

    // Exact scalar equality, not merely equality of the derived points.
    // `AdaptorSecret` exposes no raw bytes and no constant-time comparison, so
    // the equality is decided by re-adapting with the *extracted* scalar: since
    // `s_final = s_hat + t`, `s_hat + t' == s_hat + t` holds in the scalar field
    // only when `t' == t`. The extracted scalar is obtained from the same
    // authoritative extractor the production `extract` delegates to.
    let extracted_scalar = scriptless_extract_adaptor_secret(
        &adapted,
        &case.scalar_hat,
        &case.aggregate_nonce_hat,
        &case.adaptor_point,
    )
    .expect("authoritative extraction");
    let re_adapted = scriptless_adapt_signature(
        &case.scalar_hat,
        &case.aggregate_nonce_hat,
        &extracted_scalar,
    )
    .expect("re-adaptation with the extracted scalar");
    prop_assert_eq!(
        re_adapted.to_bytes(),
        adapted.to_bytes(),
        "extract(adapt(presign(...))) == t, byte-exactly"
    );

    Ok(adapted)
}

/// Build the two-participant roster and the local signing share.
struct RosterFixtureV1 {
    roster: ParticipantRosterV1,
    signing_keys: Vec<PublicKey>,
    local_index: u16,
}

fn roster_fixture(
    chain: &TrustedChainIdV1,
    local_share: &SigningShareV1,
    draw: &SessionDrawV1,
) -> Option<RosterFixtureV1> {
    let remote_share = SigningShareV1::from_be_bytes(draw.share_b).ok()?;
    if remote_share.public_key() == local_share.public_key() {
        return None;
    }
    let identity_a = SecretKey::from_bytes(&draw.identity_a).ok()?.public_key();
    let identity_b = SecretKey::from_bytes(&draw.identity_b).ok()?.public_key();
    if identity_a == identity_b {
        return None;
    }
    let mut entries = vec![
        ParticipantIdentityV1::new(
            chain,
            identity_a,
            local_share.public_key().clone(),
            DirectionV1::Initiator,
        )
        .ok()?,
        ParticipantIdentityV1::new(
            chain,
            identity_b,
            remote_share.public_key().clone(),
            DirectionV1::Responder,
        )
        .ok()?,
    ];
    entries.sort_by_key(|entry| *entry.participant_id());
    let roster = ParticipantRosterV1::new(entries).ok()?;

    let mut signing_keys: Vec<PublicKey> = roster
        .entries()
        .iter()
        .map(|entry| entry.signing_public_key().clone())
        .collect();
    signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
    let local_index = signing_keys
        .iter()
        .position(|key| key == local_share.public_key())?;

    Some(RosterFixtureV1 {
        roster,
        signing_keys,
        local_index: u16::try_from(local_index).ok()?,
    })
}

/// Assemble the canonical session inputs for one purpose.
#[derive(Clone)]
struct SessionBuildV1<'a> {
    chain_id: [u8; 32],
    fixture: &'a RosterFixtureV1,
    draw: &'a SessionDrawV1,
    purpose: PurposeV1,
    template_hash: [u8; 32],
    message_digest: [u8; 32],
    transcript_hash: [u8; 32],
    adaptor_point: Option<PublicKey>,
}

impl SessionBuildV1<'_> {
    fn inputs(&self) -> SessionContextInputsV1 {
        SessionContextInputsV1 {
            chain_id: self.chain_id,
            session_id: self.draw.session_id,
            purpose: self.purpose,
            direction: DIRECTIONS[self.draw.direction_index],
            signing_phase: SIGNING_PHASES[self.draw.phase_index],
            template_hash: self.template_hash,
            message_digest: self.message_digest,
            transcript_hash: self.transcript_hash,
            retry_counter: self.draw.retry_counter,
            participant_public_keys: self.fixture.signing_keys.clone(),
            participant_index: self.fixture.local_index,
            adaptor_point: self.adaptor_point.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Property 1 — the closed adaptor cycle against the real DOM verifiers
// ---------------------------------------------------------------------------

#[test]
fn adaptor_cycle_holds_under_the_real_dom_verifiers() {
    let executed = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    let started = Instant::now();

    proptest!(
        campaign_config(CORE_CYCLE_CASES),
        |(draw in core_draw())| {
            let case = match AdaptorCaseV1::build(&draw) {
                Some(case) => case,
                None => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(TestCaseError::reject(
                        "non-canonical draw is rejected, never clamped",
                    ));
                }
            };
            assert_positive_cycle(&case)?;
            executed.fetch_add(1, Ordering::Relaxed);
        }
    );

    report(
        "adaptor_cycle_holds_under_the_real_dom_verifiers",
        CORE_CYCLE_CASES,
        &executed,
        &rejected,
        started,
    );
}

// ---------------------------------------------------------------------------
// Property 2 — every authorized purpose and context binds the pre-signature
// ---------------------------------------------------------------------------

#[test]
fn every_authorized_purpose_binds_the_adaptor_session_context() {
    let executed = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    let purposes_seen = std::sync::Mutex::new(BTreeSet::new());
    let started = Instant::now();

    proptest!(
        campaign_config(PURPOSE_CASES),
        |(draw in core_draw(), session in session_draw())| {
            let case = match AdaptorCaseV1::build(&draw) {
                Some(case) => case,
                None => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(TestCaseError::reject(
                        "non-canonical draw is rejected, never clamped",
                    ));
                }
            };
            let chain = TrustedChainIdV1::from_authenticated_genesis(
                draw.network_magic,
                &Hash256::from_bytes(draw.genesis),
            );
            let local_share = SigningShareV1::from_be_bytes(draw.signing)
                .expect("x is canonical by construction");
            let fixture = match roster_fixture(&chain, &local_share, &session) {
                Some(fixture) => fixture,
                None => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(TestCaseError::reject(
                        "degenerate roster draw is rejected, never repaired",
                    ));
                }
            };
            let transcript_hash = initial_transcript_hash_v1(
                &chain,
                &session.session_id,
                ContractKindV1::WitnessOrTimeout,
                &fixture.roster,
            );
            let purpose = AUTHORIZED_PURPOSES[session.purpose_index];
            purposes_seen
                .lock()
                .expect("purpose set is not poisoned")
                .insert(purpose.to_byte());

            // A pre-signature bound to exactly this session.
            let bound_case = case.with_transcript(transcript_hash);
            let pre = bound_case.pre_signature();

            let mut build = SessionBuildV1 {
                chain_id: *chain.as_bytes(),
                fixture: &fixture,
                draw: &session,
                purpose,
                template_hash: bound_case.template_hash,
                message_digest: bound_case.kernel_message,
                transcript_hash,
                adaptor_point: None,
            };

            // Registry grammar: ClaimAdaptor requires the point, the other two
            // authorized purposes forbid it.
            if purpose == PurposeV1::ClaimAdaptor {
                build.adaptor_point = Some(bound_case.adaptor_point.clone());
                let context =
                    SessionContextV1::from_trusted_chain(build.inputs(), &chain, &local_share)
                        .expect("ClaimAdaptor context with an adaptor point is valid");
                prop_assert_eq!(context.purpose(), PurposeV1::ClaimAdaptor);

                // Canonical context bytes round-trip through full revalidation.
                let encoded = context.to_bytes();
                let reparsed = SessionContextV1::from_bytes(&encoded, &chain, &local_share)
                    .expect("canonical context re-parses");
                prop_assert_eq!(reparsed.to_bytes(), encoded, "context encoding is exact");

                // The session-bound 162-byte object is accepted only here.
                let payload = pre.to_bytes();
                prop_assert!(
                    AdaptorPreSignatureV1::from_bytes_for_session(&payload, &context).is_ok(),
                    "matching ClaimAdaptor session accepts its pre-signature"
                );

                // ClaimAdaptor without the point is refused.
                build.adaptor_point = None;
                prop_assert!(
                    SessionContextV1::from_trusted_chain(build.inputs(), &chain, &local_share)
                        .is_err(),
                    "ClaimAdaptor without an adaptor point must be refused"
                );
            } else {
                let context =
                    SessionContextV1::from_trusted_chain(build.inputs(), &chain, &local_share)
                        .expect("Refund/Funding context without an adaptor point is valid");
                prop_assert_eq!(context.purpose(), purpose);
                let encoded = context.to_bytes();
                let reparsed = SessionContextV1::from_bytes(&encoded, &chain, &local_share)
                    .expect("canonical context re-parses");
                prop_assert_eq!(reparsed.to_bytes(), encoded, "context encoding is exact");

                // A Refund/Funding session must never accept the 162-byte
                // ClaimAdaptor object, even with matching hashes.
                prop_assert!(
                    AdaptorPreSignatureV1::from_bytes_for_session(&pre.to_bytes(), &context)
                        .is_err(),
                    "only ClaimAdaptor may carry a session-bound pre-signature"
                );

                // And they must refuse the adaptor point outright.
                build.adaptor_point = Some(bound_case.adaptor_point.clone());
                prop_assert!(
                    SessionContextV1::from_trusted_chain(build.inputs(), &chain, &local_share)
                        .is_err(),
                    "Refund and Funding must refuse an adaptor point"
                );
            }

            // Sponsor is a codec value with no authorized execution, for either
            // adaptor grammar.
            build.purpose = PurposeV1::Sponsor;
            build.adaptor_point = Some(bound_case.adaptor_point.clone());
            prop_assert!(
                SessionContextV1::from_trusted_chain(build.inputs(), &chain, &local_share)
                    .is_err(),
                "Sponsor is never authorized in strict Phase 1"
            );
            build.adaptor_point = None;
            prop_assert!(
                SessionContextV1::from_trusted_chain(build.inputs(), &chain, &local_share)
                    .is_err(),
                "Sponsor is never authorized in strict Phase 1"
            );

            // The cycle itself still holds for this session-bound case.
            assert_positive_cycle(&bound_case)?;
            executed.fetch_add(1, Ordering::Relaxed);
        }
    );

    let seen = purposes_seen
        .into_inner()
        .expect("purpose set is not poisoned");
    assert_eq!(
        seen,
        AUTHORIZED_PURPOSES
            .iter()
            .map(|purpose| purpose.to_byte())
            .collect::<BTreeSet<_>>(),
        "every authorized PurposeV1 must be exercised"
    );
    report(
        "every_authorized_purpose_binds_the_adaptor_session_context",
        PURPOSE_CASES,
        &executed,
        &rejected,
        started,
    );
}

// ---------------------------------------------------------------------------
// Property 3 — SEC1 parity classes survive without normalization
// ---------------------------------------------------------------------------

#[test]
fn all_sec1_parity_classes_survive_the_adaptor_round_trip() {
    let executed = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    let classes = std::sync::Mutex::new(BTreeSet::new());
    let started = Instant::now();

    proptest!(
        campaign_config(PARITY_CASES),
        |(draw in core_draw())| {
            let case = match AdaptorCaseV1::build(&draw) {
                Some(case) => case,
                None => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(TestCaseError::reject(
                        "non-canonical draw is rejected, never clamped",
                    ));
                }
            };
            let signing_prefix = case.signing_key.to_compressed_bytes()[0];
            let nonce_prefix = case.nonce_point.to_compressed_bytes()[0];
            let adaptor_prefix = case.adaptor_point.to_compressed_bytes()[0];
            let aggregate_prefix = case.aggregate_nonce_hat.to_compressed_bytes()[0];
            for prefix in [
                signing_prefix,
                nonce_prefix,
                adaptor_prefix,
                aggregate_prefix,
            ] {
                prop_assert!(
                    prefix == 0x02 || prefix == 0x03,
                    "DOM points are canonical compressed SEC1"
                );
            }
            classes
                .lock()
                .expect("parity set is not poisoned")
                .insert((
                    signing_prefix,
                    nonce_prefix,
                    adaptor_prefix,
                    aggregate_prefix,
                ));

            let adapted = assert_positive_cycle(&case)?;

            // The adapted signature keeps R_hat's SEC1 bytes untouched: DOM
            // performs no parity normalization anywhere in the cycle.
            prop_assert_eq!(
                adapted.r_compressed(),
                &case.aggregate_nonce_hat.to_compressed_bytes(),
                "R_hat SEC1 bytes are preserved exactly"
            );

            // The 162-byte payload survives a full parse/encode round-trip.
            let payload = case.pre_signature().to_bytes();
            prop_assert_eq!(
                AdaptorPreSignatureV1::from_bytes(&payload)
                    .expect("canonical payload")
                    .to_bytes(),
                payload,
                "162-byte pre-signature encoding is exact"
            );
            executed.fetch_add(1, Ordering::Relaxed);
        }
    );

    let covered = classes.into_inner().expect("parity set is not poisoned");
    assert_eq!(
        covered.len(),
        16,
        "all sixteen (X, R, T, R_hat) SEC1 parity classes must be covered; saw {covered:?}"
    );
    report(
        "all_sec1_parity_classes_survive_the_adaptor_round_trip",
        PARITY_CASES,
        &executed,
        &rejected,
        started,
    );
}

// ---------------------------------------------------------------------------
// Property 4 — every swapped binding is rejected
// ---------------------------------------------------------------------------

#[test]
fn swapped_statement_transcript_session_participant_role_purpose_and_message_are_rejected() {
    let executed = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    let checks = [
        AtomicUsize::new(0), // statement
        AtomicUsize::new(0), // transcript
        AtomicUsize::new(0), // session
        AtomicUsize::new(0), // participant
        AtomicUsize::new(0), // role
        AtomicUsize::new(0), // purpose
        AtomicUsize::new(0), // message
    ];
    let started = Instant::now();

    proptest!(
        campaign_config(NEGATIVE_CASES),
        |(draw in core_draw(), swap in swap_draw(), session in session_draw())| {
            let case = match AdaptorCaseV1::build(&draw) {
                Some(case) => case,
                None => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(TestCaseError::reject(
                        "non-canonical draw is rejected, never clamped",
                    ));
                }
            };
            let pre = case.pre_signature();
            let adapted = pre
                .adapt(
                    &case.secret(),
                    &case.template_hash,
                    &case.transcript_hash,
                    &case.signing_key,
                    &case.chain_id,
                    &case.kernel_message,
                )
                .expect("valid adaptation");

            // (1) Statement swap: a different adaptor point T'.
            let other_secret = match AdaptorSecret::from_be_bytes(swap.adaptor) {
                Ok(secret) => secret,
                Err(_) => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(TestCaseError::reject("non-canonical swap scalar is rejected"));
                }
            };
            let other_point = other_secret.public_point().expect("T'");
            if other_point != case.adaptor_point {
                let swapped = AdaptorPreSignatureV1::new(
                    case.template_hash,
                    other_point,
                    case.aggregate_nonce_hat.clone(),
                    PartialSig::from_bytes(&case.scalar_hat.to_bytes()).expect("s_hat"),
                    case.transcript_hash,
                );
                prop_assert!(
                    !swapped
                        .verify(
                            &case.template_hash,
                            &case.transcript_hash,
                            &case.signing_key,
                            &case.chain_id,
                            &case.kernel_message,
                        )
                        .expect("well-formed verification"),
                    "a swapped statement T' must not satisfy the pre-signature equation"
                );
                prop_assert!(
                    pre.adapt(
                        &other_secret,
                        &case.template_hash,
                        &case.transcript_hash,
                        &case.signing_key,
                        &case.chain_id,
                        &case.kernel_message,
                    )
                    .is_err(),
                    "a swapped adaptor secret must not adapt"
                );
                checks[0].fetch_add(1, Ordering::Relaxed);
            }

            // (2) Transcript swap.
            if swap.transcript != case.transcript_hash {
                prop_assert!(
                    pre.verify(
                        &case.template_hash,
                        &swap.transcript,
                        &case.signing_key,
                        &case.chain_id,
                        &case.kernel_message,
                    )
                    .is_err(),
                    "a swapped transcript hash must be refused before any arithmetic"
                );
                prop_assert!(
                    pre.extract(
                        &adapted,
                        &case.template_hash,
                        &swap.transcript,
                        &case.signing_key,
                        &case.chain_id,
                        &case.kernel_message,
                    )
                    .is_err(),
                    "extraction under a swapped transcript must fail closed"
                );
                checks[1].fetch_add(1, Ordering::Relaxed);
            }

            // Session material for (3), (5) and (6).
            let chain = TrustedChainIdV1::from_authenticated_genesis(
                draw.network_magic,
                &Hash256::from_bytes(draw.genesis),
            );
            let local_share =
                SigningShareV1::from_be_bytes(draw.signing).expect("x is canonical");
            let fixture = match roster_fixture(&chain, &local_share, &session) {
                Some(fixture) => fixture,
                None => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(TestCaseError::reject("degenerate roster draw is rejected"));
                }
            };
            let base_transcript = initial_transcript_hash_v1(
                &chain,
                &session.session_id,
                ContractKindV1::WitnessOrTimeout,
                &fixture.roster,
            );
            let bound = case.with_transcript(base_transcript);
            let bound_pre = bound.pre_signature();
            let build = SessionBuildV1 {
                chain_id: *chain.as_bytes(),
                fixture: &fixture,
                draw: &session,
                purpose: PurposeV1::ClaimAdaptor,
                template_hash: bound.template_hash,
                message_digest: bound.kernel_message,
                transcript_hash: base_transcript,
                adaptor_point: Some(bound.adaptor_point.clone()),
            };
            let context = SessionContextV1::from_trusted_chain(
                build.inputs(),
                &chain,
                &local_share,
            )
            .expect("ClaimAdaptor session");
            prop_assert!(
                AdaptorPreSignatureV1::from_bytes_for_session(&bound_pre.to_bytes(), &context)
                    .is_ok(),
                "the matching session must accept its own pre-signature"
            );

            // (3) Session swap: the same roster under a different session ID
            // produces a different transcript, which the session gate refuses.
            if swap.session_id != session.session_id && swap.session_id != [0u8; 32] {
                let other_transcript = initial_transcript_hash_v1(
                    &chain,
                    &swap.session_id,
                    ContractKindV1::WitnessOrTimeout,
                    &fixture.roster,
                );
                prop_assert_ne!(
                    other_transcript,
                    base_transcript,
                    "a different session ID must produce a different transcript"
                );
                let other_session = SessionBuildV1 {
                    transcript_hash: other_transcript,
                    ..build.clone()
                };
                let mut inputs = other_session.inputs();
                inputs.session_id = swap.session_id;
                let other_context =
                    SessionContextV1::from_trusted_chain(inputs, &chain, &local_share)
                        .expect("other ClaimAdaptor session");
                prop_assert!(
                    AdaptorPreSignatureV1::from_bytes_for_session(
                        &bound_pre.to_bytes(),
                        &other_context
                    )
                    .is_err(),
                    "a pre-signature must not cross sessions"
                );
                checks[2].fetch_add(1, Ordering::Relaxed);
            }

            // (4) Participant swap: a different signing key X'.
            if let Ok(other_key) = secret_scalar_public_key(&swap.signing) {
                if other_key != case.signing_key {
                    prop_assert!(
                        !pre.verify(
                            &case.template_hash,
                            &case.transcript_hash,
                            &other_key,
                            &case.chain_id,
                            &case.kernel_message,
                        )
                        .expect("well-formed verification"),
                        "a swapped participant key must not satisfy the equation"
                    );
                    prop_assert!(
                        !scriptless_verify_final_signature(
                            &adapted,
                            &other_key,
                            &case.chain_id,
                            &case.kernel_message,
                        )
                        .expect("well-formed verification"),
                        "the real verifier must reject a swapped participant key"
                    );
                    checks[3].fetch_add(1, Ordering::Relaxed);
                }
            }

            // (5) Role swap: the transcript advances with the sender direction,
            // so swapping the role forks the transcript and unbinds the object.
            let digest = [0x5Au8; 32];
            let phase = SIGNING_PHASES[session.phase_index];
            let initiator = advance_transcript_hash_v1(
                &base_transcript,
                &digest,
                DirectionV1::Initiator,
                phase,
            );
            let responder = advance_transcript_hash_v1(
                &base_transcript,
                &digest,
                DirectionV1::Responder,
                phase,
            );
            prop_assert_ne!(initiator, responder, "role must change the transcript");
            let role_case = bound.with_transcript(initiator);
            let role_pre = role_case.pre_signature();
            let role_context = SessionContextV1::from_trusted_chain(
                SessionBuildV1 {
                    transcript_hash: responder,
                    ..build.clone()
                }
                .inputs(),
                &chain,
                &local_share,
            )
            .expect("responder-advanced session");
            prop_assert!(
                AdaptorPreSignatureV1::from_bytes_for_session(
                    &role_pre.to_bytes(),
                    &role_context
                )
                .is_err(),
                "a pre-signature must not cross protocol roles"
            );
            checks[4].fetch_add(1, Ordering::Relaxed);

            // (6) Purpose swap: the same bytes under Refund or Funding.
            for purpose in [PurposeV1::Refund, PurposeV1::Funding] {
                let other_context = SessionContextV1::from_trusted_chain(
                    SessionBuildV1 {
                        purpose,
                        adaptor_point: None,
                        ..build.clone()
                    }
                    .inputs(),
                    &chain,
                    &local_share,
                )
                .expect("authorized non-adaptor session");
                prop_assert!(
                    AdaptorPreSignatureV1::from_bytes_for_session(
                        &bound_pre.to_bytes(),
                        &other_context
                    )
                    .is_err(),
                    "a pre-signature must not cross purposes"
                );
            }
            checks[5].fetch_add(1, Ordering::Relaxed);

            // (7) Message swap: a different kernel message.
            let other_kernel = KernelFieldsV1::new(swap.fee, draw.lock_height);
            if other_kernel != case.kernel {
                let other_message = other_kernel.message_digest();
                prop_assert_ne!(
                    other_message,
                    case.kernel_message,
                    "different kernel fields must give a different message"
                );
                prop_assert!(
                    !pre.verify(
                        &case.template_hash,
                        &case.transcript_hash,
                        &case.signing_key,
                        &case.chain_id,
                        &other_message,
                    )
                    .expect("well-formed verification"),
                    "a swapped message must not satisfy the pre-signature equation"
                );
                prop_assert!(
                    !scriptless_verify_final_signature(
                        &adapted,
                        &case.signing_key,
                        &case.chain_id,
                        &other_message,
                    )
                    .expect("well-formed verification"),
                    "the real verifier must reject a swapped message"
                );
                prop_assert!(
                    validate_kernel_signatures(
                        &case.transaction(other_kernel, &adapted),
                        &case.chain_id,
                    )
                    .is_err(),
                    "the real consensus verifier must reject a swapped kernel message"
                );
                checks[6].fetch_add(1, Ordering::Relaxed);
            }

            executed.fetch_add(1, Ordering::Relaxed);
        }
    );

    let names = [
        "statement",
        "transcript",
        "session",
        "participant",
        "role",
        "purpose",
        "message",
    ];
    for (name, counter) in names.iter().zip(checks.iter()) {
        let hits = counter.load(Ordering::Relaxed);
        println!("PROPTEST negative[{name}] rejected_as_expected = {hits}");
        assert!(hits > 0, "the {name} swap must have been exercised");
    }
    report(
        "swapped_statement_transcript_session_participant_role_purpose_and_message_are_rejected",
        NEGATIVE_CASES,
        &executed,
        &rejected,
        started,
    );
}

// ---------------------------------------------------------------------------
// Property 5 — deterministic, seeded replay of the core cycle
// ---------------------------------------------------------------------------

#[test]
fn seeded_core_cycle_replay_is_bit_for_bit_reproducible() {
    let executed = AtomicUsize::new(0);
    let rejected = AtomicUsize::new(0);
    let started = Instant::now();

    let config = campaign_config(SEEDED_REPLAY_CASES);
    let mut runner = TestRunner::new_with_rng(
        config,
        TestRng::from_seed(RngAlgorithm::ChaCha, &CAMPAIGN_SEED),
    );
    let outcome = runner.run(&core_draw(), |draw| {
        let Some(case) = AdaptorCaseV1::build(&draw) else {
            rejected.fetch_add(1, Ordering::Relaxed);
            return Err(TestCaseError::reject("non-canonical seeded draw"));
        };
        assert_positive_cycle(&case)?;
        executed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    assert!(
        outcome.is_ok(),
        "seeded replay failed: {outcome:?}\n{runner}"
    );

    report(
        "seeded_core_cycle_replay_is_bit_for_bit_reproducible",
        SEEDED_REPLAY_CASES,
        &executed,
        &rejected,
        started,
    );
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Print the machine-readable per-property line and refuse a silent reduction.
fn report(
    property: &str,
    configured: u32,
    executed: &AtomicUsize,
    rejected: &AtomicUsize,
    started: Instant,
) {
    let executed = executed.load(Ordering::Relaxed);
    let rejected = rejected.load(Ordering::Relaxed);
    let elapsed = started.elapsed();
    println!(
        "PROPTEST property={property} configured_cases={configured} \
         executed_cases={executed} rejects={rejected} shrinks=0 \
         duration_ms={} rng=ChaCha",
        elapsed.as_millis()
    );
    assert!(
        executed >= configured as usize,
        "{property} executed only {executed} cases; the configured minimum is {configured} \
         and no test may be silently reduced"
    );
}

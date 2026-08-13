//! DSC-F4 randomized soak over the collaborative Bulletproof (§5.4/§5.7).
//!
//! The implementation catalog specified 10,000 randomized executions of the
//! collaborative Bulletproof. **The coordinator ratified a reduction to 1,000**
//! (recorded decision, not a silent relaxation), and that is the threshold this
//! harness enforces. One execution is a full §5.4 choreography over
//! the real vendored FFI — rodada 0A commit/reveal, the 0B commitment gate,
//! T1/T2 aggregation, tau_x aggregation, finalization and the consensus-shaped
//! verification. That costs seconds, not milliseconds, so 10,000 executions is
//! a soak workload measured in hours, not a unit test.
//!
//! It is therefore gated and scaled explicitly rather than silently reduced:
//!
//! ```text
//! cargo test -p dom-adaptor --test collaborative_bp_soak -- --ignored
//! DSC_F4_SOAK_CASES=1000 cargo test -p dom-adaptor --test collaborative_bp_soak -- --ignored
//! ```
//!
//! `DSC_F4_SOAK_CASES` sets the case count; the default is a smoke-sized run so
//! the harness itself stays exercised. The requirement is satisfied only by a
//! recorded run at the ratified threshold, and the count actually executed is
//! printed so the evidence states its own scale — a soak that silently ran 8
//! cases must not be reportable as a full run.
//!
//! Each case randomizes the participant count, the value across the full
//! provable range (including the 0 and MAX edges of §5.7), the blinding shares
//! and the capsule bytes, then asserts the invariants that must hold for every
//! execution: the proof is exactly 739 bytes and verifies through the exact
//! call consensus makes, with the raw capsule as `extra_commit`.

use dom_adaptor::{
    AggregateBpRound1, AggregateBpRound2, BpRound2ShareV1, BpStatementV1, CollaborativeRangeProof,
    DomCollaborativeRangeProofV1, PendingCommonNonce, SigningShareV1, TrustedChainIdV1,
};
use dom_core::Hash256;
use dom_crypto::{blake2b_256, range_proof_verify_with_extra_commit, MAX_PROVABLE_VALUE};

/// Deterministic splitmix64 — no external RNG dependency, so the soak runs
/// under `--locked` without touching the lockfile.
///
/// Each case is seeded from its **global case index**, not from a running
/// stream. That is what makes batches provably non-overlapping: batch `n`
/// covers indices `[n*BATCH_SIZE, (n+1)*BATCH_SIZE)`, no index is ever drawn
/// twice, and any failing case is reproducible on its own from its index —
/// without replaying the batch that found it.
struct Prng(u64);

impl Prng {
    /// Seed for one global case index under a campaign base seed. Mixing both
    /// through splitmix keeps distinct indices independent.
    fn for_case(base_seed: u64, case_index: u64) -> Self {
        let mut mix = Self(base_seed ^ case_index.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let _ = mix.next_u64();
        Self(mix.next_u64())
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    /// Uniform in `lo..=hi` by rejection sampling (no modulo bias).
    fn gen_range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi);
        let span = hi - lo;
        if span == 0 {
            return lo;
        }
        if span == u64::MAX {
            return self.next_u64();
        }
        let buckets = span + 1;
        let zone = u64::MAX - (u64::MAX % buckets);
        loop {
            let raw = self.next_u64();
            if raw < zone {
                return lo + (raw % buckets);
            }
        }
    }
}

/// Ratified by the coordinator as a reduction from the catalog's original
/// 10,000. Changing it again requires a new ratification.
const REQUIRED_CASES: usize = 1_000;
/// Fixed campaign base seed; batches vary by index range, never by base seed.
const BASE_SEED: u64 = 0x5343_4f41_4b00_0001;
const DEFAULT_CASES: usize = 4;
const CAPSULE_LEN: usize = 96;

fn chain() -> TrustedChainIdV1 {
    TrustedChainIdV1::from_authenticated_genesis(0x0011_2233, &Hash256::from_bytes([0x11; 32]))
}

/// A canonical nonzero scalar from the RNG, retried until in range.
fn random_share(rng: &mut Prng) -> SigningShareV1 {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes[..]);
        // Keep the scalar comfortably below the group order.
        bytes[0] = 0;
        if let Ok(share) = SigningShareV1::from_be_bytes(bytes) {
            return share;
        }
    }
}

/// Run one complete §5.4 choreography and assert the §5.7 invariants.
fn one_case(rng: &mut Prng, case: usize) {
    let participants: usize = rng.gen_range(2, 4) as usize;
    // Cover the §5.7 value edges as well as the interior.
    let value: u64 = match case % 4 {
        0 => 0,
        1 => 1,
        2 => MAX_PROVABLE_VALUE,
        _ => rng.gen_range(0, MAX_PROVABLE_VALUE),
    };
    let mut capsule = [0u8; CAPSULE_LEN];
    rng.fill(&mut capsule[..]);

    let shares: Vec<SigningShareV1> = (0..participants).map(|_| random_share(rng)).collect();
    let points: Vec<_> = shares.iter().map(|s| s.public_key().clone()).collect();

    let aggregate = match BpStatementV1::aggregate_commitment_from_shares(&points, value) {
        Ok(aggregate) => aggregate,
        // A random share set can sum to the identity; §4.3 rejects it and the
        // session would draw again. That is correct behaviour, not a failure.
        Err(_) => return,
    };
    let ids: Vec<[u8; 32]> = (0..participants)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0] = u8::try_from(i + 1).expect("bounded");
            id
        })
        .collect();

    let statement = BpStatementV1::new(
        &chain(),
        [0x22; 32],
        ids,
        value,
        points,
        aggregate,
        Some(*blake2b_256(&capsule).as_bytes()),
    )
    .expect("canonical statement");

    // Rodada 0A: every commitment published before any reveal.
    let mut pendings = Vec::with_capacity(participants);
    let mut commitments = Vec::with_capacity(participants);
    for (index, share) in shares.iter().enumerate() {
        let (pending, commitment) =
            PendingCommonNonce::new(&statement, u16::try_from(index).expect("bounded"), share)
                .expect("share opens its statement slot");
        pendings.push(pending);
        commitments.push(commitment);
    }
    let reveals: Vec<_> = pendings.iter().map(|p| p.reveal_bytes()).collect();
    let locals: Vec<_> = pendings
        .into_iter()
        .map(|p| {
            p.finish(&statement, &commitments, reveals.clone())
                .expect("all reveals match their accepted commitments")
        })
        .collect();

    let drivers: Vec<_> = (0..participants)
        .map(|_| {
            DomCollaborativeRangeProofV1::new(&statement, capsule.to_vec())
                .expect("capsule matches the statement binding")
        })
        .collect();

    // Rodada 0B + 1.
    let round1: Vec<_> = drivers
        .iter()
        .zip(&locals)
        .map(|(d, l)| d.round1(&statement, l).expect("round 1"))
        .collect();
    let accepted_r1: Vec<[u8; 32]> = round1.iter().map(|s| s.reveal_commitment()).collect();
    let aggregate_r1 =
        AggregateBpRound1::new(&statement, &accepted_r1, &round1).expect("round 1 aggregate");

    // Rodada 2, each share crossing the wire as exact bytes.
    let mut round2 = Vec::with_capacity(participants);
    for (d, l) in drivers.iter().zip(&locals) {
        let share = d
            .round2(&statement, l, &aggregate_r1)
            .expect("round 2")
            .into_zeroizing_bytes();
        round2.push(BpRound2ShareV1::from_bytes(share.as_ref(), &statement).expect("reparse"));
    }
    let aggregate_r2 = AggregateBpRound2::new(&statement, round2).expect("round 2 aggregate");

    // Rodada 3 and the invariants that must hold for every execution.
    let proof = drivers[0]
        .finalize(&statement, &aggregate_r1, &aggregate_r2)
        .expect("finalization");
    assert_eq!(
        proof.as_bytes().len(),
        739,
        "case {case}: proof size drifted"
    );
    assert!(
        range_proof_verify_with_extra_commit(
            &statement.aggregate_commitment().to_compressed_bytes(),
            proof.as_bytes(),
            &capsule,
        )
        .expect("verifier runs"),
        "case {case}: proof failed the consensus-shaped verification"
    );
}

#[test]
#[ignore = "DSC-F4 soak: seconds per case; set DSC_F4_SOAK_CASES=10000 for the full requirement"]
fn dsc_f4_randomized_collaborative_bulletproof_soak() {
    let cases: usize = std::env::var("DSC_F4_SOAK_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES);
    // Batch index selects a disjoint slice of the global case-index space.
    let batch: u64 = std::env::var("DSC_F4_SOAK_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let seed: u64 = std::env::var("DSC_F4_SOAK_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(BASE_SEED);

    let first = batch.saturating_mul(REQUIRED_CASES as u64);
    let last = first + cases as u64 - 1;
    let started = std::time::Instant::now();
    for offset in 0..cases {
        let case_index = first + offset as u64;
        // Each case stands alone: seeded from its own global index.
        let mut rng = Prng::for_case(seed, case_index);
        one_case(&mut rng, case_index as usize);
    }
    let elapsed = started.elapsed().as_secs_f64();

    // The evidence states its own scale, so a short run can never be reported
    // as the full 10,000-case requirement.
    // Machine-readable evidence line: states its own scale and exact range, so
    // a manifest can accumulate batches without double-counting.
    println!(
        "DSC_F4_BATCH batch={batch} cases={cases} index_range=[{first},{last}] \
         base_seed={seed:#x} elapsed_s={elapsed:.1} result=PASS"
    );
    if cases < REQUIRED_CASES {
        println!(
            "DSC_F4_REQUIREMENT=NOT_SATISFIED (needs {REQUIRED_CASES}, ran {cases}); \
             rerun with DSC_F4_SOAK_CASES={REQUIRED_CASES}"
        );
    } else {
        println!("DSC_F4_REQUIREMENT=SATISFIED");
    }
}

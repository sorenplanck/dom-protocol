//! Release-only laboratory timing evidence. It emits no witness material.

use dom_bp_migration_lab::split_proof_candidate::{
    prove_split_output, recover_split_output, verify_split_output, CanonicalMetadata,
    SINGLE_PROOF_LEN, SPLIT_PROOF_ENVELOPE_LEN,
};
use dom_crypto::{bp2_prove, bp2_verify, BlindingFactor};
use serde::Serialize;
use std::time::{Duration, Instant};

const ITERATIONS: usize = 20;

#[derive(Serialize)]
struct Timing {
    median_us: u128,
    p95_us: u128,
}

#[derive(Serialize)]
struct Evidence {
    schema_version: u32,
    iterations: usize,
    single_proof_len: usize,
    split_envelope_len: usize,
    current_aggregate_proof_len: usize,
    current_generate: Timing,
    current_verify: Timing,
    split_generate: Timing,
    split_verify: Timing,
    split_recover: Timing,
}

fn summarize(samples: &mut [Duration]) -> Timing {
    samples.sort_unstable();
    Timing {
        median_us: samples[samples.len() / 2].as_micros(),
        p95_us: samples[(samples.len() * 95).div_ceil(100) - 1].as_micros(),
    }
}

fn main() {
    let blind = BlindingFactor::from_bytes([0x31; 32]).expect("fixed valid test blind");
    let metadata = CanonicalMetadata::new(7, 1, 99).expect("fixed canonical metadata");
    let nonce = [0x42; 32];
    let mut current_generate = Vec::with_capacity(ITERATIONS);
    let mut current_verify = Vec::with_capacity(ITERATIONS);
    let mut split_generate = Vec::with_capacity(ITERATIONS);
    let mut split_verify = Vec::with_capacity(ITERATIONS);
    let mut split_recover = Vec::with_capacity(ITERATIONS);

    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let (current_proof, current_commitment) = bp2_prove(42, &blind).expect("current prove");
        current_generate.push(started.elapsed());
        let started = Instant::now();
        assert!(bp2_verify(&current_commitment, &current_proof).expect("current verify"));
        current_verify.push(started.elapsed());

        let started = Instant::now();
        let (commitment, envelope) =
            prove_split_output(42, &blind, &nonce, metadata.clone()).expect("split prove");
        split_generate.push(started.elapsed());
        let started = Instant::now();
        assert!(verify_split_output(&commitment, &envelope).expect("split verify"));
        split_verify.push(started.elapsed());
        let started = Instant::now();
        assert!(recover_split_output(&commitment, &envelope, &nonce)
            .expect("split recover")
            .is_some());
        split_recover.push(started.elapsed());
    }

    let evidence = Evidence {
        schema_version: 1,
        iterations: ITERATIONS,
        single_proof_len: SINGLE_PROOF_LEN,
        split_envelope_len: SPLIT_PROOF_ENVELOPE_LEN,
        current_aggregate_proof_len: 739,
        current_generate: summarize(&mut current_generate),
        current_verify: summarize(&mut current_verify),
        split_generate: summarize(&mut split_generate),
        split_verify: summarize(&mut split_verify),
        split_recover: summarize(&mut split_recover),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&evidence).expect("serialize evidence")
    );
}

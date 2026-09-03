//! Manual single-thread acceptance probe for the Wallet's old and new paths.
//!
//! Run with `cargo run --release -p dom-wallet-embedded-core --example
//! randomx_hashrate -- 15`. Dataset initialization is intentionally excluded
//! from the fast-mode measurement.

use dom_pow::{randomx_pool, MinerVm};
use std::time::{Duration, Instant};

fn main() {
    let seconds = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15)
        .max(1);
    let duration = Duration::from_secs(seconds);
    let seed = [0x42; 32];
    let mut preimage = [0u8; 80];

    let light_hps = measure(duration, &mut preimage, |input| {
        randomx_pool::randomx_hash(&seed, input).expect("light-mode RandomX hash")
    });

    eprintln!("initializing shared full RandomX dataset (excluded from timing)...");
    let vm = MinerVm::new(&seed).expect("fast-mode RandomX VM");
    let fast_hps = measure(duration, &mut preimage, |input| {
        vm.hash(input).expect("fast-mode RandomX hash")
    });

    println!("light_vm_per_hash_hps={light_hps:.2}");
    println!("fast_persistent_vm_hps={fast_hps:.2}");
    println!("speedup={:.2}x", fast_hps / light_hps);
}

fn measure<F>(duration: Duration, preimage: &mut [u8; 80], mut hash: F) -> f64
where
    F: FnMut(&[u8]) -> [u8; 32],
{
    let started = Instant::now();
    let mut hashes = 0u64;
    while started.elapsed() < duration {
        preimage[..8].copy_from_slice(&hashes.to_le_bytes());
        std::hint::black_box(hash(std::hint::black_box(preimage)));
        hashes += 1;
    }
    hashes as f64 / started.elapsed().as_secs_f64()
}

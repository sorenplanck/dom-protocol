//! Manual hashrate probe for the RandomX mining paths.
//!
//! Usage:
//!   cargo run --release -p dom-pow --example miner_hashrate_probe -- <mode> <threads> <seconds>
//!
//! Modes:
//!   light-ephemeral  — one throwaway light VM per hash (`randomx_hash`, the
//!                      validation path; what mining used before `MinerVm`)
//!   light-vm         — persistent light VM per thread (`MinerVm::new_light`)
//!   fast             — persistent fast-mode VM per thread (`MinerVm::new`,
//!                      shared ~2 GB dataset)
//!
//! Prints aggregate H/s. Dataset build time (fast mode, first run per seed)
//! is reported separately and excluded from the hashing window.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dom_pow::randomx_pool::randomx_hash;
use dom_pow::MinerVm;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("fast");
    let threads: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
    let seconds: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);
    let seed = [7u8; 32];

    // Fast mode: pay the one-off dataset build before the timed window, on
    // one thread — exactly what the first mining worker of an epoch does.
    if mode == "fast" {
        let build_start = Instant::now();
        let _warm = MinerVm::new(&seed).expect("dataset build");
        println!("dataset build: {:.1}s", build_start.elapsed().as_secs_f64());
    }

    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|worker| {
            let stop = Arc::clone(&stop);
            let total = Arc::clone(&total);
            let mode = mode.to_string();
            std::thread::spawn(move || {
                let vm = match mode.as_str() {
                    "fast" => Some(MinerVm::new(&seed).expect("fast vm")),
                    "light-vm" => Some(MinerVm::new_light(&seed).expect("light vm")),
                    "light-ephemeral" => None,
                    other => panic!("unknown mode {other}"),
                };
                let mut preimage = [0u8; 76];
                preimage[0] = worker as u8; // disjoint nonce spaces
                let mut nonce = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    preimage[8..16].copy_from_slice(&nonce.to_le_bytes());
                    let h = match &vm {
                        Some(vm) => vm.hash(&preimage).expect("hash"),
                        None => randomx_hash(&seed, &preimage).expect("hash"),
                    };
                    std::hint::black_box(h);
                    total.fetch_add(1, Ordering::Relaxed);
                    nonce += 1;
                }
            })
        })
        .collect();

    std::thread::sleep(Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("worker join");
    }
    let elapsed = start.elapsed().as_secs_f64();
    let hashes = total.load(Ordering::Relaxed);
    println!(
        "mode={mode} threads={threads} window={elapsed:.1}s hashes={hashes} rate={:.1} H/s",
        hashes as f64 / elapsed
    );
}

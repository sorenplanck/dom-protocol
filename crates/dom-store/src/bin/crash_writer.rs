//! Helper binary for Phase 3.1 SIGKILL crash-consistency tests.
//!
//! The parent test spawns this process, lets it write blocks for a brief
//! window, then sends SIGKILL while a write loop is in flight. The
//! parent then re-opens the LMDB env and asserts the invariants in
//! `tests/crash_consistency_sigkill.rs`. This binary itself never
//! exits cleanly under the test: the kill is the test condition.
//!
//! Environment contract (parent sets all of these):
//! - `DOM_CRASH_DIR`            — LMDB directory to open.
//! - `DOM_CRASH_BLOCKS`         — number of synthetic blocks to commit.
//! - `DOM_CRASH_READY_FILE`     — touched after open succeeds, before
//!   the write loop starts; parent waits for it so it knows when to arm
//!   the kill timer.
//! - `DOM_CRASH_PAUSE_MICROS`   — sleep between commits, in µs. Lets
//!   the parent land SIGKILL between (or during) iterations.

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::Duration;

use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;

fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("missing env var {key}")))
}

fn env_u64(key: &str) -> u64 {
    std::env::var(key)
        .unwrap_or_else(|_| panic!("missing env var {key}"))
        .parse()
        .unwrap_or_else(|e| panic!("env var {key} not u64: {e}"))
}

fn main() {
    let dir = env_path("DOM_CRASH_DIR");
    let blocks = env_u64("DOM_CRASH_BLOCKS");
    let ready_file = env_path("DOM_CRASH_READY_FILE");
    let pause_micros = env_u64("DOM_CRASH_PAUSE_MICROS");

    let store = DomStore::open(&dir).expect("crash_writer: open store");

    // Signal readiness so the parent can arm its kill timer with a known
    // upper bound on when commit_block calls begin.
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&ready_file)
        .expect("crash_writer: touch ready file");

    for height in 1..=blocks {
        let seed = (height & 0xff) as u8;
        let mut hash = [0u8; 32];
        hash[0] = seed;
        hash[1] = ((height >> 8) & 0xff) as u8;
        let mut commitment = [0u8; 33];
        commitment[0] = 0x02;
        commitment[1] = seed;
        commitment[2] = ((height >> 8) & 0xff) as u8;
        let mut excess = [0u8; 33];
        excess[0] = 0x03;
        excess[1] = seed;
        excess[2] = ((height >> 8) & 0xff) as u8;

        let header = vec![0xAAu8; 64];
        let body = vec![0xBBu8; 32];
        let entry = UtxoEntry {
            block_height: height,
            is_coinbase: true,
            proof: vec![0xCC; 16],
        }
        .to_bytes();

        store
            .commit_block(
                &hash,
                height,
                &header,
                &body,
                &[(commitment, entry)],
                &[],
                &[(excess, hash)],
            )
            .expect("crash_writer: commit_block");

        if pause_micros > 0 {
            std::thread::sleep(Duration::from_micros(pause_micros));
        }
    }

    // Parent will SIGKILL before this point in any meaningful run. If we
    // reach here, the test sized its kill window too generously — exit
    // non-zero so the parent assertion flags it.
    eprintln!("crash_writer: completed all {blocks} blocks without being killed");
    std::process::exit(2);
}

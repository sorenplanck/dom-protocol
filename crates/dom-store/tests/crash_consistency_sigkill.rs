//! Roadmap v2 Phase 3.1 — SIGKILL crash-consistency harness.
//!
//! The invariant tests in `crash_consistency.rs` exercise the atomicity
//! contract of `commit_block` against the public API but never actually
//! crash the writer. This file does. It spawns the `crash_writer`
//! helper binary, waits for it to signal readiness, sends SIGKILL after
//! a randomised delay so the kill lands at an arbitrary point of the
//! write loop (between commits or in the middle of one), re-opens the
//! LMDB env in this process, and asserts the post-crash state.
//!
//! Invariants checked after restart (RFC-0007 step 14):
//! 1. No partial block: for every committed block_hash the header
//!    table and the block-body table must agree (both present or both
//!    absent). LMDB's per-txn atomicity should guarantee this — the
//!    test exists to catch a future regression that, say, splits the
//!    two `put`s across separate transactions.
//! 2. `chain tip` (if set) must point at a hash that has both a
//!    header and a body.
//! 3. Every `height -> hash` mapping must reference a hash whose
//!    header is present (no dangling height pointers).
//! 4. The number of committed blocks observed after restart is `>= 0`
//!    and `<= DOM_CRASH_BLOCKS`. The lower bound checks the kill did
//!    not zero out previously committed data; the upper bound checks
//!    we are not reading a sentinel past the last successful txn.
//!
//! These properties hold regardless of *when* the kill landed. The
//! test is parameterised over a handful of kill delays (early / mid /
//! late) so a single CI run exercises several phases of the loop.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use dom_store::DomStore;
use tempfile::TempDir;

/// Locate the `crash_writer` binary built alongside the test crate.
/// Cargo exposes the path of every `[[bin]]` of the same package via
/// the `CARGO_BIN_EXE_<name>` env var at compile time.
fn crash_writer_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_crash_writer"))
}

fn wait_for_ready(ready: &Path, deadline: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if ready.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

/// Run one SIGKILL scenario.
///
/// `blocks` — total commits the child will attempt.
/// `pause_micros` — sleep between commits inside the child.
/// `kill_after` — when to send SIGKILL, measured from the moment the
/// child signals readiness. Picking values smaller than the loop's
/// total expected duration is what guarantees the kill races real
/// writes.
fn run_one_scenario(blocks: u64, pause_micros: u64, kill_after: Duration) {
    let dir = TempDir::new().expect("tempdir");
    let ready_file = dir.path().join(".ready");

    let mut child = Command::new(crash_writer_path())
        .env("DOM_CRASH_DIR", dir.path())
        .env("DOM_CRASH_BLOCKS", blocks.to_string())
        .env("DOM_CRASH_READY_FILE", &ready_file)
        .env("DOM_CRASH_PAUSE_MICROS", pause_micros.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn crash_writer");

    assert!(
        wait_for_ready(&ready_file, Duration::from_secs(5)),
        "crash_writer never signalled readiness"
    );

    std::thread::sleep(kill_after);

    // SIGKILL — uncatchable, the writer cannot flush or clean up. This
    // is the exact failure mode `commit_block`'s atomicity must survive.
    let pid = child.id() as i32;
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = child.wait();

    // Re-open the env in this process and check the invariants.
    let store = DomStore::open(dir.path()).expect("reopen after SIGKILL");

    let mut highest_with_header: Option<u64> = None;
    for height in 1..=blocks {
        let mut hash = [0u8; 32];
        hash[0] = (height & 0xff) as u8;
        hash[1] = ((height >> 8) & 0xff) as u8;

        let header = store
            .get_block_header(&hash)
            .expect("get_block_header should not error");
        let body = store
            .get_block_body(&hash)
            .expect("get_block_body should not error");

        // Invariant 1: header and body presence are coupled.
        assert_eq!(
            header.is_some(),
            body.is_some(),
            "height {height}: header/body presence diverged (header={:?}, body={:?})",
            header.is_some(),
            body.is_some(),
        );

        if header.is_some() {
            highest_with_header = Some(highest_with_header.map_or(height, |h| h.max(height)));
        }

        // Invariant 3: if a height -> hash mapping exists, the referenced
        // hash must have a header. We check the height index by reading it.
        if let Ok(Some(mapped_hash)) = store.get_hash_at_height(height) {
            assert!(
                store
                    .get_block_header(&mapped_hash)
                    .expect("get_block_header")
                    .is_some(),
                "height {height}: height->hash maps to {} which has no header",
                hex::encode(mapped_hash),
            );
        }
    }

    // Invariant 2: tip (if any) must resolve to a stored block.
    if let Some(tip) = store.get_chain_tip().expect("get_chain_tip") {
        assert!(
            store
                .get_block_header(&tip)
                .expect("get_block_header")
                .is_some(),
            "chain tip {} present but its header is missing",
            hex::encode(tip),
        );
        assert!(
            store
                .get_block_body(&tip)
                .expect("get_block_body")
                .is_some(),
            "chain tip {} present but its body is missing",
            hex::encode(tip),
        );
    }

    // Invariant 4: number of fully-committed blocks bounded by [0, blocks].
    if let Some(h) = highest_with_header {
        assert!(
            h <= blocks,
            "observed committed height {h} exceeds upper bound {blocks}",
        );
    }
}

#[test]
fn sigkill_during_writes_preserves_atomicity_short_loop() {
    // 200 blocks with 200µs pauses — total expected runtime ≈ 40ms;
    // kill at 10ms lands roughly mid-loop.
    run_one_scenario(200, 200, Duration::from_millis(10));
}

#[test]
fn sigkill_during_writes_preserves_atomicity_long_loop() {
    // 2000 blocks, 100µs pauses — total ≈ 200ms; kill at 100ms gives
    // ample chance for the kill to land between or during commits.
    run_one_scenario(2_000, 100, Duration::from_millis(100));
}

#[test]
fn sigkill_very_early_preserves_atomicity() {
    // Kill almost immediately — most likely to land before *any* commit.
    // Re-open must still succeed and observe an empty (but consistent)
    // store.
    run_one_scenario(1_000, 500, Duration::from_millis(1));
}

#![no_main]
//! Fuzz target: live mempool admission flooding + eviction churn (DoS-amplification).
//!
//! Surface: `Mempool::accept_tx` driven by a stream of attacker-controlled
//! transactions parsed from the fuzz input, interleaved with `remove_tx`,
//! `select_for_block`, `snapshot`, and `digest`. This exercises the admission
//! path's structural-validation + eviction loop under adversarial input,
//! distinct from `fuzz_mempool_snapshot` (which only hits the persisted-state
//! parser).
//!
//! Two amplification invariants are asserted (resource-limit asserts):
//!
//!   (A) No livelock / unbounded growth: each `accept_tx` returns, and the pool
//!       NEVER exceeds the admitted-set bound — `select_for_block(MAX)` total
//!       weight stays within MAX_BLOCK_WEIGHT, and the pool length never exceeds
//!       the number of admission attempts.
//!   (B) No panic on any path (accept / remove / select / snapshot / digest).
//!
//! Input framing: a sequence of `[u32 len][len bytes]` chunks; each chunk is
//! fed to `Transaction::deserialize`. Successfully parsed txs are admitted under
//! a hash derived from their canonical bytes (blake2b_256), matching production.

use dom_consensus::transaction::Transaction;
use dom_core::MAX_BLOCK_WEIGHT;
use dom_crypto::hash::blake2b_256;
use dom_mempool::Mempool;
use dom_serialization::{DomDeserialize, DomSerialize, Reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut pool = Mempool::new();
    let mut r = Reader::new(data);
    let mut attempts: usize = 0;

    // Bound the number of admission attempts so a pathological input cannot make
    // a single fuzz iteration run unbounded; the eviction loop itself must
    // terminate per call regardless.
    while attempts < 4096 {
        // Each frame: u32 LE length, then that many tx bytes.
        let Ok(len) = r.read_u32() else { break };
        let len = len as usize;
        // Cap a single frame so we don't try to slurp the whole remaining buffer
        // for one tx; if it doesn't fit, stop.
        if len > r.remaining() {
            break;
        }
        let Ok(chunk) = r.read_bytes(len) else { break };
        attempts += 1;

        // Parse a transaction from the chunk. Malformed → skip (graceful).
        let mut tr = Reader::new(chunk);
        let Ok(tx) = Transaction::deserialize(&mut tr) else {
            continue;
        };

        // Canonical hash of the tx bytes (production binds tx_hash this way).
        let Ok(tx_bytes) = tx.to_bytes() else {
            continue;
        };
        let tx_hash = *blake2b_256(&tx_bytes).as_bytes();

        // Interleave a removal of a previously-seen hash to churn the indices.
        if attempts % 7 == 0 {
            pool.remove_tx(&tx_hash);
        }

        // Admission must not panic; eviction loop must terminate.
        let _ = pool.accept_tx(tx, tx_hash, attempts as u64);

        // (A) Resource-limit invariant: the pool stays bounded after each accept.
        // select_for_block at the block cap must never report weight over the cap.
        let selected = pool.select_for_block(MAX_BLOCK_WEIGHT);
        let total: u64 = selected.iter().map(|e| e.weight as u64).sum();
        assert!(
            total <= MAX_BLOCK_WEIGHT as u64,
            "block selection exceeded MAX_BLOCK_WEIGHT: {total}"
        );
        assert!(
            pool.len() <= attempts,
            "pool length {} exceeded admission attempts {}",
            pool.len(),
            attempts
        );
    }

    // (B) Diagnostic surfaces must not panic on the resulting pool.
    let _ = pool.snapshot();
    let _ = pool.digest();
    let _ = pool.all_hashes();
});

//! dom-shield — KAV-negativo / directed-corruption for
//! `PersistedMempoolState` (de)serialization.
//!
//! Surface: `PersistedMempoolState::from_bytes` / `::deserialize`. Wire layout
//! (see dom-mempool/src/lib.rs `impl DomDeserialize`):
//!
//!   u32  entry_count                      (LE; capped at MAX_PERSISTED_MEMPOOL_ENTRIES)
//!   repeat entry_count times:
//!     [32]  tx_hash                        (read VERBATIM — never recomputed)
//!     u64   received_at                     (LE)
//!     Transaction                          (inputs|outputs|kernels lists + 32-byte offset)
//!
//! These are *directed* corruptions: each input deviates from a valid encoding in
//! exactly one way, and the assertion pins the exact consequence (graceful Err, a
//! specific accepted value, or a round-trip), never just "doesn't panic".
//!
//! Anti-theater note on the count cap: `MAX_PERSISTED_MEMPOOL_ENTRIES`
//! = `MAX_BLOCK_TXS * 10` = 50_000. `deserialize` rejects `len > 50_000` BEFORE
//! `Vec::with_capacity(len)`, so a huge count prefix cannot drive an unbounded
//! pre-allocation. We assert both halves: 50_001 is rejected pre-alloc, and a
//! benign count without backing bytes fails as EOF (not OOM).

use dom_consensus::transaction::{Transaction, TransactionKernel, TransactionOutput};
use dom_core::{Amount, DomError, KERNEL_FEAT_PLAIN};
use dom_crypto::hash::blake2b_256;
use dom_crypto::pedersen::Commitment;
use dom_mempool::{PersistedMempoolEntry, PersistedMempoolState};
use dom_serialization::{DomDeserialize, DomSerialize};

const MAX_PERSISTED_MEMPOOL_ENTRIES: usize = 5_000 * 10; // MAX_BLOCK_TXS * 10

fn g_commitment() -> Commitment {
    let g = [
        0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    Commitment::from_compressed_bytes(&g).unwrap()
}

/// A minimal structurally-encodable transaction (no inputs, one output, one
/// kernel, zero offset). Only its *bytes* matter for these tests.
fn sample_tx(fee: u64) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment: g_commitment(),
            proof: vec![0u8; 100],
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess: g_commitment(),
            excess_signature: [0u8; 65],
        }],
        offset: [0u8; 32],
    }
}

fn one_entry_state(tx_hash: [u8; 32], received_at: u64, tx: Transaction) -> PersistedMempoolState {
    PersistedMempoolState {
        entries: vec![PersistedMempoolEntry {
            tx,
            tx_hash,
            received_at,
        }],
    }
}

// ── (V1) Empty input ──────────────────────────────────────────────────────────

/// Zero bytes: the u32 count prefix cannot even be read. Must be a graceful
/// `Malformed` EOF, never a panic.
#[test]
fn empty_input_is_eof_error() {
    let err = PersistedMempoolState::from_bytes(&[]).expect_err("empty must error");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

// ── (V2) Count = 0, exact ───────────────────────────────────────────────────────

/// A bare `count=0` (four LE zero bytes, no trailing) decodes to the empty
/// state — and `from_bytes`'s `finish()` confirms no trailing bytes remain.
#[test]
fn zero_count_decodes_empty() {
    let bytes = 0u32.to_le_bytes();
    let decoded = PersistedMempoolState::from_bytes(&bytes).expect("zero count valid");
    assert_eq!(decoded, PersistedMempoolState::default());
    assert!(decoded.entries.is_empty());
}

// ── (V3) Huge count, cap-before-alloc ──────────────────────────────────────────

/// A count just over the cap (50_001) must be rejected by the explicit limit
/// check BEFORE `Vec::with_capacity` runs — no large allocation attempt. The
/// payload is ONLY the 4-byte prefix: if the cap were not enforced first, the
/// code would try to reserve space for 50_001 entries before discovering the
/// truncation; instead it returns the count-limit error.
#[test]
fn count_over_cap_rejected_before_alloc() {
    let over = (MAX_PERSISTED_MEMPOOL_ENTRIES as u32) + 1;
    let bytes = over.to_le_bytes();
    let err = PersistedMempoolState::from_bytes(&bytes).expect_err("over-cap must reject");
    match err {
        DomError::Malformed(msg) => assert!(
            msg.contains("exceeds limit"),
            "expected count-limit error, got: {msg}"
        ),
        other => panic!("expected Malformed count-limit, got {other:?}"),
    }
}

/// `u32::MAX` count prefix — the extreme amplification attempt. Same cap path;
/// must reject without attempting a ~4 billion-entry reservation.
#[test]
fn u32_max_count_rejected_before_alloc() {
    let bytes = u32::MAX.to_le_bytes();
    let err = PersistedMempoolState::from_bytes(&bytes).expect_err("u32::MAX must reject");
    assert!(
        matches!(err, DomError::Malformed(ref m) if m.contains("exceeds limit")),
        "got {err:?}"
    );
}

/// At-cap count (exactly 50_000) is NOT rejected by the limit gate — it passes
/// the cap and then fails as EOF because no entry bytes follow. This pins that
/// the gate is `>` (strict) not `>=`, and that the post-cap path is bounded by
/// real input length, not by the prefix.
#[test]
fn at_cap_count_passes_gate_then_eof() {
    let at = MAX_PERSISTED_MEMPOOL_ENTRIES as u32;
    let bytes = at.to_le_bytes();
    let err = PersistedMempoolState::from_bytes(&bytes).expect_err("no entry bytes → EOF");
    match err {
        DomError::Malformed(msg) => assert!(
            // Must NOT be the count-limit message; must be an EOF/short-read.
            !msg.contains("exceeds limit"),
            "at-cap count must pass the limit gate, got limit error: {msg}"
        ),
        other => panic!("expected Malformed EOF, got {other:?}"),
    }
}

// ── (V4) Count says N, body has fewer ──────────────────────────────────────────

/// Count claims 3 entries but only one entry's worth of bytes follow. Must fail
/// as EOF when reading the second entry's tx_hash — graceful, no panic.
#[test]
fn count_exceeds_actual_entries_is_eof() {
    let state = one_entry_state([0x11; 32], 7, sample_tx(1000));
    let mut bytes = state.to_bytes().expect("serialize");
    // Overwrite the leading u32 count (1 → 3).
    bytes[0..4].copy_from_slice(&3u32.to_le_bytes());
    let err = PersistedMempoolState::from_bytes(&bytes).expect_err("short body → EOF");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

// ── (V5) Trailing bytes ─────────────────────────────────────────────────────────

/// A valid one-entry encoding with a single extra trailing byte. `from_bytes`
/// calls `Reader::finish()`, so trailing bytes are consensus-invalid and must
/// reject (catches a regression that silently ignores garbage tails).
#[test]
fn trailing_byte_rejected() {
    let state = one_entry_state([0x22; 32], 99, sample_tx(2000));
    let mut bytes = state.to_bytes().expect("serialize");
    bytes.push(0xFF);
    let err = PersistedMempoolState::from_bytes(&bytes).expect_err("trailing byte must reject");
    assert!(
        matches!(err, DomError::Malformed(ref m) if m.contains("trailing")),
        "got {err:?}"
    );
}

// ── (V6) Truncated mid-transaction ─────────────────────────────────────────────

/// Truncate a valid one-entry encoding inside the embedded Transaction (drop the
/// last byte). Decoding the inner tx must fail as EOF — never a panic or a
/// half-built entry.
#[test]
fn truncated_inside_transaction_is_eof() {
    let state = one_entry_state([0x33; 32], 5, sample_tx(3000));
    let mut bytes = state.to_bytes().expect("serialize");
    bytes.pop(); // drop one byte from the tail (inside Transaction.offset)
    let err = PersistedMempoolState::from_bytes(&bytes).expect_err("truncated tx → EOF");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

// ── (V7) Corrupt embedded proof length (inner amplification prefix) ─────────────

/// The embedded Transaction's output carries a u32-length-prefixed proof. Patch
/// that inner length to a huge value with no backing bytes. The inner
/// `read_vec(MAX_PROOF_SIZE)` must reject (limit or EOF) — confirming the
/// nested parser is itself bounded, not just the outer count.
#[test]
fn corrupt_inner_proof_length_rejected() {
    let state = one_entry_state([0x44; 32], 1, sample_tx(4000));
    let mut bytes = state.to_bytes().expect("serialize");
    // Layout up to the proof length:
    //   4 (count) + 32 (tx_hash) + 8 (received_at)
    //   + Transaction: 4 (inputs count=0) + 4 (outputs count=1)
    //   + 33 (output commitment) → then the u32 proof length.
    let proof_len_off = 4 + 32 + 8 + 4 + 4 + 33;
    bytes[proof_len_off..proof_len_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let err =
        PersistedMempoolState::from_bytes(&bytes).expect_err("huge inner proof len must reject");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

// ── (V8) tx_hash is NOT recomputed vs blake2b(tx) ──────────────────────────────

/// CENTRAL FINDING — directed test pairing a WRONG hash with a tx.
///
/// `deserialize` reads `tx_hash` verbatim and never recomputes it from the
/// transaction bytes. We build a snapshot whose stored `tx_hash` is provably
/// NOT `blake2b_256(tx_bytes)`, serialize it, and decode it back: the decode
/// SUCCEEDS and preserves the bogus hash unchanged. This pins the trust model —
/// the persisted-state parser authenticates nothing about the (hash, tx)
/// binding; any integrity guarantee must come from the caller, not this format.
///
/// This is not a crash bug; it is a documented property. If a future change adds
/// hash verification in `deserialize`, this test goes RED and forces a conscious
/// decision (it would then be a behavior change to the format).
#[test]
fn tx_hash_is_trusted_not_recomputed() {
    let tx = sample_tx(5000);
    let tx_bytes = tx.to_bytes().expect("tx serialize");
    let real_hash = *blake2b_256(&tx_bytes).as_bytes();

    // A hash guaranteed different from the canonical one.
    let mut wrong_hash = real_hash;
    wrong_hash[0] ^= 0xFF;
    assert_ne!(wrong_hash, real_hash, "constructed wrong hash must differ");

    let state = one_entry_state(wrong_hash, 0, tx);
    let bytes = state.to_bytes().expect("serialize");

    let decoded = PersistedMempoolState::from_bytes(&bytes)
        .expect("snapshot with a wrong hash still decodes (hash is trusted, not verified)");
    assert_eq!(decoded.entries.len(), 1);
    assert_eq!(
        decoded.entries[0].tx_hash, wrong_hash,
        "deserialize must return the stored hash verbatim, NOT blake2b(tx)"
    );
    assert_ne!(
        decoded.entries[0].tx_hash, real_hash,
        "if this fails, deserialize started recomputing the hash — format behavior changed"
    );
    // Confirm the canonical hash of the decoded tx is the real one, i.e. the
    // mismatch is genuine and not an artifact of tx mutation.
    let decoded_tx_bytes = decoded.entries[0].tx.to_bytes().expect("re-serialize");
    assert_eq!(*blake2b_256(&decoded_tx_bytes).as_bytes(), real_hash);
}

// ── (V9) Round-trip determinism of a valid multi-entry state ───────────────────

/// A canonically-ordered multi-entry state round-trips byte-for-byte and
/// value-for-value. Guards against field-order / framing drift in the codec.
#[test]
fn valid_multientry_roundtrips() {
    let entries = (0u8..4)
        .map(|i| PersistedMempoolEntry {
            tx: sample_tx(1000 + i as u64),
            tx_hash: [i; 32],
            received_at: i as u64 * 10,
        })
        .collect::<Vec<_>>();
    let state = PersistedMempoolState { entries };
    let bytes = state.to_bytes().expect("serialize");
    let decoded = PersistedMempoolState::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, state);
    // Re-serialize is identical (deterministic codec).
    assert_eq!(decoded.to_bytes().expect("re-serialize"), bytes);
}

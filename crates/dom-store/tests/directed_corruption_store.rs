//! dom-shield — dom-store directed-corruption + KAV-negativo + XDIFF families.
//!
//! Scope: the *persisted-state parsers* and the on-disk read API of dom-store
//! against TAMPERED / SHORT / WRONG-LENGTH on-disk bytes. COVERAGE #8 marks the
//! fuzz-panic family `[—]` (bounded fixed-offset parsers → fuzz theater); this
//! file instead pins the directed corruption contract that the bounded claim
//! rests on, and surfaces the one place the "no panic path" claim does NOT hold:
//! the `block_height + maturity` add in `UtxoSet::validate_input_with_maturity`.
//!
//! NO production change. RED tests document a finding; they do not fix it.

mod common;

use common::open_test_store;
use dom_core::{BlockHeight, DomError, COINBASE_MATURITY};
use dom_store::{BlockStore, PeerAddr, UtxoEntry, UtxoSet, DB_PEER_ADDRS, DB_UTXOS};
use lmdb::{Transaction, WriteFlags};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// directed-corruption: UtxoEntry::from_bytes
// Vector: tampered / short / wrong-length on-disk bytes must yield a clean Err
// (or a faithful Ok for the well-formed-but-adversarial case) — never a panic.
// ---------------------------------------------------------------------------

#[test]
fn utxo_from_bytes_empty_is_clean_err() {
    let r = UtxoEntry::from_bytes(&[]);
    assert!(
        matches!(r, Err(DomError::Malformed(_))),
        "empty on-disk utxo bytes must be a clean Malformed Err, got {r:?}"
    );
}

#[test]
fn utxo_from_bytes_short_below_9_is_clean_err() {
    // Every length 0..=8 is below the 9-byte fixed header (u64 height + 1 flag).
    for len in 0..9usize {
        let buf = vec![0xABu8; len];
        let r = UtxoEntry::from_bytes(&buf);
        assert!(
            matches!(r, Err(DomError::Malformed(_))),
            "utxo bytes of len {len} (< 9) must be clean Err, got {r:?}"
        );
    }
}

#[test]
fn utxo_from_bytes_exactly_9_yields_empty_proof_no_panic() {
    // Boundary: exactly the fixed header, zero proof bytes. proof = bytes[9..].
    let mut buf = vec![0u8; 9];
    buf[8] = 1; // is_coinbase true
    let e = UtxoEntry::from_bytes(&buf).expect("9-byte utxo entry must parse");
    assert_eq!(e.block_height, 0);
    assert!(e.is_coinbase);
    assert!(
        e.proof.is_empty(),
        "proof from a 9-byte record must be empty"
    );
}

#[test]
fn utxo_from_bytes_tampered_coinbase_flag_is_truthy_not_just_one() {
    // bytes[8] != 0 ⇒ coinbase. A tampered flag of 0xFF must still parse as
    // coinbase (the parser is total over the flag byte), never panic.
    let mut buf = vec![0u8; 9];
    buf[8] = 0xFF;
    let e = UtxoEntry::from_bytes(&buf).expect("tampered flag must still parse");
    assert!(
        e.is_coinbase,
        "any non-zero flag byte must read as coinbase"
    );
}

#[test]
fn get_utxo_on_corrupt_short_on_disk_entry_returns_err_not_panic() {
    // Write a deliberately-short (< 9 byte) value at a 33-byte commitment key,
    // bypassing commit_block's encoder, then read it back through get_utxo.
    // The from_bytes guard must turn this into a propagated Err, not a panic.
    let dir = TempDir::new().expect("tempdir");
    let commitment = [0x02u8; 33];
    {
        let store = open_test_store(dir.path());
        let mut txn = store.env.begin_rw_txn().expect("rw txn");
        txn.put(
            store.db_utxos,
            &commitment,
            &[0xCCu8; 4],
            WriteFlags::empty(),
        )
        .expect("put short utxo");
        txn.commit().expect("commit");
    }
    let store = open_test_store(dir.path());
    let r = store.get_utxo(&commitment);
    assert!(
        matches!(r, Err(DomError::Malformed(_))),
        "get_utxo over a corrupt short on-disk entry must be a clean Err, got {r:?}"
    );
    // sanity: the DB name constant we relied on still names the utxos db.
    assert_eq!(DB_UTXOS, "utxos");
}

// ---------------------------------------------------------------------------
// directed-corruption: PeerAddr::from_bytes
// ---------------------------------------------------------------------------

#[test]
fn peer_from_bytes_short_below_12_is_clean_err() {
    for len in 0..12usize {
        let buf = vec![0x7Eu8; len];
        let r = PeerAddr::from_bytes("1.2.3.4:8333".into(), &buf);
        assert!(
            matches!(r, Err(DomError::Malformed(_))),
            "peer bytes of len {len} (< 12) must be clean Err, got {r:?}"
        );
    }
}

#[test]
fn peer_from_bytes_exactly_12_parses_no_panic() {
    let buf = vec![0u8; 12];
    let p = PeerAddr::from_bytes("addr".into(), &buf).expect("12-byte peer must parse");
    assert_eq!(p.last_seen, 0);
    assert_eq!(p.failures, 0);
    assert_eq!(DB_PEER_ADDRS, "peer_addrs");
}

// ---------------------------------------------------------------------------
// KAV-negativo: PeerAddr trailing-bytes NON-STRICT parse (malleability).
// from_bytes reads bytes[0..12] and IGNORES anything past byte 12. So two
// distinct on-disk encodings (12 bytes vs 12 bytes + garbage tail) decode to
// the SAME PeerAddr. The codec is non-canonical / malleable on input.
// Documented as a finding via assertion: the test PASSES (it proves the
// malleability exists); it is not a crash, so no fix is forced — recorded.
// ---------------------------------------------------------------------------

#[test]
fn peer_from_bytes_ignores_trailing_bytes_malleable_decode() {
    let base = {
        let p = PeerAddr {
            addr: "x".into(),
            last_seen: 0x1122_3344_5566_7788,
            failures: 0x99AA_BBCC,
        };
        p.to_bytes()
    };
    assert_eq!(base.len(), 12, "canonical peer encoding is 12 bytes");

    let mut with_tail = base.clone();
    with_tail.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // garbage tail

    let a = PeerAddr::from_bytes("x".into(), &base).expect("canonical parses");
    let b = PeerAddr::from_bytes("x".into(), &with_tail).expect("tail-padded parses");

    // MALLEABILITY: two different byte strings decode to the same logical value.
    assert_eq!(a.last_seen, b.last_seen);
    assert_eq!(a.failures, b.failures);
    // And critically, the parser does NOT reject the longer encoding — there is
    // no strict-length check past the 12-byte minimum.
    // (If a future hardening adds a strict-length gate, THIS test flips to RED
    // and that is the signal to update the malleability record in COVERAGE.)
}

#[test]
fn utxo_proof_tail_is_load_bearing_not_ignored() {
    // Contrast with PeerAddr: for UtxoEntry the trailing bytes ARE the proof,
    // so they are NOT malleable — every extra byte changes the decoded value.
    // This pins that the uncapped `bytes[9..].to_vec()` is faithfully captured.
    let mut a = vec![0u8; 9];
    a.extend_from_slice(&[1, 2, 3]);
    let mut b = vec![0u8; 9];
    b.extend_from_slice(&[1, 2, 3, 4]);
    let pa = UtxoEntry::from_bytes(&a).unwrap();
    let pb = UtxoEntry::from_bytes(&b).unwrap();
    assert_ne!(pa.proof, pb.proof, "utxo proof tail must be load-bearing");
}

// ---------------------------------------------------------------------------
// KAV-negativo (RED EXPECTED): is_mature_for / validate_input_with_maturity
// overflow. `UtxoSet::validate_input_with_maturity` formats its error with
// `entry.block_height + maturity` (utxo.rs ~L88). With a corrupt on-disk
// block_height ≈ u64::MAX reaching the IMMATURE branch, that add overflows.
// The workspace pins `overflow-checks = true` for BOTH dev and release
// (root Cargo.toml [profile.dev]/[profile.release]), so this PANICS in every
// build profile — a reachable panic / DoS driven by a single tampered u64 in
// the persisted utxos db. Contract: this should be a clean Err, not a panic.
//
// This test asserts the SAFE contract (clean TemporarilyInvalid Err, no panic)
// and is therefore EXPECTED TO FAIL (RED) against current code. It is the
// finding. It is NOT a fix. See report: RED-DS-STORE-001.
// ---------------------------------------------------------------------------

#[test]
fn validate_input_with_maturity_does_not_panic_on_max_block_height() {
    // Corrupt/hostile entry: coinbase, block_height = u64::MAX, current height
    // small ⇒ saturating_sub == 0 < maturity ⇒ IMMATURE branch ⇒ the
    // `block_height + maturity` add executes and overflows.
    let entry = UtxoEntry {
        block_height: u64::MAX,
        is_coinbase: true,
        proof: vec![],
    };
    // SAFE CONTRACT (expected): a clean TemporarilyInvalid Err, no panic.
    let r = UtxoSet::validate_input_with_maturity(&entry, BlockHeight(0), COINBASE_MATURITY);
    assert!(
        matches!(r, Err(DomError::TemporarilyInvalid(_))),
        "immature coinbase at u64::MAX must be a clean Err, not a panic; got {r:?}"
    );
}

#[test]
fn is_mature_for_boundary_created_plus_maturity_equals_height() {
    // proptest-invariante / KAV boundary: mature exactly when
    // current_height - block_height == maturity (delta reaches threshold).
    let e = UtxoEntry {
        block_height: 100,
        is_coinbase: true,
        proof: vec![],
    };
    assert!(!e.is_mature_for(100 + COINBASE_MATURITY - 1, COINBASE_MATURITY));
    assert!(e.is_mature_for(100 + COINBASE_MATURITY, COINBASE_MATURITY));
}

// ---------------------------------------------------------------------------
// XDIFF: BlockStore::compute_block_hash vs the canonical header hash used by
// the connect/validate path (chain_state::compute_block_hash). Both are raw,
// untagged Blake2b-256 over the header bytes. If BlockStore's hasher ever
// diverged (domain tag, digest swap, framing) from the value used as the
// `blocks`/`chain_tip` key, the store would index blocks under a different
// hash than the chain layer expects. We pin parity by recomputing the same
// primitive inline (the chain fn is private to dom-chain) and asserting equal.
// ---------------------------------------------------------------------------

fn canonical_blake2b_256(bytes: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[test]
fn block_store_hash_matches_canonical_blake2b_256() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; 1],
        vec![0xFFu8; 32],
        vec![0xABu8; 200],
        (0..=255u8).cycle().take(1024).collect(),
    ];
    for inp in inputs {
        assert_eq!(
            BlockStore::compute_block_hash(&inp).as_bytes(),
            &canonical_blake2b_256(&inp),
            "BlockStore::compute_block_hash diverged from canonical Blake2b-256 \
             for input len {}",
            inp.len()
        );
    }
}

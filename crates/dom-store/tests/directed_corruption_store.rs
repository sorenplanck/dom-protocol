//! dom-shield — dom-store directed-corruption + KAV-negativo + XDIFF families.
//!
//! Scope: the *persisted-state parsers* and the on-disk read API of dom-store
//! against TAMPERED / SHORT / WRONG-LENGTH on-disk bytes. COVERAGE #8 marks the
//! fuzz-panic family `[—]` (bounded fixed-offset parsers → fuzz theater); this
//! file instead pins the directed corruption contract that the bounded claim
//! rests on.

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
fn utxo_from_bytes_rejects_noncanonical_coinbase_flag() {
    // The canonical encoder emits only 0 or 1. A corrupted flag must not be
    // silently reinterpreted as a valid coinbase entry.
    let mut buf = vec![0u8; 9];
    buf[8] = 0xFF;
    assert!(
        matches!(UtxoEntry::from_bytes(&buf), Err(DomError::Malformed(_))),
        "noncanonical coinbase flags must fail closed"
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
// PeerAddr trailing bytes are noncanonical persistence corruption and must be
// rejected rather than silently ignored.
// ---------------------------------------------------------------------------

#[test]
fn peer_from_bytes_rejects_trailing_bytes() {
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

    let _ = PeerAddr::from_bytes("x".into(), &base).expect("canonical parses");
    assert!(
        matches!(
            PeerAddr::from_bytes("x".into(), &with_tail),
            Err(DomError::Malformed(_))
        ),
        "trailing persistence bytes must fail closed"
    );
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
// Maturity diagnostics use saturating arithmetic so hostile persisted heights
// cannot overflow the error path.
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

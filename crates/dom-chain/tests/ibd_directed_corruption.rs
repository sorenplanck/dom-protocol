//! dom-shield directed-corruption — poisoned persisted IBD snapshot bytes and
//! the FIX-020 silent UTXO-set replace probe.
//!
//! Two corrupted-persisted-state surfaces are exercised here:
//!
//!  A) `PersistedIbdState::deserialize` cursor / cap fields. The in-memory
//!     struct invariants are checked by ibd.rs unit tests, but those build the
//!     bytes via the (clamping) serializer. A real attacker / a torn LMDB write
//!     hands us RAW bytes where `block_cursor` or `header_cursor` exceeds the
//!     decoded queue length, or where a length prefix exceeds MAX_HEADERS_PER_MSG.
//!     The decoder must reject every such frame BEFORE it is handed to
//!     `IbdState::from_persisted`. We craft the bytes directly.
//!
//!  B) FIX-020 — `ChainState::open` -> `ensure_canonical_utxo_set` SILENTLY
//!     replaces a tampered persisted UTXO set with the reconstructed canonical
//!     one (it logs `info!` and returns Ok). The corruption_detection.rs suite
//!     treats that auto-heal as success; this probe instead pins the SAFETY
//!     expectation that a divergence between the persisted set and the
//!     reconstructed canonical set should be surfaced as an error or a
//!     detectable alarm to the operator (so a node that was running on a
//!     poisoned set does not silently continue). It is expected to run RED
//!     against current behavior — see the report (FIX-020).

mod common;

use common::open_test_store;
use dom_chain::{ChainState, PersistedIbdState, CHAIN_CORRUPT_SENTINEL};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, MAX_HEADERS_PER_MSG,
    PROTOCOL_VERSION,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_pow::CompactTarget;
use dom_serialization::{DomDeserialize, DomSerialize, Writer};
use dom_store::utxo::UtxoEntry;
use dom_store::{DomStore, METADATA_UTXO_SET_DIGEST_KEY};
use lmdb::{Cursor, Transaction, WriteFlags};
use primitive_types::U256;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// A) Poisoned PersistedIbdState frames (raw-byte directed corruption).
// ---------------------------------------------------------------------------

/// Hand-assemble a PersistedIbdState frame with attacker-chosen counts and
/// cursors, bypassing the struct's serialize() clamping. Field order mirrors
/// `impl DomSerialize for PersistedIbdState` exactly.
#[allow(clippy::too_many_arguments)]
fn craft_frame(
    phase_tag: u8,
    pending_block_count: u32,
    actual_pending_blocks: u32,
    pending_header_count: u32,
    actual_pending_headers: u32,
    block_cursor: u32,
    header_cursor: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(phase_tag); // IbdPhase
    w.write_vec(b"127.0.0.1:1").expect("peer"); // peer_addr
    w.write_u64(0); // start_height
    w.write_u64(0); // best_peer_height
    w.write_u64(0); // headers_height
    w.write_u64(0); // blocks_height
    w.write_u64(0); // last_progress_height
    w.write_bytes(&[0u8; 32]); // checkpoint_tip_hash
    w.write_u8(0); // retry_attempts
    w.write_u8(0); // last_interruption presence = None

    w.write_u32(pending_block_count); // declared count
    for _ in 0..actual_pending_blocks {
        w.write_bytes(&[0u8; 32]);
    }
    w.write_u32(pending_header_count); // declared count
    for _ in 0..actual_pending_headers {
        w.write_vec(&[0xAAu8; 8]).expect("header");
    }
    w.write_u32(block_cursor);
    w.write_u32(header_cursor);
    w.write_u64(0); // header_cursor_height
    w.finish()
}

#[test]
fn deserialize_rejects_block_cursor_beyond_pending_blocks() {
    // 1 pending block present and declared, but block_cursor = 2 (> 1).
    let bytes = craft_frame(2 /*BlockSync*/, 1, 1, 0, 0, 2, 0);
    let err = PersistedIbdState::from_bytes(&bytes)
        .expect_err("block_cursor beyond pending blocks must be rejected");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

#[test]
fn deserialize_rejects_header_cursor_beyond_pending_headers() {
    // 1 pending header present and declared, header_cursor = 5 (> 1).
    let bytes = craft_frame(2, 0, 0, 1, 1, 0, 5);
    let err = PersistedIbdState::from_bytes(&bytes)
        .expect_err("header_cursor beyond pending headers must be rejected");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

#[test]
fn deserialize_rejects_pending_block_count_over_cap() {
    // Declared pending-block count exceeds MAX_HEADERS_PER_MSG. The decoder
    // must reject on the cap check BEFORE attempting to allocate/read that many
    // 32-byte hashes (DoS-allocation guard). We provide zero actual bodies; a
    // correct decoder errors on the cap before reaching them.
    let over = (MAX_HEADERS_PER_MSG as u32) + 1;
    let bytes = craft_frame(2, over, 0, 0, 0, 0, 0);
    let err = PersistedIbdState::from_bytes(&bytes)
        .expect_err("pending block count over cap must be rejected");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

#[test]
fn deserialize_rejects_pending_header_count_over_cap() {
    let over = (MAX_HEADERS_PER_MSG as u32) + 1;
    let bytes = craft_frame(2, 0, 0, over, 0, 0, 0);
    let err = PersistedIbdState::from_bytes(&bytes)
        .expect_err("pending header count over cap must be rejected");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

#[test]
fn deserialize_rejects_unknown_phase_tag() {
    // Phase tag 9 is out of range (valid 0..=8). Directed single-byte flip.
    let bytes = craft_frame(9, 0, 0, 0, 0, 0, 0);
    let err =
        PersistedIbdState::from_bytes(&bytes).expect_err("unknown phase tag must be rejected");
    assert!(matches!(err, DomError::Malformed(_)), "got {err:?}");
}

#[test]
fn deserialize_well_formed_frame_roundtrips() {
    // Control: a well-formed frame (cursor 0, counts within cap) must decode.
    // Guards against the corruption tests passing only because decode always
    // fails. start..=headers heights are all 0, satisfying the monotonic check.
    let bytes = craft_frame(0 /*Idle*/, 0, 0, 0, 0, 0, 0);
    let decoded = PersistedIbdState::from_bytes(&bytes).expect("well-formed frame must decode");
    assert_eq!(decoded.block_cursor, 0);
    assert_eq!(decoded.header_cursor, 0);
}

// ---------------------------------------------------------------------------
// B) FIX-020 — a tampered persisted UTXO set must ALARM (fatal) on reopen, and
//    heal only under the explicit operator repair opt-in.
//
// The production fix lives in `ensure_canonical_utxo_set` (chain_state.rs): when
// the persisted UTXO set diverges from the canonical reconstruction, the default
// startup path (`ChainState::open`) now logs at ERROR and returns a fatal
// `CHAIN_CORRUPT_SENTINEL` error instead of silently calling `replace_utxo_set`.
// The reconstruction survives only as an explicit operator opt-in
// (`ChainState::open_with_utxo_repair`). These two tests pin both halves of that
// contract with a real committed chain and a raw-byte tampered UTXO entry.
// ---------------------------------------------------------------------------

type SyntheticGenesis = (Vec<u8>, Vec<u8>, [u8; 32], [u8; 33], [u8; 33]);

/// Minimal cryptographically-shaped genesis block with one coinbase output.
/// Mirrors the synthetic builder in corruption_detection.rs, trimmed to the
/// single block these barrier tests need.
fn synthetic_genesis() -> SyntheticGenesis {
    let mut blind = [0u8; 32];
    blind[31] = 0xE0;
    let output = Commitment::commit(50, &BlindingFactor::from_bytes(blind).expect("blind"));
    let mut kblind = [0u8; 32];
    kblind[31] = 0xE1;
    let excess = Commitment::commit(0, &BlindingFactor::from_bytes(kblind).expect("kblind"));

    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(0),
        prev_hash: Hash256::ZERO,
        timestamp: Timestamp(1_704_067_200),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0x1f00_ffff),
        total_difficulty: U256::one(),
        pow: ProofOfWork {
            nonce: 0xA0,
            randomx_hash: Hash256::ZERO,
        },
    };
    let header_bytes = header.to_bytes().expect("serialize header");
    let block_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    let output_bytes = *output.as_bytes();
    let excess_bytes = *excess.as_bytes();
    let block = Block {
        header,
        coinbase: CoinbaseTransaction {
            output: TransactionOutput {
                commitment: output,
                proof: vec![0xAA; 8],
            },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value: 1,
                excess,
                excess_signature: [0u8; 65],
            },
            offset: [0u8; 32],
        },
        transactions: Vec::new(),
    };
    (
        header_bytes,
        block.to_bytes().expect("serialize block"),
        block_hash,
        output_bytes,
        excess_bytes,
    )
}

/// Commit the genesis block, returning the canonical coinbase output commitment.
fn commit_genesis_chain(store: &DomStore) -> [u8; 33] {
    let (header, body, hash, output, excess) = synthetic_genesis();
    store
        .commit_block(
            &hash,
            0,
            &header,
            &body,
            &[(
                output,
                UtxoEntry {
                    block_height: 0,
                    is_coinbase: true,
                    proof: vec![0xAA; 8],
                }
                .to_bytes(),
            )],
            &[],
            &[(excess, hash)],
        )
        .expect("commit synthetic genesis");
    output
}

fn dump_utxos(store: &DomStore) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let txn = store.env.begin_ro_txn().expect("ro txn");
    let mut cursor = txn.open_ro_cursor(store.db_utxos).expect("cursor");
    let mut out = BTreeMap::new();
    for item in cursor.iter() {
        let (k, v) = item.expect("cursor item");
        out.insert(k.to_vec(), v.to_vec());
    }
    out
}

/// Overwrite a persisted UTXO entry with attacker/rot bytes and drop the
/// digest metadata, forcing `persisted != canonical` on the next reopen.
fn tamper_persisted_utxo(store: &DomStore, commitment: &[u8; 33]) {
    let mut txn = store.env.begin_rw_txn().expect("rw txn");
    txn.put(
        store.db_utxos,
        commitment,
        &UtxoEntry {
            block_height: 999,
            is_coinbase: false,
            proof: vec![0xAB; 8],
        }
        .to_bytes(),
        WriteFlags::empty(),
    )
    .expect("tamper utxo");
    match txn.del(store.db_metadata, &METADATA_UTXO_SET_DIGEST_KEY, None) {
        Ok(()) | Err(lmdb::Error::NotFound) => {}
        Err(e) => panic!("del digest: {e}"),
    }
    txn.commit().expect("commit tamper");
}

/// SAFETY barrier: a persisted UTXO set that diverges from the canonical
/// reconstruction must make the DEFAULT reopen fail closed — never silently
/// heal. The node must refuse to run on a possibly-tampered set.
#[test]
fn fix020_tampered_persisted_utxo_set_should_alarm_on_reopen() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    {
        let store = open_test_store(dir.path());
        let output = commit_genesis_chain(&store);
        tamper_persisted_utxo(&store, &output);
    }

    let result = ChainState::open(
        open_test_store(dir.path()),
        // This fixture commits a deliberately synthetic block-zero record.
        // Hash256::ZERO selects the unpinned test identity so genesis
        // enforcement does not mask the UTXO-corruption assertion below.
        Hash256::ZERO,
        dom_core::NETWORK_MAGIC_REGTEST,
    );
    let msg = match result {
        Err(e) => format!("{e}"),
        Ok(_) => {
            panic!("FIX-020: default reopen on a tampered UTXO set must fail, not silently heal")
        }
    };
    assert!(
        msg.contains(CHAIN_CORRUPT_SENTINEL) && msg.contains("diverges"),
        "divergence must surface the corruption sentinel; got: {msg}"
    );
    assert!(
        msg.contains("open_with_utxo_repair"),
        "the fatal error must instruct the operator to use the explicit repair mode; got: {msg}"
    );
}

/// The reconstruction path is preserved as an EXPLICIT operator opt-in: opening
/// with `open_with_utxo_repair` rebuilds the canonical UTXO set and re-persists
/// the digest, healing the tampered entry.
#[test]
fn fix020_operator_repair_mode_rebuilds_canonical_utxo_set() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let output = {
        let store = open_test_store(dir.path());
        commit_genesis_chain(&store)
    };
    // Canonical snapshot captured from a clean reopen BEFORE tampering.
    let canonical = {
        let chain = ChainState::open(
            open_test_store(dir.path()),
            Hash256::ZERO,
            dom_core::NETWORK_MAGIC_REGTEST,
        )
        .expect("clean reopen");
        dump_utxos(&chain.store)
    };

    tamper_persisted_utxo(&open_test_store(dir.path()), &output);

    let repaired = ChainState::open_with_utxo_repair(
        open_test_store(dir.path()),
        Hash256::ZERO,
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("operator repair mode must rebuild the canonical UTXO set");

    assert_eq!(
        dump_utxos(&repaired.store),
        canonical,
        "repair mode must restore the exact canonical UTXO set"
    );
    assert!(
        repaired
            .store
            .get_metadata(METADATA_UTXO_SET_DIGEST_KEY)
            .expect("digest lookup")
            .is_some(),
        "repair must re-persist the canonical UTXO digest"
    );
}

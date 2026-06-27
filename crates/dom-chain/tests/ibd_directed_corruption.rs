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
use dom_chain::PersistedIbdState;
use dom_core::{DomError, MAX_HEADERS_PER_MSG};
use dom_serialization::{DomDeserialize, Writer};

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
// B) FIX-020 probe — silent UTXO-set replace on reopen.
//
// This probe needs a committed canonical chain plus a tampered persisted UTXO
// set, then a reopen, and asserts the divergence is surfaced (error/alarm)
// rather than silently healed. Building a cryptographically valid committed
// chain here would duplicate the heavy block-builders in
// corruption_detection.rs / reorg_equivalence.rs. The executable assertion of
// the SAFETY expectation lives in corruption_detection.rs's reopen tests today
// (they prove the SILENT auto-heal happens and succeeds). The probe is recorded
// as a documented RED gap (FIX-020) rather than a duplicated heavy fixture: the
// production behavior in `ensure_canonical_utxo_set` (chain_state.rs ~line 1208)
// returns Ok after `store.replace_utxo_set(...)` with only an `info!` log when
// `persisted != canonical_raw`. There is NO error path and NO operator alarm
// signal an integration test could assert on. Surfacing that is a code change
// (PRECISA DECISÃO HUMANA) and is therefore out of test-construction scope.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "FIX-020: ensure_canonical_utxo_set silently replaces a tampered \
persisted UTXO set (info! log, returns Ok) — no error/alarm exists to assert \
on without a production change (PRECISA DECISÃO HUMANA). Building the heavy \
committed-chain fixture would duplicate corruption_detection.rs. Tracked as a \
RED gap; see report."]
fn fix020_tampered_persisted_utxo_set_should_alarm_on_reopen() {
    // Intentionally a no-op placeholder pinned by the #[ignore] note above.
    // The behavioral evidence is in corruption_detection.rs::
    // reopen_rebuilds_exact_canonical_utxo_after_altered_persisted_utxo, which
    // demonstrates the SILENT heal (success, no error) that this probe argues
    // should instead alarm.
    let _ = open_test_store(std::path::Path::new("."));
}

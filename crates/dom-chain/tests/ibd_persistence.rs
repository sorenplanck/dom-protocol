//! Restart-safe IBD persistence tests.
//!
//! These tests pin the persisted IBD snapshot contract:
//! 1. serialized state round-trips bit-exactly;
//! 2. the LMDB metadata record survives reopen unchanged;
//! 3. clearing the persisted session is durable across reopen.

use dom_chain::{IbdInterruption, IbdPhase, PersistedIbdState};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_store::DomStore;
use tempfile::TempDir;

fn sample_state() -> PersistedIbdState {
    PersistedIbdState {
        phase: IbdPhase::BlockSync,
        peer_addr: "127.0.0.1:33369".into(),
        start_height: 42,
        best_peer_height: 88,
        headers_height: 64,
        blocks_height: 59,
        last_progress_height: 59,
        retry_attempts: 2,
        last_interruption: Some(IbdInterruption::Timeout),
        pending_blocks: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
        block_cursor: 2,
        header_cursor_height: 64,
    }
}

#[test]
fn persisted_ibd_state_serialization_roundtrips() {
    let state = sample_state();
    let decoded =
        PersistedIbdState::from_bytes(&state.to_bytes().expect("serialize")).expect("decode");
    assert_eq!(decoded, state);
}

#[test]
fn persisted_ibd_state_survives_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().to_path_buf();
    let expected = sample_state();

    {
        let store = DomStore::open(&path).expect("open");
        expected.save(&store).expect("save");
    }

    let reopened = DomStore::open(&path).expect("reopen");
    let restored = PersistedIbdState::load(&reopened)
        .expect("load")
        .expect("state must exist");
    assert_eq!(restored, expected);
}

#[test]
fn cleared_ibd_state_stays_cleared_after_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().to_path_buf();

    {
        let store = DomStore::open(&path).expect("open");
        sample_state().save(&store).expect("save");
        PersistedIbdState::clear(&store).expect("clear");
    }

    let reopened = DomStore::open(&path).expect("reopen");
    assert!(PersistedIbdState::load(&reopened)
        .expect("load after clear")
        .is_none());
}

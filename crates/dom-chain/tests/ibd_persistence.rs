//! Restart-safe IBD persistence tests.
//!
//! These tests pin the persisted IBD snapshot contract:
//! 1. serialized state round-trips bit-exactly;
//! 2. the LMDB metadata record survives reopen unchanged;
//! 3. clearing the persisted session is durable across reopen.

mod common;

use common::open_test_store;
use dom_chain::{
    IbdInterruption, IbdPhase, PersistedIbdState, IBD_SESSION_METADATA_KEY,
    LEGACY_IBD_SESSION_METADATA_KEY,
};
use dom_serialization::{DomDeserialize, DomSerialize};
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
        checkpoint_tip_hash: [0xAB; 32],
        retry_attempts: 2,
        last_interruption: Some(IbdInterruption::Timeout),
        pending_blocks: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
        pending_headers: vec![vec![0xAA; 64], vec![0xBB; 64]],
        block_cursor: 2,
        header_cursor: 1,
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
        let store = open_test_store(&path);
        expected.save(&store).expect("save");
    }

    let reopened = open_test_store(&path);
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
        let store = open_test_store(&path);
        sample_state().save(&store).expect("save");
        PersistedIbdState::clear(&store).expect("clear");
    }

    let reopened = open_test_store(&path);
    assert!(PersistedIbdState::load(&reopened)
        .expect("load after clear")
        .is_none());
}

#[test]
fn legacy_ibd_session_is_migrated_to_versioned_metadata() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    let expected = sample_state();
    let versioned = expected.to_bytes().expect("serialize v2");
    store
        .put_metadata(LEGACY_IBD_SESSION_METADATA_KEY, &versioned[1..])
        .expect("write legacy snapshot");

    let restored = PersistedIbdState::load(&store)
        .expect("migrate")
        .expect("state present");

    assert_eq!(restored, expected);
    assert!(store
        .get_metadata(LEGACY_IBD_SESSION_METADATA_KEY)
        .expect("read legacy key")
        .is_none());
    assert!(store
        .get_metadata(IBD_SESSION_METADATA_KEY)
        .expect("read v2 key")
        .is_some());
}

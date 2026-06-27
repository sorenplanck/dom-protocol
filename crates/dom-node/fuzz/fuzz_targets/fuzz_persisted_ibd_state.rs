#![no_main]
//! Fuzz target: dom_chain::PersistedIbdState::from_bytes — the corrupt-persisted
//! IBD cursor surface the node loads on startup (node.rs initialize_ibd_state ->
//! PersistedIbdState::load -> from_bytes). The parser MUST reject out-of-range
//! block_cursor / header_cursor (slice-index guards) without panicking, so the
//! node's later `pending_blocks[cursor..]` slicing can never go OOB.
use dom_serialization::DomDeserialize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(state) = dom_chain::PersistedIbdState::from_bytes(data) {
        // If it parsed, the cursors MUST be within the decoded vectors — the
        // exact invariant the node relies on before slicing. Calling the
        // resumability check must not panic.
        let _ = state.is_round_resumable();
        assert!(state.block_cursor as usize <= state.pending_blocks.len());
        assert!(state.header_cursor as usize <= state.pending_headers.len());
    }
});

#![no_main]
//! Fuzz target: dom_chain::ChainState::validate_ibd_headers_batch
//!
//! Attack vector (Lens A: panic/crash, OOB, over-alloc). This is the live
//! headers-first prefilter that runs over peer-supplied header bytes BEFORE any
//! block body is requested — i.e. the first attacker-reachable parser on the IBD
//! path. It decodes each raw header, links continuity, checks parent linkage,
//! and applies header-only consensus rules. It must return Ok/Err for ANY
//! sequence of arbitrary byte blobs and never panic.
//!
//! The fuzzer splits the input into length-prefixed chunks (each chunk = one raw
//! header blob), so a single corpus entry produces an arbitrary batch of
//! arbitrary headers. The ChainState is a throwaway regtest store in a tempdir.

use libfuzzer_sys::fuzz_target;
use dom_chain::ChainState;
use dom_core::{Hash256, Timestamp, GENESIS_HASH_REGTEST, NETWORK_MAGIC_REGTEST};
use dom_store::DomStore;

const MAP_SIZE: usize = 32 << 20; // 32 MiB throwaway store

/// Split `data` into up to a bounded number of chunks. The first byte gives a
/// chunk count nibble; each chunk is a 1-byte length prefix followed by that
/// many bytes (clamped to the remaining input). This yields a Vec<Vec<u8>> of
/// arbitrary raw-header candidates without needing a full structured fuzzer.
fn split_chunks(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if data.is_empty() {
        return out;
    }
    // Bound batch count to MAX_HEADERS_PER_MSG-ish to avoid pathological inputs
    // dominating the run; the production cap is enforced upstream by the wire
    // layer, not by validate_ibd_headers_batch itself.
    let max_chunks = 64usize;
    let mut i = 0usize;
    while i < data.len() && out.len() < max_chunks {
        let len = data[i] as usize;
        i += 1;
        let end = (i + len).min(data.len());
        out.push(data[i..end].to_vec());
        i = end;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let raw_headers = split_chunks(data);

    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let store = match DomStore::open_with_map_size(dir.path(), MAP_SIZE) {
        Ok(s) => s,
        Err(_) => return,
    };
    let chain = match ChainState::open(
        store,
        Hash256::from_bytes(GENESIS_HASH_REGTEST),
        NETWORK_MAGIC_REGTEST,
    ) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Realistic, fixed `now`; the property under test is "no panic", not a
    // particular accept/reject verdict.
    let _ = chain.validate_ibd_headers_batch(&raw_headers, Timestamp(2_000_000_000));
});

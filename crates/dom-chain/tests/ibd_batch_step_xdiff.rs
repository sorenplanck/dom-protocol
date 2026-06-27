//! dom-shield XDIFF — `validate_ibd_headers_batch` vs `validate_ibd_header_step`.
//!
//! The live headers-first IBD path validates a full batch in one call
//! (`validate_ibd_headers_batch`); the restart/resume path re-validates the
//! persisted queue one header at a time (`validate_ibd_header_step`) so a node
//! interrupted mid-batch resumes deterministically. These two implementations
//! re-encode the SAME consensus rules (continuity, parent linkage, height/
//! prev_hash ordering, decode). If they ever disagree on whether a given raw
//! header queue is acceptable, a node that crashed mid-batch could accept on
//! resume a queue it would have rejected live (or vice-versa) — a path-
//! dependent consensus divergence.
//!
//! Building positively-valid batches requires real RandomX PoW per header,
//! which is exercised elsewhere (chain_state randomx_seed_tests, the live IBD
//! tests). This differential pins the cheaper, equally consensus-critical half:
//! every STRUCTURAL rejection (decode failure, unknown start parent, height
//! gap, prev_hash break) must be reported IDENTICALLY by both entry points,
//! because those checks run before any PoW work and are the ones an attacker
//! reaches for free. A divergence here is the finding.

mod common;

use common::open_test_chain;
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp, PROTOCOL_VERSION};
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use primitive_types::U256;
use tempfile::TempDir;

fn synth_header(prev: Hash256, height: u64) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(height),
        prev_hash: prev,
        timestamp: Timestamp(1_700_000_000 + height),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0x1f00_ffff),
        total_difficulty: U256::from(height + 1),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    }
}

fn raw(h: &BlockHeader) -> Vec<u8> {
    h.to_bytes().expect("serialize header")
}

fn open_chain(dir: &std::path::Path) -> ChainState {
    open_test_chain(
        dir,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("chain open")
}

/// Variant tag of a DomError so we can compare "same kind of rejection"
/// without depending on the exact (path-specific) message text.
fn err_kind(e: &DomError) -> &'static str {
    match e {
        DomError::Invalid(_) => "Invalid",
        DomError::Malformed(_) => "Malformed",
        DomError::Orphan(_) => "Orphan",
        DomError::PolicyRejected(_) => "PolicyRejected",
        DomError::PeerMisbehavior { .. } => "PeerMisbehavior",
        DomError::Internal(_) => "Internal",
        DomError::TemporarilyInvalid(_) => "TemporarilyInvalid",
    }
}

/// Drive the step API across the whole queue exactly as the resume path does:
/// start with an empty missing-hash prefix and advance the cursor until either
/// a step rejects (return that error) or the cursor reaches the end (Ok).
fn run_step_to_completion(
    chain: &ChainState,
    raws: &[Vec<u8>],
    now: Timestamp,
) -> Result<(), DomError> {
    let mut cursor = 0usize;
    let mut missing: Vec<[u8; 32]> = Vec::new();
    while cursor < raws.len() {
        let (_h, observed) = chain.validate_ibd_header_step(raws, cursor, &missing, now)?;
        missing = observed;
        cursor += 1;
    }
    Ok(())
}

fn assert_same_rejection(raws: &[Vec<u8>], label: &str) {
    let dir = TempDir::new().expect("tempdir");
    let chain = open_chain(dir.path());
    let now = Timestamp(2_000_000_000);

    let batch = chain.validate_ibd_headers_batch(raws, now);
    let step = run_step_to_completion(&chain, raws, now);

    match (&batch, &step) {
        (Err(b), Err(s)) => assert_eq!(
            err_kind(b),
            err_kind(s),
            "{label}: batch rejected as {} but step rejected as {}",
            err_kind(b),
            err_kind(s)
        ),
        (Ok(_), Ok(_)) => panic!("{label}: expected both to reject, both accepted"),
        (b, s) => panic!("{label}: divergent accept/reject — batch={b:?} step={s:?}"),
    }
}

#[test]
fn xdiff_unknown_start_parent_rejected_identically() {
    // First header (height 7) attaches to a parent the store does not have.
    let h = synth_header(Hash256::from_bytes([0x99; 32]), 7);
    assert_same_rejection(&[raw(&h)], "unknown-start-parent");
}

#[test]
fn xdiff_height_gap_rejected_identically() {
    // Two-header queue with a forward height gap (0 then 5).
    let h0 = synth_header(Hash256::ZERO, 0);
    let h0_hash = dom_crypto::hash::blake2b_256(&raw(&h0));
    let h_gap = synth_header(h0_hash, 5);
    assert_same_rejection(&[raw(&h0), raw(&h_gap)], "height-gap");
}

#[test]
fn xdiff_prev_hash_break_rejected_identically() {
    // Contiguous heights (0,1) but the second header's prev_hash is wrong.
    let h0 = synth_header(Hash256::ZERO, 0);
    let h1 = synth_header(Hash256::from_bytes([0x77; 32]), 1);
    assert_same_rejection(&[raw(&h0), raw(&h1)], "prev-hash-break");
}

#[test]
fn xdiff_malformed_header_bytes_rejected_identically() {
    // Truncated/garbage bytes that cannot decode into a BlockHeader.
    let garbage = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
    assert_same_rejection(&[garbage], "malformed-bytes");
}

#[test]
fn xdiff_backwards_second_header_rejected_identically() {
    // Heights go 3 then 2 (backwards), a continuity violation both must catch.
    let h3 = synth_header(Hash256::from_bytes([0x05; 32]), 3);
    let h3_hash = dom_crypto::hash::blake2b_256(&raw(&h3));
    let h2 = synth_header(h3_hash, 2);
    assert_same_rejection(&[raw(&h3), raw(&h2)], "backwards");
}

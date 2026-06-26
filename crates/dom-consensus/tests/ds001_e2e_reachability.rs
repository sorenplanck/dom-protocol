//! DS-001 END-TO-END regression guardian (consensus level).
//!
//! Confirms that the REAL consensus entry `validate_range_proofs` — the path a
//! peer's transaction output flows through — SURVIVES malformed-but-exact-size
//! (739-byte) range proofs, repeatedly, on one thread. Before the scratch fix
//! (`dom-crypto` bulletproof_bp: create+destroy the grin scratch per FFI call),
//! reusing one scratch leaked a frame on every malformed-proof verify until a
//! later call SIGSEGV'd. This test drives 6 such peer transactions through
//! `validate_range_proofs` and asserts each is rejected (Err) and the loop runs
//! to completion with no panic/SIGSEGV — i.e. the frame-leak regression stays
//! closed at the consensus boundary, not only at the `bp2_verify` unit level.
//!
//! Run with: `cargo test -p dom-consensus --test ds001_e2e_reachability -- --nocapture`

use dom_consensus::transaction::{Transaction, TransactionOutput};
use dom_consensus::validate_range_proofs;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{blake2b_256_tagged, bp2_prove};

const PROOF_LEN: usize = 739;

fn counter4_proof() -> Vec<u8> {
    let counter: u32 = 4;
    let mut out = Vec::with_capacity(PROOF_LEN);
    let mut block: u32 = 0;
    while out.len() < PROOF_LEN {
        let mut seed = Vec::with_capacity(8);
        seed.extend_from_slice(&counter.to_le_bytes());
        seed.extend_from_slice(&block.to_le_bytes());
        let h = blake2b_256_tagged("DOM:ds001-malformed-probe:v1", &seed);
        out.extend_from_slice(h.as_bytes());
        block += 1;
    }
    out.truncate(PROOF_LEN);
    out
}

#[test]
fn ds001_reaches_consensus_validate_range_proofs() {
    // Valid SEC1 commitment + a malformed exact-size (739-byte) proof.
    let blind = BlindingFactor::from_bytes([0x22u8; 32]).expect("blind");
    let (_p, commitment_sec1) = bp2_prove(7, &blind).expect("prove");
    let commitment = Commitment::from_compressed_bytes(&commitment_sec1).expect("commit parse");

    // One tx with a single malformed-739 output. validate_range_proofs bails on
    // the first Ok(false), so each call performs exactly ONE bp2_verify — exactly
    // what a node does per incoming peer tx. Each call rejects the tx (Err) and,
    // with the per-call scratch fix, releases its FFI scratch frame — so nothing
    // accumulates. We loop to mimic a node processing 6 such peer txs in a row.
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment,
            proof: counter4_proof(),
        }],
        kernels: vec![],
        offset: [0u8; 32],
    };

    for i in 0..6 {
        eprintln!("peer tx #{i}: dom_consensus::validate_range_proofs (malformed-739 output) ...");
        let r = validate_range_proofs(&tx);
        eprintln!("  -> returned {r:?} (tx rejected, frame released — no accumulation)");
        // A malformed proof MUST be rejected; reaching this assert each iteration
        // is itself the regression check (no SIGSEGV terminated the process).
        assert!(
            r.is_err(),
            "iteration {i}: malformed 739-byte proof must be rejected by consensus"
        );
    }
    // Reached only if the consensus FFI path did NOT crash within 6 calls.
    println!("SURVIVED (no crash) after 6 validate_range_proofs calls");
}

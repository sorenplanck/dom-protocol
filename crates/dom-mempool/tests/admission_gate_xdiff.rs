//! dom-shield — XDIFF: cheap-admission-gate parity + digest convergence.
//!
//! ## Gate parity (drift between the two admission entry points)
//!
//! `precheck_cheap_admission_gates` (run at the top of
//! `accept_tx_with_chain_view`) and `accept_validated_tx` (the tail of BOTH
//! entry points) independently enforce the same three crypto-independent gates:
//! duplicate-hash, min-relay-fee, and weight-vs-capacity. The source comment
//! claims they "mirror exactly … (same error messages)", so moving them earlier
//! "changes no verdict". This XDIFF treats the two as separate implementations
//! of one spec and asserts they cannot drift:
//!
//!   * a duplicate gets the same `PolicyRejected("already in mempool")` whether
//!     it arrives via the legacy `accept_tx` path (precheck NOT run) or the
//!     chain-view path (precheck run first);
//!   * a below-floor-fee tx gets the same `PolicyRejected` fee message on both;
//!   * for the duplicate gate specifically, the chain-view path must reject
//!     BEFORE paying for crypto — verified by reusing a known hash with a
//!     tx whose crypto is broken (if precheck drifted to run after crypto we'd
//!     see a different, crypto error).
//!
//! Both gates funnel to the SAME private function for capacity, so we use the
//! two PUBLIC entry points as the differential A/B sides.
//!
//! ## Digest convergence (cross-version / cross-path)
//!
//! `digest()` is the byte-level convergence primitive (RFC-0012 §3.4). XDIFF:
//! two pools that admit the same set through DIFFERENT entry points
//! (legacy `accept_tx` vs `reinject_batch`) must converge to the same digest.

use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{Amount, DomError, KERNEL_FEAT_PLAIN, MIN_RELAY_FEE_RATE, TAG_KERNEL_MSG};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp2_prove, schnorr_sign, SecretKey};
use dom_mempool::Mempool;
use dom_store::utxo::UtxoEntry;

const TEST_CHAIN_ID: [u8; 32] = [0x42; 32];

fn g_commitment() -> Commitment {
    let g = [
        0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    Commitment::from_compressed_bytes(&g).unwrap()
}

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

/// Plain single-output tx (legacy-path valid). weight 24.
fn make_tx(fee: u64, seed: u8) -> (Transaction, [u8; 32]) {
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment: Commitment::commit(1_000, &scalar(seed)),
            proof: vec![seed; 100],
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess: g_commitment(),
            excess_signature: [seed; 65],
        }],
        offset: [0u8; 32],
    };
    let mut hash = [0u8; 32];
    hash[0..8].copy_from_slice(&fee.to_le_bytes());
    hash[8] = seed;
    (tx, hash)
}

/// Fully valid signed spending tx + its canonical UTXO entry (chain-view path).
fn valid_signed_tx(fee: u64, seed: u8) -> (Transaction, [u8; 32], UtxoEntry) {
    let input_value = 10_000 + fee;
    let input_blinding = scalar(seed);
    let output_value = input_value - fee;
    let kernel_blinding = scalar(seed.wrapping_add(80));
    let output_blinding = input_blinding
        .add(&kernel_blinding)
        .expect("output blinding");
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = bp2_prove(output_value, &output_blinding).expect("range proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &TEST_CHAIN_ID).expect("kernel sig");
    let tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess,
            excess_signature: sig.to_bytes(),
        }],
        offset: [0u8; 32],
    };
    let mut hash = [0u8; 32];
    hash[0..8].copy_from_slice(&fee.to_le_bytes());
    hash[8] = seed;
    let entry = UtxoEntry {
        block_height: 1,
        is_coinbase: false,
        proof: vec![],
    };
    (tx, hash, entry)
}

fn accept_chain_view(
    pool: &mut Mempool,
    tx: Transaction,
    hash: [u8; 32],
    input: [u8; 33],
    entry: UtxoEntry,
) -> Result<(), DomError> {
    pool.accept_tx_with_chain_view(tx, hash, 0, 100, TEST_CHAIN_ID, 10, move |c| {
        if *c == input {
            Ok(Some(entry.clone()))
        } else {
            Ok(None)
        }
    })
}

// ── XDIFF-1: duplicate-gate verdict parity (legacy vs chain-view) ──────────────

/// A duplicate hash is rejected with the SAME `PolicyRejected("already in
/// mempool")` on BOTH the legacy `accept_tx` path (precheck not run — gate fires
/// inside accept_validated_tx) and the chain-view path (precheck fires first).
/// Drift here would mean the two gate copies diverged.
#[test]
fn xdiff_duplicate_gate_same_verdict_both_paths() {
    // Side A: legacy path.
    let mut pool_a = Mempool::new();
    let (tx, hash) = make_tx(MIN_RELAY_FEE_RATE * 100, 0x01);
    pool_a
        .accept_tx(tx.clone(), hash, 0)
        .expect("first accept (legacy)");
    let err_a = pool_a
        .accept_tx(tx, hash, 1)
        .expect_err("dup must reject (legacy)");

    // Side B: chain-view path.
    let mut pool_b = Mempool::new();
    let (vtx, vhash, ventry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 100, 0x02);
    let vinput = *vtx.inputs[0].commitment.as_bytes();
    accept_chain_view(&mut pool_b, vtx.clone(), vhash, vinput, ventry.clone())
        .expect("first accept (chain-view)");
    let err_b = accept_chain_view(&mut pool_b, vtx, vhash, vinput, ventry)
        .expect_err("dup must reject (chain-view)");

    for (label, err) in [("legacy", &err_a), ("chain-view", &err_b)] {
        match err {
            DomError::PolicyRejected(msg) => assert!(
                msg.contains("already in mempool"),
                "{label}: expected duplicate message, got: {msg}"
            ),
            other => panic!("{label}: expected PolicyRejected duplicate, got {other:?}"),
        }
    }
}

// ── XDIFF-2: min-fee-gate verdict parity (legacy vs chain-view) ────────────────

/// A below-floor-fee tx is rejected with a `PolicyRejected` fee message on BOTH
/// paths. On the chain-view path the fee gate must fire from precheck (before
/// crypto), so we deliberately also break the signature: if the verdict were a
/// crypto `Invalid` instead of the fee `PolicyRejected`, the gates drifted.
#[test]
fn xdiff_min_fee_gate_same_verdict_both_paths() {
    // Side A: legacy path, fee below floor (fee 1 → fee_rate 0).
    let mut pool_a = Mempool::new();
    let (tx, hash) = make_tx(1, 0x03);
    let err_a = pool_a
        .accept_tx(tx, hash, 0)
        .expect_err("below-floor reject (legacy)");

    // Side B: chain-view path, below-floor fee AND a broken signature.
    let mut pool_b = Mempool::new();
    let (mut vtx, vhash, ventry) = valid_signed_tx(1, 0x04);
    vtx.kernels[0].excess_signature[64] ^= 0x01; // corrupt sig
    let vinput = *vtx.inputs[0].commitment.as_bytes();
    let err_b = accept_chain_view(&mut pool_b, vtx, vhash, vinput, ventry)
        .expect_err("below-floor reject (chain-view)");

    for (label, err) in [("legacy", &err_a), ("chain-view", &err_b)] {
        match err {
            DomError::PolicyRejected(msg) => assert!(
                msg.contains("MIN_RELAY_FEE_RATE") || msg.contains("fee rate"),
                "{label}: expected fee message, got: {msg}"
            ),
            other => panic!("{label}: expected fee PolicyRejected (gate parity); got {other:?}"),
        }
    }
}

// ── XDIFF-3: precheck dedup runs BEFORE crypto (no verdict drift to crypto) ─────

/// On the chain-view path, a known hash reused by a tx with BROKEN crypto must
/// be rejected as a DUPLICATE (cheap), not as a crypto `Invalid`. If precheck
/// drifted to after `validate_transaction`, this would surface a signature
/// error instead — the exact regression the FABLE5-001 reorder prevents.
#[test]
fn xdiff_precheck_dedup_precedes_crypto() {
    let mut pool = Mempool::new();
    let (good, hash, gentry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x05);
    let ginput = *good.inputs[0].commitment.as_bytes();
    accept_chain_view(&mut pool, good, hash, ginput, gentry).expect("first valid accept");

    // Different tx, broken signature, SAME hash.
    let (mut bad, _bh, bentry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x06);
    bad.kernels[0].excess_signature[64] ^= 0x01;
    let binput = *bad.inputs[0].commitment.as_bytes();
    let err = accept_chain_view(&mut pool, bad, hash, binput, bentry)
        .expect_err("dup-hash bad-crypto must reject");
    match err {
        DomError::PolicyRejected(msg) => assert!(
            msg.contains("already in mempool"),
            "expected cheap dedup BEFORE crypto, got: {msg}"
        ),
        other => panic!("precheck drifted after crypto: got {other:?} instead of dedup"),
    }
}

// ── XDIFF-4: digest convergence across admission paths ─────────────────────────

/// The same admitted set, fed through DIFFERENT public entry points
/// (`accept_tx` one-by-one vs `reinject_batch`), must converge to the SAME
/// 32-byte digest. This is the cross-path convergence guarantee.
#[test]
fn xdiff_digest_converges_across_admission_paths() {
    let txs: Vec<(Transaction, [u8; 32])> = (1u8..=6)
        .map(|s| make_tx(MIN_RELAY_FEE_RATE * 100 + s as u64, s))
        .collect();

    // Path A: one-by-one accept_tx.
    let mut pool_a = Mempool::new();
    for (tx, hash) in &txs {
        pool_a.accept_tx(tx.clone(), *hash, 0).expect("accept_tx");
    }

    // Path B: reinject_batch (sorts then accept_tx internally).
    let mut pool_b = Mempool::new();
    let batch = txs
        .iter()
        .map(|(tx, hash)| (tx.clone(), *hash, 0u64))
        .collect::<Vec<_>>();
    let results = pool_b.reinject_batch(batch);
    assert!(results.iter().all(|(_, r)| r.is_ok()), "all must admit");

    assert_eq!(pool_a.all_hashes(), pool_b.all_hashes(), "same set");
    assert_eq!(
        pool_a.digest(),
        pool_b.digest(),
        "digest must converge across admission paths"
    );
}

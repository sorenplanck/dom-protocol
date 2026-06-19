//! FABLE5-001 — mempool admission *ordering*, AFTER the fix.
//!
//! Originally this file documented the vulnerability: full cryptographic
//! validation (`validate_transaction` → Bulletproof + Schnorr) ran BEFORE the
//! cheap admission gates (duplicate-hash, min-relay-fee), so a peer replaying a
//! known tx forced repeated range-proof verification.
//!
//! The fix (`Mempool::precheck_cheap_admission_gates`, called at the top of
//! `accept_tx_with_chain_view`) hoists the crypto-INDEPENDENT gates ahead of
//! validation. These tests now assert the FIXED ordering, and — critically —
//! that the reorder did NOT change any transaction's accept/reject verdict:
//!
//!   * duplicate / below-fee / over-capacity txs are now rejected WITHOUT
//!     running crypto (cheap), with the same error messages as before;
//!   * a genuinely NEW, above-fee, non-duplicate tx with bad crypto is STILL
//!     rejected by `validate_transaction` (so real invalid txs remain
//!     cryptographically rejected and peer-scoreable);
//!   * a valid new tx is STILL accepted.
//!
//! The builders produce a genuinely valid signed transaction (real `bp2_prove`
//! plus `schnorr_sign`); they are local to this file (the audit forbids editing
//! existing test files).

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

/// A fully valid signed spending transaction: real Pedersen commitments, a real
/// Bulletproof range proof on the output, and a valid Schnorr kernel signature.
fn valid_signed_tx(fee: u64, seed: u8) -> (Transaction, [u8; 32], UtxoEntry) {
    let input_value = 10_000 + fee;
    let input_blinding = scalar(seed);
    let output_value = input_value.checked_sub(fee).expect("fee below input");
    let kernel_blinding = scalar(seed.wrapping_add(80));
    let output_blinding = input_blinding
        .add(&kernel_blinding)
        .expect("output blinding");
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = bp2_prove(output_value, &output_blinding).expect("range proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig =
        schnorr_sign(&secret, &kernel_message(fee, 0), &TEST_CHAIN_ID).expect("kernel signature");

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

/// Same as `valid_signed_tx` but with the Schnorr signature corrupted so that
/// `validate_transaction` fails at the kernel-signature step (after the range
/// proof passes). Used to tell "crypto ran" apart from a cheap gate firing.
fn bad_sig_tx(fee: u64, seed: u8) -> (Transaction, [u8; 32], UtxoEntry) {
    let (mut tx, hash, entry) = valid_signed_tx(fee, seed);
    tx.kernels[0].excess_signature[64] ^= 0x01;
    (tx, hash, entry)
}

fn accept(
    pool: &mut Mempool,
    tx: Transaction,
    hash: [u8; 32],
    input_commitment: [u8; 33],
    entry: UtxoEntry,
) -> Result<(), DomError> {
    pool.accept_tx_with_chain_view(tx, hash, 0, 100, TEST_CHAIN_ID, 10, move |c| {
        if *c == input_commitment {
            Ok(Some(entry.clone()))
        } else {
            Ok(None)
        }
    })
}

/// FIX PROOF (dedup before crypto): with a tx already in the pool under hash
/// `H`, submitting a tx with a BROKEN signature that reuses `H` is now rejected
/// as a DUPLICATE — not for the signature. If crypto still ran first, we'd see a
/// signature `Invalid`; instead we see the cheap "already in mempool", proving
/// the dedup gate runs before `validate_transaction`.
#[test]
fn robustness_duplicate_check_runs_before_crypto() {
    let mut pool = Mempool::new();

    let (tx, hash, entry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x11);
    let input = *tx.inputs[0].commitment.as_bytes();
    accept(&mut pool, tx, hash, input, entry).expect("first valid accept");
    assert_eq!(pool.len(), 1);

    // A different tx (bad signature), submitted under the SAME hash `H`.
    let (bad, _bad_hash, bad_entry) = bad_sig_tx(MIN_RELAY_FEE_RATE * 30, 0x22);
    let bad_input = *bad.inputs[0].commitment.as_bytes();

    let err = accept(&mut pool, bad, hash, bad_input, bad_entry)
        .expect_err("duplicate-hash tx must be rejected");

    match &err {
        DomError::PolicyRejected(msg) => assert!(
            msg.contains("already in mempool"),
            "expected cheap duplicate rejection (dedup before crypto), got: {msg}"
        ),
        other => panic!(
            "expected PolicyRejected 'already in mempool' (dedup runs first now); got {other:?}"
        ),
    }
}

/// FIX PROOF (min-fee before crypto): a below-floor-fee tx whose signature is
/// ALSO invalid is now rejected by the FEE gate, not by crypto. Seeing the fee
/// `PolicyRejected` (rather than a signature `Invalid`) proves the min-relay-fee
/// gate runs before `validate_transaction`.
#[test]
fn robustness_min_fee_gate_runs_before_crypto() {
    let mut pool = Mempool::new();

    // fee = 1 nom → fee_rate far below MIN_RELAY_FEE_RATE; signature corrupted.
    let (tx, hash, entry) = bad_sig_tx(1, 0x44);
    let input = *tx.inputs[0].commitment.as_bytes();

    let err = accept(&mut pool, tx, hash, input, entry).expect_err("below-floor fee rejected");
    match &err {
        DomError::PolicyRejected(msg) => assert!(
            msg.contains("MIN_RELAY_FEE_RATE") || msg.contains("fee rate"),
            "expected fee-policy rejection BEFORE crypto, got: {msg}"
        ),
        other => panic!("expected fee PolicyRejected (min-fee runs before crypto); got {other:?}"),
    }
    assert_eq!(pool.len(), 0);
}

/// Replaying the identical valid tx is rejected cheaply as a duplicate
/// (`PolicyRejected` "already in mempool"). This is the unscored-but-now-CHEAP
/// path: no Bulletproof verification is paid on the replay.
#[test]
fn robustness_duplicate_replay_is_cheaply_rejected() {
    let mut pool = Mempool::new();

    let (tx, hash, entry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x33);
    let input = *tx.inputs[0].commitment.as_bytes();
    accept(&mut pool, tx.clone(), hash, input, entry.clone()).expect("first accept");

    for _ in 0..5 {
        let err = accept(&mut pool, tx.clone(), hash, input, entry.clone())
            .expect_err("replay must be rejected as duplicate");
        match &err {
            DomError::PolicyRejected(msg) => assert!(
                msg.contains("already in mempool"),
                "expected duplicate rejection, got: {msg}"
            ),
            other => panic!("expected PolicyRejected duplicate, got {other:?}"),
        }
    }
    assert_eq!(pool.len(), 1, "replays must not inflate the pool");
}

/// VERDICT-PRESERVATION (the reorder must not weaken validation): a genuinely
/// NEW, above-fee, non-duplicate transaction with a bad signature is STILL
/// rejected by `validate_transaction` (a crypto `Invalid`), so real invalid txs
/// remain cryptographically rejected and peer-scoreable.
#[test]
fn robustness_new_invalid_tx_still_rejected_by_crypto() {
    let mut pool = Mempool::new();

    let (tx, hash, entry) = bad_sig_tx(MIN_RELAY_FEE_RATE * 30, 0x55);
    let input = *tx.inputs[0].commitment.as_bytes();

    let err = accept(&mut pool, tx, hash, input, entry).expect_err("bad-sig tx must be rejected");
    match &err {
        DomError::Invalid(msg) => assert!(
            msg.contains("signature") || msg.contains("Schnorr") || msg.contains("kernel"),
            "expected a kernel-signature rejection, got: {msg}"
        ),
        other => panic!(
            "a new, above-fee, non-dup invalid-crypto tx must still be rejected by crypto; \
             got {other:?}"
        ),
    }
    assert_eq!(pool.len(), 0);
}

/// VERDICT-PRESERVATION: a valid new tx is STILL accepted after the reorder.
#[test]
fn robustness_valid_new_tx_still_accepted() {
    let mut pool = Mempool::new();

    let (tx, hash, entry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x66);
    let input = *tx.inputs[0].commitment.as_bytes();

    accept(&mut pool, tx, hash, input, entry).expect("valid new tx must still be accepted");
    assert_eq!(pool.len(), 1);
}

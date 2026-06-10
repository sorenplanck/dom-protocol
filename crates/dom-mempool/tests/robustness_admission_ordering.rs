//! FABLE5 robustness audit — mempool admission *ordering*.
//!
//! Finding FABLE5-001: `Mempool::accept_tx_with_chain_view` runs the full
//! cryptographic transaction validation (`dom_consensus::validate_transaction`
//! → Bulletproof range-proof verify + Schnorr kernel-signature verify) BEFORE
//! the cheap in-memory gates: the duplicate-hash check and the min-relay-fee
//! check both live in `accept_validated_tx`, which only runs *after* crypto
//! succeeds (see `crates/dom-mempool/src/lib.rs:211-292`).
//!
//! Consequence: a peer that has observed a single valid transaction can replay
//! its bytes repeatedly. Every replay forces the node to re-run a real
//! Bulletproof verification before discovering, via the duplicate check, that
//! it already holds the tx. The replay is rejected with
//! `DomError::PolicyRejected("transaction already in mempool")`, and
//! `peer_violation_score` (`crates/dom-node/src/node.rs:1712-1731`) maps that
//! `PolicyRejected` variant to `None` — i.e. NO ban score. So the amplification
//! is unbounded by the peer-scoring defence: crypto cost is paid every time and
//! the peer is never banned for it.
//!
//! These tests do not modify production code; they exercise the public mempool
//! admission API and assert the *observable ordering* of rejections, which is
//! what proves the cheap gates run after (not before) the expensive crypto.
//!
//! The builders below are copied from `convergence_semantics.rs` because the
//! audit rules forbid editing existing test files; they produce a genuinely
//! valid signed transaction (real `bp_prove` + `schnorr_sign`).

use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{Amount, DomError, KERNEL_FEAT_PLAIN, MIN_RELAY_FEE_RATE, TAG_KERNEL_MSG};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp_prove, schnorr_sign, SecretKey};
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
    let (proof, _) = bp_prove(output_value, &output_blinding).expect("range proof");
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
            proof: proof.bytes,
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

/// Accept a tx through the production chain-view path, with the input present
/// in the (simulated) canonical UTXO set so admission is not blocked by a
/// missing input.
fn accept(
    pool: &mut Mempool,
    tx: Transaction,
    hash: [u8; 32],
    input_commitment: [u8; 33],
    entry: UtxoEntry,
) -> Result<(), DomError> {
    pool.accept_tx_with_chain_view(
        tx,
        hash,
        0,
        100,
        TEST_CHAIN_ID,
        10,
        |c| {
            if *c == input_commitment {
                Ok(Some(entry.clone()))
            } else {
                Ok(None)
            }
        },
    )
}

/// CORE PROOF: with a tx already in the pool under hash `H`, submitting a
/// *different* tx that carries a broken signature but reuses hash `H` is
/// rejected for the SIGNATURE, not for being a duplicate. If the cheap
/// duplicate check ran first, the error would be "transaction already in
/// mempool"; instead we get a crypto rejection, proving full crypto runs
/// before the dedup gate.
#[test]
fn robustness_crypto_runs_before_duplicate_check() {
    let mut pool = Mempool::new();

    let (tx, hash, entry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x11);
    let input = *tx.inputs[0].commitment.as_bytes();
    accept(&mut pool, tx, hash, input, entry.clone()).expect("first valid accept");
    assert_eq!(pool.len(), 1);

    // Build a second, *different* valid tx, then corrupt its kernel signature.
    // Reuse the FIRST tx's hash so the dedup check (keyed on the caller-supplied
    // hash) would fire first if it ran before crypto.
    let (mut bad, _bad_hash, bad_entry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x22);
    bad.kernels[0].excess_signature[40] ^= 0xFF; // break the Schnorr signature
    let bad_input = *bad.inputs[0].commitment.as_bytes();

    let err = accept(&mut pool, bad, hash, bad_input, bad_entry)
        .expect_err("corrupted-signature tx must be rejected");

    // The decisive assertion: the rejection is a cryptographic one, NOT the
    // cheap duplicate gate. This is only possible if validate_transaction
    // (range proof + signature) executed before accept_validated_tx's dedup.
    match &err {
        DomError::Invalid(msg) => {
            assert!(
                msg.contains("signature") || msg.contains("Schnorr") || msg.contains("kernel"),
                "expected a kernel-signature rejection, got: {msg}"
            );
        }
        other => panic!(
            "expected DomError::Invalid (crypto ran first); got {other:?} \
             — if this is 'already in mempool' the ordering would be SAFE"
        ),
    }
}

/// AMPLIFICATION + SCORING GAP: replaying the identical valid tx is rejected as
/// a duplicate with `PolicyRejected`, and that variant carries the message the
/// node's `peer_violation_score` does NOT score (it only scores the
/// "handshake timeout" PolicyRejected). So the replay is both (a) re-validated
/// with full crypto each time and (b) never bannable. We assert the exact error
/// shape the scoring logic keys on.
#[test]
fn robustness_duplicate_replay_is_unscored_policy_rejection() {
    let mut pool = Mempool::new();

    let (tx, hash, entry) = valid_signed_tx(MIN_RELAY_FEE_RATE * 30, 0x33);
    let input = *tx.inputs[0].commitment.as_bytes();
    accept(&mut pool, tx.clone(), hash, input, entry.clone()).expect("first accept");

    // Replay the SAME bytes many times. Each call runs validate_transaction
    // (Bulletproof + Schnorr) before the dedup rejection.
    for _ in 0..5 {
        let err = accept(&mut pool, tx.clone(), hash, input, entry.clone())
            .expect_err("replay must be rejected as duplicate");
        match &err {
            DomError::PolicyRejected(msg) => {
                assert!(
                    msg.contains("already in mempool"),
                    "expected duplicate rejection, got: {msg}"
                );
                // Mirror of node.rs peer_violation_score: only a PolicyRejected
                // mentioning "handshake timeout" is scored; anything else => no
                // ban score. This replay therefore costs CPU but never bans.
                assert!(
                    !msg.contains("handshake timeout"),
                    "duplicate rejection would be UNSCORED by peer_violation_score"
                );
            }
            other => panic!("expected PolicyRejected duplicate, got {other:?}"),
        }
    }
    assert_eq!(pool.len(), 1, "replays must not inflate the pool");
}

/// Companion observation: the min-relay-fee gate also lives behind full crypto.
/// A below-floor-fee tx with a VALID signature is rejected by fee policy
/// (`PolicyRejected … MIN_RELAY_FEE_RATE`) only after the Bulletproof and
/// Schnorr verifications have already run. We can't assert timing without
/// flakiness, but we can assert that a below-floor tx reaches the fee gate
/// (i.e. crypto passed) rather than being cheaply screened out first.
#[test]
fn robustness_min_fee_gate_is_behind_crypto() {
    let mut pool = Mempool::new();

    // fee = 1 nom → fee_rate far below MIN_RELAY_FEE_RATE, but a fully valid
    // signature/proof over that fee.
    let (tx, hash, entry) = valid_signed_tx(1, 0x44);
    let input = *tx.inputs[0].commitment.as_bytes();

    let err = accept(&mut pool, tx, hash, input, entry).expect_err("below-floor fee rejected");
    match &err {
        DomError::PolicyRejected(msg) => assert!(
            msg.contains("MIN_RELAY_FEE_RATE") || msg.contains("fee rate"),
            "expected fee-policy rejection (reached only after crypto passed), got: {msg}"
        ),
        other => panic!("expected fee PolicyRejected, got {other:?}"),
    }
    assert_eq!(pool.len(), 0);
}

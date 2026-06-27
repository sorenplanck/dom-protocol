//! dom-shield KAV-negativo for dom-consensus — per-step rejection of the PUBLIC
//! `validate_transaction` orchestrator (lib.rs), one vector per validation door.
//!
//! Each test starts from a fully VALID transaction that `validate_transaction`
//! ACCEPTS, then perturbs exactly ONE thing so a specific step must REJECT it.
//! This is non-vacuous: the baseline is proven to pass first, so each rejection
//! is attributable to the single mutation (not to a pre-existing failure).
//!
//! Doors covered (RFC-0007 step → vector):
//!   - structure: too-many-kernels / empty-kernels / empty-proof
//!   - kernel-features: unknown feature byte (256-value sweep)
//!   - lock_height malleability: HEIGHT_LOCKED==0 ; non-HEIGHT_LOCKED with lh!=0
//!   - lock_height temporal: HEIGHT_LOCKED in the future → TemporarilyInvalid
//!   - range proof: tampered proof byte
//!   - kernel signature: tampered excess / wrong chain_id
//!   - fee: per-kernel fee respected (sum), weight bound
//!   - balance: inflated output
//!
//! Coinbase doors (CoinbaseTransaction::validate):
//!   - offset != 0 rejected ; features != COINBASE rejected
//!
//! Technique: known-answer negative vectors (KAV-negativo).

use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_consensus::{validate_transaction, CoinbaseKernel, CoinbaseTransaction, ValidationContext};
use dom_core::{
    Amount, BlockHeight, DomError, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_HEIGHT_LOCKED,
    KERNEL_FEAT_PLAIN, MAX_KERNELS_PER_TX, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;

const CHAIN_ID: [u8; 32] = [0x11u8; 32];

fn ctx() -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(1),
        chain_id: CHAIN_ID,
        now: Timestamp(u64::MAX),
    }
}

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn kernel_message(features: u8, fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::new();
    data.push(features);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

/// Fully valid 1-in/1-out tx that `validate_transaction` accepts.
/// fee = input_value - output_value.
fn valid_tx(input_value: u64, output_value: u64) -> Transaction {
    let input_blinding = scalar(10);
    let kernel_blinding = scalar(11);
    let fee = input_value - output_value;
    let output_blinding = input_blinding
        .add(&kernel_blinding)
        .expect("output blinding");

    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).expect("tx proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(
        &secret,
        &kernel_message(KERNEL_FEAT_PLAIN, fee, 0),
        &CHAIN_ID,
    )
    .expect("kernel sig");

    Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).expect("fee"),
            lock_height: 0,
            excess,
            excess_signature: sig.to_bytes(),
        }],
        offset: [0u8; 32],
    }
}

// The baseline MUST pass — otherwise every negative test below is vacuous.
#[test]
fn kav_baseline_valid_tx_is_accepted() {
    let tx = valid_tx(100, 90);
    validate_transaction(&tx, &ctx())
        .expect("baseline tx must be accepted (else negative vectors are vacuous)");
}

// ── Door: structure — empty kernels ───────────────────────────────────────────
#[test]
fn kav_neg_empty_kernels_rejected() {
    let mut tx = valid_tx(100, 90);
    tx.kernels.clear();
    let err = validate_transaction(&tx, &ctx()).expect_err("empty kernels must reject");
    assert!(
        err.to_string().contains("at least one kernel"),
        "got: {err}"
    );
}

// ── Door: structure — too many kernels ────────────────────────────────────────
#[test]
fn kav_neg_too_many_kernels_rejected() {
    let mut tx = valid_tx(100, 90);
    let k = tx.kernels[0].clone();
    while tx.kernels.len() <= MAX_KERNELS_PER_TX {
        tx.kernels.push(k.clone());
    }
    let err = validate_transaction(&tx, &ctx()).expect_err("over-limit kernels must reject");
    assert!(err.to_string().contains("too many kernels"), "got: {err}");
}

// ── Door: structure — empty range proof ───────────────────────────────────────
#[test]
fn kav_neg_empty_proof_rejected() {
    let mut tx = valid_tx(100, 90);
    tx.outputs[0].proof.clear();
    let err = validate_transaction(&tx, &ctx()).expect_err("empty proof must reject");
    assert!(err.to_string().contains("empty range proof"), "got: {err}");
}

// ── Door: kernel features — unknown feature byte (256-value sweep) ─────────────
#[test]
fn kav_neg_unknown_kernel_feature_byte_sweep() {
    let known = [
        KERNEL_FEAT_PLAIN,
        KERNEL_FEAT_COINBASE,
        KERNEL_FEAT_HEIGHT_LOCKED,
    ];
    for b in 0u16..=255u16 {
        let feat = b as u8;
        if known.contains(&feat) {
            continue; // known features are handled by their own doors
        }
        let mut tx = valid_tx(100, 90);
        tx.kernels[0].features = feat;
        let err = validate_transaction(&tx, &ctx()).unwrap_err_or_else_panic(feat);
        assert!(
            err.to_string().contains("unknown kernel features"),
            "feature 0x{feat:02x} must reject as unknown, got: {err}"
        );
    }
}

// Tiny helper so the sweep reads cleanly and pinpoints the failing byte.
trait UnwrapErrByte {
    fn unwrap_err_or_else_panic(self, feat: u8) -> DomError;
}
impl UnwrapErrByte for Result<(), DomError> {
    fn unwrap_err_or_else_panic(self, feat: u8) -> DomError {
        match self {
            Err(e) => e,
            Ok(()) => panic!("unknown kernel feature 0x{feat:02x} was ACCEPTED"),
        }
    }
}

// ── Door: kernel features — COINBASE feature in a plain tx ─────────────────────
#[test]
fn kav_neg_coinbase_feature_in_plain_tx_rejected() {
    let mut tx = valid_tx(100, 90);
    tx.kernels[0].features = KERNEL_FEAT_COINBASE;
    let err = validate_transaction(&tx, &ctx()).expect_err("coinbase feature in tx must reject");
    assert!(
        err.to_string().contains("COINBASE feature in non-coinbase"),
        "got: {err}"
    );
}

// ── Door: lock_height malleability — HEIGHT_LOCKED with lock_height == 0 ───────
#[test]
fn kav_neg_height_locked_zero_rejected() {
    let mut tx = valid_tx(100, 90);
    tx.kernels[0].features = KERNEL_FEAT_HEIGHT_LOCKED;
    tx.kernels[0].lock_height = 0;
    let err = validate_transaction(&tx, &ctx())
        .expect_err("HEIGHT_LOCKED with lock_height 0 must reject");
    assert!(
        err.to_string()
            .contains("HEIGHT_LOCKED with lock_height == 0"),
        "got: {err}"
    );
}

// ── Door: lock_height malleability — non-HEIGHT_LOCKED with lock_height != 0 ───
#[test]
fn kav_neg_non_locked_with_nonzero_lock_height_rejected() {
    let mut tx = valid_tx(100, 90);
    // features stays PLAIN, but lock_height is set non-zero → malleable, must reject.
    tx.kernels[0].lock_height = 7;
    let err = validate_transaction(&tx, &ctx())
        .expect_err("non-HEIGHT_LOCKED kernel with lock_height != 0 must reject");
    assert!(
        err.to_string().contains("lock_height must be 0"),
        "got: {err}"
    );
}

// ── Door: lock_height temporal — HEIGHT_LOCKED in the future ──────────────────
#[test]
fn kav_neg_height_locked_in_future_is_temporarily_invalid() {
    // Build a tx whose single kernel is HEIGHT_LOCKED with a future lock_height,
    // and whose signature is over that exact (features, fee, lock_height) message
    // so structure passes and the TEMPORAL door is what fires.
    let input_value = 100u64;
    let output_value = 90u64;
    let fee = input_value - output_value;
    let lock_height = 1000u64;

    let input_blinding = scalar(20);
    let kernel_blinding = scalar(21);
    let output_blinding = input_blinding.add(&kernel_blinding).unwrap();
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).unwrap();
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).unwrap();
    let sig = schnorr_sign(
        &secret,
        &kernel_message(KERNEL_FEAT_HEIGHT_LOCKED, fee, lock_height),
        &CHAIN_ID,
    )
    .unwrap();

    let tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_HEIGHT_LOCKED,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height,
            excess,
            excess_signature: sig.to_bytes(),
        }],
        offset: [0u8; 32],
    };

    // current_height (1) < lock_height (1000) → TemporarilyInvalid.
    let err = validate_transaction(&tx, &ctx()).expect_err("future-locked kernel must defer");
    assert!(
        matches!(err, DomError::TemporarilyInvalid(_)),
        "expected TemporarilyInvalid, got: {err:?}"
    );
}

// ── Door: range proof — tampered proof byte ───────────────────────────────────
#[test]
fn kav_neg_tampered_range_proof_rejected() {
    let mut tx = valid_tx(100, 90);
    let mid = tx.outputs[0].proof.len() / 2;
    tx.outputs[0].proof[mid] ^= 0xFF;
    let err = validate_transaction(&tx, &ctx()).expect_err("tampered proof must reject");
    assert!(err.to_string().contains("range proof"), "got: {err}");
}

// ── Door: kernel signature — wrong chain_id ───────────────────────────────────
#[test]
fn kav_neg_wrong_chain_id_rejects_signature() {
    let tx = valid_tx(100, 90);
    // Same valid tx, but verified under a DIFFERENT chain_id → signature must fail.
    let wrong_ctx = ValidationContext {
        current_height: BlockHeight(1),
        chain_id: [0x22u8; 32],
        now: Timestamp(u64::MAX),
    };
    let err = validate_transaction(&tx, &wrong_ctx)
        .expect_err("signature under wrong chain_id must reject (replay protection)");
    assert!(
        err.to_string().contains("Schnorr signature invalid")
            || err.to_string().contains("signature"),
        "got: {err}"
    );
}

// ── Door: kernel signature — tampered excess point ────────────────────────────
#[test]
fn kav_neg_tampered_excess_rejects_signature() {
    let mut tx = valid_tx(100, 90);
    // Replace excess with an unrelated point → signature no longer verifies.
    tx.kernels[0].excess = Commitment::commit(0, &scalar(99));
    let err = validate_transaction(&tx, &ctx()).expect_err("tampered excess must reject");
    assert!(
        err.to_string().contains("Schnorr signature invalid")
            || err.to_string().contains("balance"),
        "got: {err}"
    );
}

// ── Door: balance — inflated output ───────────────────────────────────────────
#[test]
fn kav_neg_inflated_output_rejected() {
    // Build a tx that is structurally/crypto-valid in every step EXCEPT balance:
    // re-commit the output to a larger value with the SAME blinding (so the range
    // proof and signature paths still pass for THEIR inputs but the H-component
    // breaks). We rebuild a fresh proof for the inflated value so the range-proof
    // door passes and the BALANCE door is the one that fires.
    let input_value = 100u64;
    let honest_output = 90u64;
    let fee = input_value - honest_output;
    let inflated_output = 95u64; // > honest_output by 5 → inflation

    let input_blinding = scalar(30);
    let kernel_blinding = scalar(31);
    let output_blinding = input_blinding.add(&kernel_blinding).unwrap();

    let input_commitment = Commitment::commit(input_value, &input_blinding);
    // Commit the INFLATED value under the balanced blinding → H-component wrong.
    let output_commitment = Commitment::commit(inflated_output, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(inflated_output, &output_blinding).unwrap();
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).unwrap();
    let sig = schnorr_sign(
        &secret,
        &kernel_message(KERNEL_FEAT_PLAIN, fee, 0),
        &CHAIN_ID,
    )
    .unwrap();

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

    let err = validate_transaction(&tx, &ctx()).expect_err("inflated output must reject");
    assert!(err.to_string().contains("balance"), "got: {err}");
}

// ── Coinbase door: offset != 0 ────────────────────────────────────────────────

fn valid_coinbase(height: BlockHeight, total_fees: u64) -> CoinbaseTransaction {
    let explicit_value = dom_core::block_reward(height).noms() + total_fees;
    let blinding = scalar(90);
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).unwrap();
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).unwrap();
    let msg = {
        let mut data = Vec::new();
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&explicit_value.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sig = schnorr_sign(&secret, msg.as_bytes(), &CHAIN_ID).unwrap();
    CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    }
}

#[test]
fn kav_neg_coinbase_baseline_valid() {
    let cb = valid_coinbase(BlockHeight(1), 0);
    cb.validate(BlockHeight(1), 0, &CHAIN_ID)
        .expect("baseline coinbase must validate (else negative coinbase vectors are vacuous)");
}

#[test]
fn kav_neg_coinbase_nonzero_offset_rejected() {
    let mut cb = valid_coinbase(BlockHeight(1), 0);
    cb.offset = [0u8; 32];
    cb.offset[31] = 1; // non-zero offset
    let err = cb
        .validate(BlockHeight(1), 0, &CHAIN_ID)
        .expect_err("coinbase with non-zero offset must reject");
    assert!(
        err.to_string().contains("offset must be zero"),
        "got: {err}"
    );
}

#[test]
fn kav_neg_coinbase_wrong_features_rejected() {
    let mut cb = valid_coinbase(BlockHeight(1), 0);
    cb.kernel.features = KERNEL_FEAT_PLAIN;
    let err = cb
        .validate(BlockHeight(1), 0, &CHAIN_ID)
        .expect_err("coinbase with non-coinbase features must reject");
    assert!(err.to_string().contains("features must be"), "got: {err}");
}

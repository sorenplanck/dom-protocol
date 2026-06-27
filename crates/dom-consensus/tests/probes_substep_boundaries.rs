//! dom-shield PROBES for dom-consensus — sub-step boundary documentation.
//!
//! These probes document the EXACT boundary of what `validate_block` /
//! `validate_transaction` enforce in ISOLATION, versus what the higher layer
//! (`dom-chain::connect_block`) enforces. They are NOT bug claims by themselves;
//! they pin the contract so a future refactor that silently moves a check is a
//! RED test.
//!
//! PROBE FIX-006 (#[ignore], by-design note): `validate_block` alone does NOT
//!   call validate_pow / median-time-past / future-timestamp. PoW is enforced in
//!   dom-chain::connect_block, not here. The probe asserts validate_block accepts
//!   a block carrying a ZERO PoW (all other fields valid) to document that the
//!   PoW door lives one layer up. Marked #[ignore] so it never gates the suite —
//!   it is executable documentation, runnable on demand.
//!
//! PROBE offset-canonical asymmetry (may RED): the BLOCK header offset is
//!   canonical-checked (block.rs::validate_kernel_offset_canonical, reached via
//!   validate_block→validate_header_syntax), but a per-TRANSACTION `tx.offset`
//!   is NOT canonical-checked inside validate_transaction (transaction.rs:~205
//!   parses it as raw 32 bytes; the balance equation reduces it mod n). This
//!   probe feeds tx.offset = {n, n+1, 0xFF..FF} and asserts a DETERMINISTIC
//!   result. It does NOT assert rejection (that would be a merit decision); it
//!   asserts the two runs over identical bytes agree — catching any
//!   NON-DETERMINISM in the offset path.

use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_consensus::{
    compute_block_pmmr_roots, validate_block, validate_transaction, Block, CoinbaseKernel,
    CoinbaseTransaction, ValidationContext,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    PROTOCOL_VERSION, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::CompactTarget;
use primitive_types::U256;

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
    BlindingFactor::from_bytes(bytes).expect("scalar")
}

fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::new();
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

fn build_coinbase(total_fees: u64) -> CoinbaseTransaction {
    let explicit_value = dom_core::block_reward(BlockHeight(1)).noms() + total_fees;
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

/// Valid spend tx with an explicit offset. The output blinding includes the
/// offset so the tx-level balance equation closes (offset·G term).
fn spend_tx_with_offset(offset: [u8; 32]) -> Transaction {
    let input_value = 100u64;
    let output_value = 90u64;
    let fee = input_value - output_value;
    let input_blinding = scalar(10);
    let kernel_blinding = scalar(11);
    // output = input + kernel + offset (so balance closes with this offset)
    let offset_bf = BlindingFactor::from_bytes(offset).ok();
    let mut output_blinding = input_blinding.add(&kernel_blinding).unwrap();
    if let Some(ob) = &offset_bf {
        output_blinding = output_blinding.add(ob).unwrap();
    }
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).unwrap();
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).unwrap();
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &CHAIN_ID).unwrap();
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
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess,
            excess_signature: sig.to_bytes(),
        }],
        offset,
    }
}

// ── PROBE FIX-006: validate_block ignores PoW in isolation ────────────────────

/// by-design: PoW is enforced in dom-chain::connect_block, NOT in validate_block.
/// This probe documents that validate_block ACCEPTS a structurally/economically
/// valid block whose ProofOfWork is all-zero (no real work). If a future change
/// pulls PoW validation INTO validate_block, this test would start failing and
/// must be revisited (the sub-step boundary moved). Ignored by default.
#[test]
#[ignore = "by-design: PoW enforced in dom-chain::connect_block, not validate_block"]
fn probe_fix006_validate_block_ignores_zero_pow() {
    let tx = spend_tx_with_offset([0u8; 32]);
    let total_fees = tx.total_fee().unwrap();
    let coinbase = build_coinbase(total_fees);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, std::slice::from_ref(&tx)).unwrap();
    let block = Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(1),
            prev_hash: Hash256::from_bytes([0x55; 32]),
            timestamp: Timestamp(1_704_067_260),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32], // tx offset is zero → aggregate is zero
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::from(2u64),
            // ZERO proof of work — no real RandomX work done.
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions: vec![tx],
    };

    // Documents the boundary: validate_block alone does NOT reject zero PoW.
    validate_block(&block, &ctx())
        .expect("validate_block in isolation must ignore PoW (enforced one layer up)");
}

// ── PROBE: tx.offset canonical-check asymmetry (determinism, may RED) ──────────

/// secp256k1 group order n (big-endian).
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

fn n_plus_one() -> [u8; 32] {
    // n is given big-endian; tx.offset is consumed as raw 32 bytes by the balance
    // path (FieldBytes are big-endian for k256). Build n+1 big-endian.
    let mut v = SECP256K1_N;
    for i in (0..32).rev() {
        let (s, carry) = v[i].overflowing_add(1);
        v[i] = s;
        if !carry {
            break;
        }
    }
    v
}

/// PROBE: feed a per-tx `offset` that is non-canonical (== n, == n+1, == 0xFF..FF)
/// and assert validate_transaction is DETERMINISTIC over identical bytes. Unlike
/// the block header offset (which IS canonical-checked in validate_header_syntax),
/// the tx offset is parsed as raw bytes and reduced mod n in the balance equation.
/// We do NOT assert acceptance/rejection (a merit decision); we assert the result
/// is identical across two runs — catching any non-determinism in the offset path.
///
/// NOTE: this MAY surface that a non-canonical tx.offset is silently accepted-or-
/// reduced where the block header would Malformed-reject — an asymmetry recorded
/// for the FIX-QUEUE. The determinism assertion itself is the hard guarantee.
#[test]
fn probe_tx_offset_noncanonical_is_deterministic() {
    let offsets: [[u8; 32]; 3] = [
        SECP256K1_N,  // == n
        n_plus_one(), // == n+1
        [0xFFu8; 32], // == 2^256-1 (>> n)
    ];

    for off in offsets {
        let tx = spend_tx_with_offset(off);
        let r1 = validate_transaction(&tx, &ctx()).map_err(|e| e.to_string());
        let r2 = validate_transaction(&tx, &ctx()).map_err(|e| e.to_string());
        assert_eq!(
            r1, r2,
            "validate_transaction over identical tx.offset bytes must be deterministic \
             (offset = {off:02x?})"
        );
    }
}

/// Companion: the BLOCK header offset path DOES canonical-reject n / n+1 / 0xFF
/// (validate_header_syntax → validate_kernel_offset_canonical). This pins the
/// asymmetry: header offset = Malformed, tx offset = (no canonical gate). If the
/// header check were ever removed, this is RED.
#[test]
fn probe_block_header_offset_noncanonical_is_rejected() {
    let tx = spend_tx_with_offset([0u8; 32]);
    let total_fees = tx.total_fee().unwrap();
    let coinbase = build_coinbase(total_fees);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, std::slice::from_ref(&tx)).unwrap();

    for bad_offset in [SECP256K1_N, n_plus_one(), [0xFFu8; 32]] {
        let block = Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                height: BlockHeight(1),
                prev_hash: Hash256::from_bytes([0x55; 32]),
                timestamp: Timestamp(1_704_067_260),
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset: bad_offset,
                target: CompactTarget(0x1f00_ffff),
                total_difficulty: U256::from(2u64),
                pow: ProofOfWork {
                    nonce: 0,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase: coinbase.clone(),
            transactions: vec![tx.clone()],
        };
        let err = validate_block(&block, &ctx())
            .expect_err("non-canonical block header offset must reject");
        assert!(
            matches!(err, dom_core::DomError::Malformed(_)),
            "expected Malformed for non-canonical header offset {bad_offset:02x?}, got: {err:?}"
        );
    }
}

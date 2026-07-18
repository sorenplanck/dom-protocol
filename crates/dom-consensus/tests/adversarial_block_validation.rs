use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, validate_block, validate_transaction, Block, CoinbaseKernel,
    CoinbaseTransaction, Transaction, TransactionInput, TransactionKernel, TransactionOutput,
    ValidationContext,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    PROTOCOL_VERSION, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::{
    hash::blake2b_256_tagged,
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_pow::CompactTarget;
use primitive_types::U256;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn g_point() -> Commitment {
    let g = [
        0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    Commitment::from_compressed_bytes(&g).unwrap()
}

fn ctx() -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(1),
        chain_id: [0x11; 32],
        now: Timestamp(u64::MAX),
    }
}

fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

fn build_coinbase(total_fees: u64, chain_id: &[u8; 32]) -> CoinbaseTransaction {
    let explicit_value = dom_core::block_reward(BlockHeight(1)).noms() + total_fees;
    let blinding = scalar(90);
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let msg = {
        let mut data = Vec::with_capacity(1 + 8);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&explicit_value.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("coinbase sig");
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

#[derive(Clone)]
struct ValidSpendFixture {
    tx: Transaction,
    output_commitment: Commitment,
    output_value: u64,
    output_blinding: BlindingFactor,
}

fn build_valid_spend_tx(
    input_value: u64,
    input_blinding: BlindingFactor,
    output_value: u64,
    kernel_blinding: BlindingFactor,
    offset_blinding: Option<BlindingFactor>,
) -> ValidSpendFixture {
    let fee = input_value
        .checked_sub(output_value)
        .expect("output must not exceed input");
    let mut output_blinding = input_blinding
        .add(&kernel_blinding)
        .expect("output blinding add");
    let offset = if let Some(offset) = offset_blinding.clone() {
        output_blinding = output_blinding.add(&offset).expect("offset add");
        *offset.as_bytes()
    } else {
        [0u8; 32]
    };
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).expect("tx proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &ctx().chain_id).expect("kernel sig");

    ValidSpendFixture {
        tx: Transaction {
            inputs: vec![TransactionInput {
                commitment: input_commitment,
            }],
            outputs: vec![TransactionOutput {
                commitment: output_commitment.clone(),
                proof,
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).expect("fee"),
                lock_height: 0,
                excess,
                excess_signature: sig.to_bytes(),
            }],
            offset,
        },
        output_commitment,
        output_value,
        output_blinding,
    }
}

fn aggregate_tx_offsets(transactions: &[Transaction]) -> [u8; 32] {
    use k256::{elliptic_curve::PrimeField, Scalar};
    let mut total = Scalar::ZERO;
    for tx in transactions {
        let field = k256::FieldBytes::from(tx.offset);
        let scalar = Scalar::from_repr(field);
        if scalar.is_some().into() {
            total += scalar.unwrap();
        }
    }
    total.to_repr().into()
}

fn valid_block_with_transactions(transactions: Vec<Transaction>) -> Block {
    let total_fees = transactions.iter().map(|tx| tx.total_fee().unwrap()).sum();
    let coinbase = build_coinbase(total_fees, &ctx().chain_id);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(BlockHeight(1), &coinbase, &transactions).expect("pmmr roots");
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(1),
            prev_hash: Hash256::from_bytes([0x55; 32]),
            timestamp: Timestamp(1_704_067_260),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: aggregate_tx_offsets(&transactions),
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::from(2u64),
            pow: ProofOfWork {
                nonce: 7,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions,
    }
}

#[test]
fn consensus_rejects_invalid_aggregate_balance() {
    let tx = build_valid_spend_tx(75, scalar(10), 60, scalar(11), Some(scalar(12))).tx;
    let mut block = valid_block_with_transactions(vec![tx]);
    block.header.total_kernel_offset = [0u8; 32];

    let err = validate_block(&block, &ctx()).expect_err("wrong aggregate offset must reject");
    assert!(
        err.to_string().contains("aggregate block balance"),
        "expected aggregate-balance rejection, got: {err}"
    );
}

#[test]
fn consensus_rejects_invalid_cut_through() {
    let tx1 = build_valid_spend_tx(50, scalar(31), 40, scalar(32), None);
    let tx2_fixture = build_valid_spend_tx(
        tx1.output_value,
        tx1.output_blinding.clone(),
        30,
        scalar(33),
        None,
    );
    let mut tx2 = tx2_fixture.tx;
    tx2.inputs[0].commitment = tx1.output_commitment;

    let block = valid_block_with_transactions(vec![tx1.tx, tx2]);
    let err = validate_block(&block, &ctx()).expect_err("non-canonical cut-through must reject");
    assert!(
        err.to_string().contains("cut-through"),
        "expected cut-through rejection, got: {err}"
    );
}

#[test]
fn consensus_rejects_invalid_reward_fee_equation() {
    let tx = build_valid_spend_tx(100, scalar(5), 100, scalar(6), None);
    let coinbase = build_coinbase(7, &ctx().chain_id);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(BlockHeight(1), &coinbase, std::slice::from_ref(&tx.tx))
            .expect("pmmr roots");
    let block = Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(1),
            prev_hash: Hash256::from_bytes([0x55; 32]),
            timestamp: Timestamp(1_704_067_260),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: aggregate_tx_offsets(std::slice::from_ref(&tx.tx)),
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::from(2u64),
            pow: ProofOfWork {
                nonce: 8,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions: vec![tx.tx],
    };

    let err = validate_block(&block, &ctx()).expect_err("coinbase overpay must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("explicit_value") || msg.contains("reward") || msg.contains("fees"),
        "expected reward/fee rejection, got: {msg}"
    );
}

#[test]
fn consensus_rejects_invalid_kernel_excess_relation() {
    let mut tx = build_valid_spend_tx(100, scalar(40), 90, scalar(41), None).tx;
    tx.kernels[0].excess = g_point();
    let block = valid_block_with_transactions(vec![tx]);

    let err = validate_block(&block, &ctx()).expect_err("tampered kernel excess must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("Schnorr signature invalid") || msg.contains("bad excess point"),
        "expected kernel/excess rejection, got: {msg}"
    );
}

#[test]
fn consensus_rejects_valid_transactions_composing_invalid_block() {
    let tx1 = build_valid_spend_tx(70, scalar(50), 60, scalar(51), None);
    let tx2_fixture = build_valid_spend_tx(
        tx1.output_value,
        tx1.output_blinding.clone(),
        55,
        scalar(52),
        None,
    );
    let mut tx2 = tx2_fixture.tx;
    tx2.inputs[0].commitment = tx1.output_commitment.clone();

    validate_transaction(&tx1.tx, &ctx()).expect("tx1 must be individually valid");
    validate_transaction(&tx2, &ctx()).expect("tx2 must be individually valid");

    let block = valid_block_with_transactions(vec![tx1.tx, tx2]);
    let err = validate_block(&block, &ctx()).expect_err("block composition must still reject");
    assert!(
        err.to_string().contains("cut-through"),
        "expected block composition cut-through rejection, got: {err}"
    );
}

#[test]
fn consensus_rejects_tampered_body_with_plausible_header() {
    let tx1 = build_valid_spend_tx(120, scalar(60), 100, scalar(61), None).tx;
    let tx2 = build_valid_spend_tx(90, scalar(62), 80, scalar(63), None).tx;
    let valid = valid_block_with_transactions(vec![tx1.clone(), tx2.clone()]);
    validate_block(&valid, &ctx()).expect("control block must be valid");

    let mut tampered = valid.clone();
    tampered.transactions.swap(0, 1);

    let err = validate_block(&tampered, &ctx())
        .expect_err("body reorder under an unchanged header must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("PMMR") || msg.contains("root"),
        "expected PMMR/root mismatch, got: {msg}"
    );
}

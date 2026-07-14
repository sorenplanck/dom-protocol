use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, validate_block, validate_block_transactions, validate_transaction,
    Block, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionInput, TransactionKernel,
    TransactionOutput, ValidationContext,
};
use dom_core::{
    block_reward, Amount, BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE,
    KERNEL_FEAT_PLAIN, MAX_BLOCK_TXS, MAX_BLOCK_WEIGHT, MAX_INPUTS_PER_TX, MAX_KERNELS_PER_TX,
    MAX_OUTPUTS_PER_TX, MAX_TX_WEIGHT, PROTOCOL_VERSION, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
    WEIGHT_COINBASE_KERNEL, WEIGHT_INPUT, WEIGHT_KERNEL, WEIGHT_OUTPUT,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::CompactTarget;
use dom_serialization::{DomDeserialize, DomSerialize};
use primitive_types::U256;

const CHAIN_ID: [u8; 32] = [0x11; 32];

fn scalar(seed: u16) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[30..32].copy_from_slice(&seed.max(1).to_be_bytes());
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn ctx() -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(1),
        chain_id: CHAIN_ID,
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

fn independent_tx_weight(inputs: usize, outputs: usize, kernels: usize) -> u32 {
    let total = (inputs as u64)
        .checked_mul(u64::from(WEIGHT_INPUT))
        .and_then(|v| {
            (outputs as u64)
                .checked_mul(u64::from(WEIGHT_OUTPUT))
                .and_then(|outputs| v.checked_add(outputs))
        })
        .and_then(|v| {
            (kernels as u64)
                .checked_mul(u64::from(WEIGHT_KERNEL))
                .and_then(|kernels| v.checked_add(kernels))
        })
        .expect("test counts must not overflow independent arithmetic");
    u32::try_from(total).expect("test weight must fit u32")
}

fn independent_block_weight(transactions: &[Transaction]) -> u32 {
    let tx_weight = transactions.iter().fold(0u64, |acc, tx| {
        acc.checked_add(u64::from(independent_tx_weight(
            tx.inputs.len(),
            tx.outputs.len(),
            tx.kernels.len(),
        )))
        .expect("test block weight overflow")
    });
    let coinbase = u64::from(WEIGHT_COINBASE_KERNEL) + u64::from(WEIGHT_OUTPUT);
    u32::try_from(coinbase + tx_weight).expect("test block weight must fit u32")
}

fn sum_blindings(blindings: &[BlindingFactor]) -> BlindingFactor {
    let mut total = blindings[0].clone();
    for blinding in &blindings[1..] {
        total = total.add(blinding).expect("blinding sum");
    }
    total
}

fn negate_blinding(blinding: &BlindingFactor) -> BlindingFactor {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;

    let field = k256::FieldBytes::from(*blinding.as_bytes());
    let scalar = Scalar::from_repr(field).expect("valid scalar");
    let negated = -scalar;
    BlindingFactor::from_bytes(negated.to_repr().into()).expect("nonzero negated scalar")
}

fn signed_weight_tx(
    num_inputs: usize,
    num_outputs: usize,
    num_kernels: usize,
    seed: u16,
) -> Transaction {
    assert!(num_inputs > 0);
    assert!(num_kernels > 0);
    let input_value = 1_000_000u64;
    let input_blindings: Vec<_> = (0..num_inputs)
        .map(|i| scalar(seed + i as u16 + 1))
        .collect();
    let input_sum = sum_blindings(&input_blindings);
    let total_fee = if num_outputs == 0 {
        input_value
            .checked_mul(num_inputs as u64)
            .expect("input total")
    } else {
        1_000u64
    };
    let kernel_blindings: Vec<_> = if num_outputs == 0 {
        let target_kernel_sum = negate_blinding(&input_sum);
        if num_kernels == 1 {
            vec![target_kernel_sum]
        } else {
            let mut blindings: Vec<_> = (0..num_kernels - 1)
                .map(|i| scalar(seed + 700 + i as u16))
                .collect();
            let previous_sum = sum_blindings(&blindings);
            blindings.push(
                target_kernel_sum
                    .sub_nonzero(&previous_sum)
                    .expect("last kernel blinding"),
            );
            blindings
        }
    } else {
        (0..num_kernels)
            .map(|i| scalar(seed + 700 + i as u16))
            .collect()
    };
    let kernel_sum = sum_blindings(&kernel_blindings);

    let mut output_blindings: Vec<BlindingFactor> = Vec::with_capacity(num_outputs);
    let mut outputs = Vec::with_capacity(num_outputs);
    if num_outputs > 0 {
        let target_output_blinding = input_sum.add(&kernel_sum).expect("target output blind");
        let output_total = input_value
            .checked_mul(num_inputs as u64)
            .and_then(|v| v.checked_sub(total_fee))
            .expect("output total");
        let mut remaining_value = output_total;
        for i in 0..num_outputs {
            let is_last = i + 1 == num_outputs;
            let value = if is_last {
                remaining_value
            } else {
                let share = output_total / num_outputs as u64;
                remaining_value = remaining_value.checked_sub(share).expect("remaining value");
                share
            };
            let blinding = if is_last {
                if output_blindings.is_empty() {
                    target_output_blinding.clone()
                } else {
                    let previous_sum = sum_blindings(&output_blindings);
                    target_output_blinding
                        .sub_nonzero(&previous_sum)
                        .expect("last output blinding")
                }
            } else {
                scalar(seed + 2_000 + i as u16)
            };
            let commitment = Commitment::commit(value, &blinding);
            let (proof, _) = dom_crypto::bp2_prove(value, &blinding).expect("range proof");
            output_blindings.push(blinding);
            outputs.push(TransactionOutput { commitment, proof });
        }
    }

    let inputs = input_blindings
        .iter()
        .map(|blinding| TransactionInput {
            commitment: Commitment::commit(input_value, blinding),
        })
        .collect();
    let mut remaining_fee = total_fee;
    let kernels = kernel_blindings
        .iter()
        .enumerate()
        .map(|(i, kernel_blinding)| {
            let fee = if i + 1 == num_kernels {
                remaining_fee
            } else {
                remaining_fee = remaining_fee.checked_sub(1).expect("remaining fee");
                1
            };
            let excess = Commitment::commit(0, kernel_blinding);
            let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
            let sig =
                schnorr_sign(&secret, &kernel_message(fee, 0), &CHAIN_ID).expect("kernel sig");
            TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).expect("fee"),
                lock_height: 0,
                excess,
                excess_signature: sig.to_bytes(),
            }
        })
        .collect();

    Transaction {
        inputs,
        outputs,
        kernels,
        offset: [0u8; 32],
    }
}

fn signed_coinbase(total_fees: u64) -> CoinbaseTransaction {
    let explicit_value = block_reward(BlockHeight(1)).noms() + total_fees;
    let blinding = scalar(60_000);
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let mut data = Vec::with_capacity(1 + 8);
    data.push(KERNEL_FEAT_COINBASE);
    data.extend_from_slice(&explicit_value.to_le_bytes());
    let msg = blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data);
    let sig = schnorr_sign(&secret, msg.as_bytes(), &CHAIN_ID).expect("coinbase sig");
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

fn weight_only_tx(
    num_inputs: usize,
    num_outputs: usize,
    num_kernels: usize,
    seed: u8,
) -> Transaction {
    let inputs = (0..num_inputs)
        .map(|i| TransactionInput {
            commitment: Commitment::commit(
                1_000 + i as u64,
                &scalar(u16::from(seed) * 100 + i as u16 + 1),
            ),
        })
        .collect();
    let outputs = (0..num_outputs)
        .map(|i| TransactionOutput {
            commitment: Commitment::commit(
                2_000 + i as u64,
                &scalar(u16::from(seed) * 200 + i as u16 + 1),
            ),
            proof: Vec::new(),
        })
        .collect();
    let kernels = (0..num_kernels)
        .map(|i| TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(0).expect("zero fee"),
            lock_height: 0,
            excess: Commitment::commit(0, &scalar(u16::from(seed) * 300 + i as u16 + 1)),
            excess_signature: [seed; 65],
        })
        .collect();
    Transaction {
        inputs,
        outputs,
        kernels,
        offset: [0u8; 32],
    }
}

fn block_with_transactions(transactions: Vec<Transaction>) -> Block {
    let total_fees = transactions
        .iter()
        .try_fold(0u64, |acc, tx| {
            acc.checked_add(tx.total_fee().expect("tx fee"))
        })
        .expect("total fees");
    let coinbase = signed_coinbase(total_fees);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &transactions).expect("pmmr roots");
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(1),
            prev_hash: Hash256::from_bytes([0x55; 32]),
            timestamp: Timestamp(1_704_067_260),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
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
fn block_weight_production_paths_use_one_normative_formula() {
    let empty_tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        kernels: vec![],
        offset: [0u8; 32],
    };
    assert_eq!(empty_tx.weight(), 0);
    assert_eq!(empty_tx.weight(), independent_tx_weight(0, 0, 0));

    let one_in_one_out_one_kernel = signed_weight_tx(1, 1, 1, 10);
    assert_eq!(
        one_in_one_out_one_kernel.weight(),
        WEIGHT_INPUT + WEIGHT_OUTPUT + WEIGHT_KERNEL
    );
    validate_transaction(&one_in_one_out_one_kernel, &ctx()).expect("valid control tx");

    let below_limit_txs = vec![
        signed_weight_tx(1, 1, 1, 100),
        signed_weight_tx(1, 2, 1, 200),
    ];
    let below_limit = block_with_transactions(below_limit_txs.clone());
    assert_eq!(
        below_limit.weight().expect("below-limit block weight"),
        independent_block_weight(&below_limit_txs)
    );

    let exact_block_limit_txs: Vec<_> = (0..9)
        .map(|i| weight_only_tx(7, 190, 1, i + 1))
        .chain(std::iter::once(weight_only_tx(5, 189, 1, 20)))
        .collect();
    let exact_block_limit = block_with_transactions(exact_block_limit_txs.clone());
    assert_eq!(
        exact_block_limit
            .weight()
            .expect("exact block limit weight"),
        MAX_BLOCK_WEIGHT
    );

    let limit_plus_one_txs: Vec<_> = (0..9)
        .map(|i| weight_only_tx(7, 190, 1, i + 31))
        .chain(std::iter::once(weight_only_tx(6, 189, 1, 50)))
        .collect();
    let limit_plus_one = block_with_transactions(limit_plus_one_txs);
    assert_eq!(
        limit_plus_one.weight().expect("limit plus one weight"),
        MAX_BLOCK_WEIGHT + 1
    );
    let plus_one_err = validate_block(&limit_plus_one, &ctx())
        .expect_err("full block validation must reject limit plus one");
    assert!(
        matches!(plus_one_err, DomError::Invalid(ref msg) if msg.contains("block weight")),
        "expected limit-plus-one weight rejection, got {plus_one_err}"
    );

    let exact_non_coinbase_weight_txs: Vec<_> =
        (0..10).map(|i| weight_only_tx(7, 190, 1, i + 61)).collect();
    let exact_non_coinbase_weight = exact_non_coinbase_weight_txs.iter().fold(0u32, |acc, tx| {
        acc.checked_add(tx.weight()).expect("tx weight sum")
    });
    assert_eq!(exact_non_coinbase_weight, MAX_BLOCK_WEIGHT);

    let overweight_block = block_with_transactions(exact_non_coinbase_weight_txs.clone());
    assert_eq!(
        overweight_block.weight().expect("overweight block weight"),
        MAX_BLOCK_WEIGHT + WEIGHT_COINBASE_KERNEL + WEIGHT_OUTPUT
    );
    let encoded = overweight_block.to_bytes().expect("serialize block");
    let decoded = Block::from_bytes(&encoded).expect("deserialize block");
    assert_eq!(
        decoded.weight().expect("decoded block weight"),
        overweight_block.weight().expect("original block weight")
    );

    let total_fees = exact_non_coinbase_weight_txs
        .iter()
        .try_fold(0u64, |acc, tx| {
            acc.checked_add(tx.total_fee().expect("fee"))
        })
        .expect("fees");
    let pre_fix_result = validate_block_transactions(
        &exact_non_coinbase_weight_txs,
        &overweight_block.coinbase,
        &ctx(),
        BlockHeight(1),
        total_fees,
    );
    assert!(
        pre_fix_result.is_err(),
        "validate_block_transactions accepted a body whose full block weight is {}",
        overweight_block.weight().expect("block weight")
    );

    let full_block_err = validate_block(&overweight_block, &ctx())
        .expect_err("full block validation must reject limit plus coinbase weight");
    assert!(
        matches!(full_block_err, DomError::Invalid(ref msg) if msg.contains("block weight")),
        "expected full block weight rejection, got {full_block_err}"
    );

    let coinbase_only = block_with_transactions(vec![]);
    assert_eq!(
        coinbase_only.weight().expect("coinbase-only weight"),
        WEIGHT_COINBASE_KERNEL + WEIGHT_OUTPUT
    );

    let max_bounded_tx_weight =
        independent_tx_weight(MAX_INPUTS_PER_TX, MAX_OUTPUTS_PER_TX, MAX_KERNELS_PER_TX);
    assert!(max_bounded_tx_weight > MAX_TX_WEIGHT);
    let max_bounded_block_weight = u64::from(WEIGHT_COINBASE_KERNEL + WEIGHT_OUTPUT)
        + (MAX_BLOCK_TXS as u64) * u64::from(max_bounded_tx_weight);
    assert!(max_bounded_block_weight < u64::from(u32::MAX));
}

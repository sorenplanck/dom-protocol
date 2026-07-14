#![allow(missing_docs)]

use crate::{
    block::validate_header_syntax, block_weight, validate_block_transactions, BlockHeader,
    CoinbaseTransaction, Transaction, ValidationContext,
};
use dom_core::{DomError, MAX_BLOCK_TXS, MAX_BLOCK_WEIGHT};
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub coinbase: CoinbaseTransaction,
    pub transactions: Vec<Transaction>,
}

impl DomSerialize for Block {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        self.header.serialize(w)?;
        self.coinbase.serialize(w)?;
        w.write_list(&self.transactions)?;
        Ok(())
    }
}

impl DomDeserialize for Block {
    const MIN_SERIALIZED_SIZE: usize =
        BlockHeader::MIN_SERIALIZED_SIZE + CoinbaseTransaction::MIN_SERIALIZED_SIZE + 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            header: BlockHeader::deserialize(r)?,
            coinbase: CoinbaseTransaction::deserialize(r)?,
            transactions: r.read_list(MAX_BLOCK_TXS)?,
        })
    }
}

impl Block {
    pub fn weight(&self) -> Result<u32, DomError> {
        block_weight(&self.coinbase, &self.transactions)
    }

    pub fn total_fees(&self) -> Result<u64, DomError> {
        let mut total: u64 = 0;
        for tx in &self.transactions {
            let fee = tx.total_fee()?;
            total = total
                .checked_add(fee)
                .ok_or_else(|| DomError::Invalid("block fee overflow".into()))?;
        }
        Ok(total)
    }
}

pub fn validate_block(block: &Block, ctx: &ValidationContext) -> Result<(), DomError> {
    validate_header_syntax(&block.header)?;

    let block_weight = block.weight()?;
    if block_weight > MAX_BLOCK_WEIGHT {
        return Err(DomError::Invalid(format!(
            "block weight {block_weight} > MAX_BLOCK_WEIGHT {MAX_BLOCK_WEIGHT}"
        )));
    }

    if block.transactions.len() > MAX_BLOCK_TXS {
        return Err(DomError::Invalid(format!(
            "too many transactions: {} > {}",
            block.transactions.len(),
            MAX_BLOCK_TXS
        )));
    }

    let mut seen_inputs: HashSet<[u8; 33]> = HashSet::new();
    for tx in &block.transactions {
        for input in &tx.inputs {
            if !seen_inputs.insert(*input.commitment.as_bytes()) {
                return Err(DomError::Invalid(
                    "duplicate input commitment across block".into(),
                ));
            }
        }
    }

    let mut seen_outputs: HashSet<[u8; 33]> = HashSet::new();
    if !seen_outputs.insert(*block.coinbase.output.commitment.as_bytes()) {
        return Err(DomError::Invalid(
            "duplicate output commitment in block".into(),
        ));
    }
    for tx in &block.transactions {
        for output in &tx.outputs {
            if !seen_outputs.insert(*output.commitment.as_bytes()) {
                return Err(DomError::Invalid(
                    "duplicate output commitment across block".into(),
                ));
            }
        }
    }

    // RFC-0010 §3.3: Block must be in canonical cut-through form.
    // A commitment appearing as both a block output and a block input means
    // cut-through was not applied — reject unconditionally.
    for tx in &block.transactions {
        for input in &tx.inputs {
            if seen_outputs.contains(input.commitment.as_bytes()) {
                return Err(DomError::Invalid(
                    "block-level cut-through violation: input commitment matches a block output"
                        .into(),
                ));
            }
        }
    }

    let total_fees = block.total_fees()?;

    validate_block_transactions(
        &block.transactions,
        &block.coinbase,
        ctx,
        block.header.height,
        total_fees,
    )?;

    // Aggregate block balance equation (RFC-0008 block-level).
    // Derivation: summing all per-tx balance equations plus coinbase cancels
    // the fee terms, yielding:
    //   Sum(all_outputs) − Sum(all_inputs)
    //     = Sum(all_excesses) + total_kernel_offset·G + block_reward·H
    //
    // where block_reward is the base subsidy (not including fees), because
    // the fee terms cancel between regular transactions and the coinbase.
    {
        let all_outputs: Vec<_> = std::iter::once(&block.coinbase.output.commitment)
            .chain(
                block
                    .transactions
                    .iter()
                    .flat_map(|tx| tx.outputs.iter().map(|o| &o.commitment)),
            )
            .cloned()
            .collect();
        let all_inputs: Vec<_> = block
            .transactions
            .iter()
            .flat_map(|tx| tx.inputs.iter().map(|i| &i.commitment))
            .cloned()
            .collect();
        let all_excesses: Vec<_> = std::iter::once(&block.coinbase.kernel.excess)
            .chain(
                block
                    .transactions
                    .iter()
                    .flat_map(|tx| tx.kernels.iter().map(|k| &k.excess)),
            )
            .cloned()
            .collect();
        let base_reward = dom_core::block_reward(block.header.height).noms();

        let valid = dom_crypto::verify_block_balance_equation(
            &all_outputs,
            &all_inputs,
            &all_excesses,
            &block.header.total_kernel_offset,
            base_reward,
        )?;
        if !valid {
            return Err(DomError::Invalid(
                "aggregate block balance equation does not hold".into(),
            ));
        }
    }

    // RFC-0007 step 17: validate PMMR roots
    crate::validate_pmmr_roots(block)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_block_pmmr_roots;
    use crate::transaction::{
        CoinbaseKernel, TransactionInput, TransactionKernel, TransactionOutput,
    };
    use dom_core::{
        Amount, BlockHeight, Hash256, Timestamp, INITIAL_BLOCK_REWARD, KERNEL_FEAT_COINBASE,
        KERNEL_FEAT_PLAIN, PROTOCOL_VERSION, WEIGHT_COINBASE_KERNEL, WEIGHT_OUTPUT,
    };
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::keys::SecretKey;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::schnorr_sign;
    use dom_pow::CompactTarget;
    use dom_serialization::{DomDeserialize, DomSerialize};
    use primitive_types::U256;

    fn g_point() -> Commitment {
        let g = [
            0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        Commitment::from_compressed_bytes(&g).unwrap()
    }

    fn h_point() -> Commitment {
        let h = [
            0x02u8, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ];
        Commitment::from_compressed_bytes(&h).unwrap()
    }

    fn dummy_header() -> BlockHeader {
        BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight::GENESIS,
            prev_hash: Hash256::ZERO,
            timestamp: Timestamp(1_704_067_200),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::one(),
            pow: crate::block::ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        }
    }

    fn dummy_coinbase() -> CoinbaseTransaction {
        CoinbaseTransaction {
            output: TransactionOutput {
                commitment: g_point(),
                proof: vec![0u8; 100],
            },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value: INITIAL_BLOCK_REWARD,
                excess: g_point(),
                excess_signature: [0u8; 65],
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
        *blake2b_256_tagged(dom_core::TAG_KERNEL_MSG, &data).as_bytes()
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
            blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &data)
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

    fn build_valid_spend_tx(
        input_value: u64,
        input_blinding: BlindingFactor,
        output_value: u64,
        kernel_blinding: BlindingFactor,
        offset_blinding: Option<BlindingFactor>,
    ) -> ValidSpendFixture {
        let fee = input_value
            .checked_sub(output_value)
            .expect("output must be <= input");
        let mut output_blinding = input_blinding
            .add(&kernel_blinding)
            .expect("output blinding add");
        let offset_bytes = if let Some(offset) = offset_blinding.clone() {
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
        let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &[0x11; 32]).expect("kernel sig");

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
                offset: offset_bytes,
            },
            output_commitment,
            output_value,
            output_blinding,
        }
    }

    /// Sum all tx offsets as scalars mod n (aggregate block kernel offset).
    fn aggregate_tx_offsets(transactions: &[Transaction]) -> [u8; 32] {
        use k256::{elliptic_curve::PrimeField, Scalar};
        let mut total = Scalar::ZERO;
        for tx in transactions {
            let fb = k256::FieldBytes::from(tx.offset);
            let s_ct = Scalar::from_repr(fb);
            if s_ct.is_some().into() {
                total += s_ct.unwrap();
            }
        }
        total.to_repr().into()
    }

    fn valid_block_with_transactions(transactions: Vec<Transaction>) -> Block {
        let total_fees = transactions
            .iter()
            .map(|tx| tx.total_fee().expect("fee"))
            .sum();
        let coinbase = build_coinbase(total_fees, &[0x11; 32]);
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, &transactions).expect("pmmr roots");
        let total_kernel_offset = aggregate_tx_offsets(&transactions);
        Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                height: BlockHeight(1),
                prev_hash: Hash256::from_bytes([0x55; 32]),
                timestamp: Timestamp(1_704_067_260),
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset,
                target: CompactTarget(0x1f00_ffff),
                total_difficulty: U256::from(2u64),
                pow: crate::block::ProofOfWork {
                    nonce: 7,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase,
            transactions,
        }
    }

    #[test]
    fn block_serialization_roundtrip() {
        let block = Block {
            header: dummy_header(),
            coinbase: dummy_coinbase(),
            transactions: vec![],
        };
        let bytes = block.to_bytes().unwrap();
        let block2 = Block::from_bytes(&bytes).unwrap();
        assert_eq!(block, block2);
    }

    #[test]
    fn empty_block_weight_is_coinbase_only() {
        let block = Block {
            header: dummy_header(),
            coinbase: dummy_coinbase(),
            transactions: vec![],
        };
        let expected = dummy_coinbase().kernel.weight() + WEIGHT_OUTPUT;
        assert_eq!(block.weight().unwrap(), expected);
    }

    #[test]
    fn empty_block_weight_below_max() {
        let block = Block {
            header: dummy_header(),
            coinbase: dummy_coinbase(),
            transactions: vec![],
        };
        assert!(block.weight().unwrap() < MAX_BLOCK_WEIGHT);
    }

    /// The coinbase contributes exactly one kernel + one output to block weight.
    /// Counting the coinbase kernel twice was a spec-drift bug: the validator
    /// over-counted by `WEIGHT_COINBASE_KERNEL` relative to the miner's budget
    /// reservation, so a full block could exceed `MAX_BLOCK_WEIGHT`.
    #[test]
    fn empty_block_weight_counts_coinbase_kernel_once() {
        let block = Block {
            header: dummy_header(),
            coinbase: dummy_coinbase(),
            transactions: vec![],
        };
        // The canonical coinbase kernel weight is WEIGHT_COINBASE_KERNEL; an
        // empty block is exactly that kernel plus the single coinbase output.
        assert_eq!(
            dummy_coinbase().kernel.weight(),
            WEIGHT_COINBASE_KERNEL,
            "coinbase kernel weight must be the canonical constant"
        );
        assert_eq!(
            block.weight().unwrap(),
            WEIGHT_COINBASE_KERNEL + WEIGHT_OUTPUT,
            "empty block must count the coinbase kernel exactly once"
        );
    }

    /// Consensus/miner consistency: the weight the validator charges for the
    /// coinbase (an empty block) must equal the weight the miner reserves before
    /// selecting transactions. The miner computes its reservation as
    /// `WEIGHT_COINBASE_KERNEL + WEIGHT_OUTPUT` (see dom-node/src/miner.rs:560),
    /// leaving `MAX_BLOCK_WEIGHT - that` as the tx budget. If these diverge, the
    /// miner can pack txs that push a block over MAX_BLOCK_WEIGHT (spec-drift).
    #[test]
    fn empty_block_weight_matches_miner_coinbase_reservation() {
        let block = Block {
            header: dummy_header(),
            coinbase: dummy_coinbase(),
            transactions: vec![],
        };
        // Replicated from dom-node::miner (dom-consensus cannot depend on dom-node).
        let miner_coinbase_reservation = WEIGHT_COINBASE_KERNEL + WEIGHT_OUTPUT;
        let miner_tx_budget = MAX_BLOCK_WEIGHT - miner_coinbase_reservation;

        let empty_block_weight = block.weight().unwrap();
        assert_eq!(
            empty_block_weight, miner_coinbase_reservation,
            "validator coinbase weight must equal miner coinbase reservation"
        );
        assert_eq!(
            MAX_BLOCK_WEIGHT - empty_block_weight,
            miner_tx_budget,
            "tx budget left after an empty block must match the miner's tx budget"
        );
    }

    #[test]
    fn block_duplicate_input_cross_tx_rejected() {
        let make_tx = |commit: Commitment| Transaction {
            inputs: vec![TransactionInput { commitment: commit }],
            outputs: vec![TransactionOutput {
                commitment: h_point(),
                proof: vec![0u8; 100],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(1000).unwrap(),
                lock_height: 0,
                excess: g_point(),
                excess_signature: [0u8; 65],
            }],
            offset: [0u8; 32],
        };
        let block = Block {
            header: dummy_header(),
            coinbase: dummy_coinbase(),
            transactions: vec![make_tx(h_point()), make_tx(h_point())],
        };
        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(0),
                chain_id: [0x01u8; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .unwrap_err();
        match err {
            DomError::Invalid(msg) => assert!(msg.contains("duplicate input"), "got: {msg}"),
            other => panic!("expected Invalid(duplicate input), got {other:?}"),
        }
    }

    #[test]
    fn block_duplicate_output_with_coinbase_rejected() {
        let bad_tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: g_point(), // same as coinbase output
                proof: vec![0u8; 100],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(1000).unwrap(),
                lock_height: 0,
                excess: g_point(),
                excess_signature: [0u8; 65],
            }],
            offset: [0u8; 32],
        };
        let block = Block {
            header: dummy_header(),
            coinbase: dummy_coinbase(),
            transactions: vec![bad_tx],
        };
        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(0),
                chain_id: [0x01u8; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .unwrap_err();
        match err {
            DomError::Invalid(msg) => assert!(msg.contains("duplicate output"), "got: {msg}"),
            other => panic!("expected Invalid(duplicate output), got {other:?}"),
        }
    }

    #[test]
    fn block_with_internal_spend_pair_requires_block_level_cut_through() {
        let tx1 = build_valid_spend_tx(50, scalar(1), 40, scalar(2), None);
        let tx2 = build_valid_spend_tx(
            tx1.output_value,
            tx1.output_blinding.clone(),
            30,
            scalar(3),
            None,
        );
        let mut tx2 = tx2.tx;
        tx2.inputs[0].commitment = tx1.output_commitment.clone();

        let block = valid_block_with_transactions(vec![tx1.tx, tx2]);
        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(1),
                chain_id: [0x11; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .expect_err("non-cut-through block representation must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("cut-through") || msg.contains("aggregate"),
            "expected block-level cut-through or aggregate rejection, got: {msg}"
        );
    }

    #[test]
    fn invariant_each_transaction_can_validate_while_block_level_cut_through_still_must_reject() {
        let tx1 = build_valid_spend_tx(50, scalar(31), 40, scalar(32), None);
        let tx2_fixture = build_valid_spend_tx(
            tx1.output_value,
            tx1.output_blinding.clone(),
            30,
            scalar(33),
            None,
        );
        let mut tx2 = tx2_fixture.tx.clone();
        tx2.inputs[0].commitment = tx1.output_commitment.clone();

        let ctx = ValidationContext {
            current_height: BlockHeight(1),
            chain_id: [0x11; 32],
            now: Timestamp(u64::MAX),
        };
        crate::validate_transaction(&tx1.tx, &ctx).expect("tx1 must be individually valid");
        crate::validate_transaction(&tx2, &ctx).expect("tx2 must be individually valid");

        let block = valid_block_with_transactions(vec![tx1.tx, tx2]);
        let err = validate_block(&block, &ctx)
            .expect_err("non-canonical block-level cut-through must still reject");
        assert!(
            err.to_string().contains("cut-through"),
            "expected cut-through rejection, got: {err}"
        );
    }

    #[test]
    fn block_with_wrong_total_kernel_offset_is_rejected_by_aggregate_balance() {
        let tx = build_valid_spend_tx(75, scalar(10), 60, scalar(11), Some(scalar(12))).tx;
        let mut block = valid_block_with_transactions(vec![tx.clone()]);
        assert!(
            crate::validate_transaction(
                &tx,
                &ValidationContext {
                    current_height: BlockHeight(1),
                    chain_id: [0x11; 32],
                    now: Timestamp(u64::MAX),
                },
            )
            .is_ok(),
            "fixture must pass per-transaction validation first"
        );
        block.header.total_kernel_offset = [0u8; 32];

        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(1),
                chain_id: [0x11; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .expect_err("wrong block aggregate kernel offset must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("offset") || msg.contains("aggregate") || msg.contains("balance"),
            "expected aggregate block-balance rejection, got: {msg}"
        );
    }

    #[test]
    fn invariant_each_transaction_can_validate_while_block_aggregate_offset_equation_still_must_reject(
    ) {
        let tx = build_valid_spend_tx(75, scalar(41), 60, scalar(42), Some(scalar(43))).tx;
        let ctx = ValidationContext {
            current_height: BlockHeight(1),
            chain_id: [0x11; 32],
            now: Timestamp(u64::MAX),
        };
        crate::validate_transaction(&tx, &ctx).expect("transaction must be individually valid");

        let mut block = valid_block_with_transactions(vec![tx]);
        block.header.total_kernel_offset = [0u8; 32];
        let err = validate_block(&block, &ctx)
            .expect_err("aggregate block balance must reject wrong total_kernel_offset");
        let msg = err.to_string();
        assert!(
            msg.contains("aggregate") || msg.contains("balance"),
            "expected aggregate-balance rejection, got: {msg}"
        );
    }

    #[test]
    fn invariant_pmmr_and_header_fields_cannot_mask_invalid_block_economic_balance() {
        let chain_id = [0x11; 32];
        let coinbase = build_coinbase(0, &chain_id);
        let mut invalid_offset = [0u8; 32];
        invalid_offset[31] = 1;
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, &[]).expect("pmmr roots");
        let block = Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                height: BlockHeight(1),
                prev_hash: Hash256::from_bytes([0x55; 32]),
                timestamp: Timestamp(1_704_067_260),
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset: invalid_offset,
                target: CompactTarget(0x1f00_ffff),
                total_difficulty: U256::from(2u64),
                pow: crate::block::ProofOfWork {
                    nonce: 7,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase,
            transactions: vec![],
        };

        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(1),
                chain_id,
                now: Timestamp(u64::MAX),
            },
        )
        .expect_err("economically invalid block must reject even when PMMR roots match bytes");
        let msg = err.to_string();
        assert!(
            msg.contains("aggregate") || msg.contains("balance"),
            "expected aggregate-balance rejection, got: {msg}"
        );
    }

    /// A correctly constructed single-tx block (zero offset, no intra-block spends)
    /// must pass ALL validation steps including the new cut-through and aggregate
    /// balance checks.
    #[test]
    fn valid_single_tx_block_passes_full_validation() {
        let tx = build_valid_spend_tx(100, scalar(5), 85, scalar(6), None);
        let block = valid_block_with_transactions(vec![tx.tx]);
        validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(1),
                chain_id: [0x11; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .expect("fully valid block must pass all validation including aggregate balance");
    }

    /// A chain of three intra-block spends (C1→C2→C3) where no cut-through was
    /// applied before the block was assembled must be rejected. This is the
    /// "cut-through ambiguity" adversarial case: each individual transaction is
    /// valid, but the block representation is not canonical.
    #[test]
    fn cut_through_chain_of_internal_spends_rejected() {
        let tx1 = build_valid_spend_tx(90, scalar(20), 80, scalar(21), None);
        let tx2 = build_valid_spend_tx(
            tx1.output_value,
            tx1.output_blinding.clone(),
            70,
            scalar(22),
            None,
        );
        let tx3 = build_valid_spend_tx(
            tx2.output_value,
            tx2.output_blinding.clone(),
            60,
            scalar(23),
            None,
        );

        // Save the intermediate output commitments before shadowing the fixtures.
        let tx1_output_commit = tx1.output_commitment.clone();
        let tx2_output_commit = tx2.output_commitment.clone();

        // Wire up intra-block spends: tx2 spends tx1's output, tx3 spends tx2's output.
        let mut tx2 = tx2.tx;
        tx2.inputs[0].commitment = tx1_output_commit;
        let mut tx3 = tx3.tx;
        tx3.inputs[0].commitment = tx2_output_commit;

        let block = valid_block_with_transactions(vec![tx1.tx, tx2, tx3]);
        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(1),
                chain_id: [0x11; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .expect_err("block with chain of intra-block spends must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("cut-through") || msg.contains("aggregate"),
            "expected cut-through or aggregate rejection, got: {msg}"
        );
    }

    /// A transaction whose input commitment matches the coinbase output of the
    /// SAME block must be rejected. The coinbase output is in `seen_outputs` so
    /// the cut-through check catches any attempt to spend it intra-block.
    #[test]
    fn coinbase_output_cannot_be_spent_in_same_block() {
        let coinbase_blinding = scalar(77);
        let coinbase_output_commit = Commitment::commit(
            dom_core::block_reward(BlockHeight(1)).noms(),
            &coinbase_blinding,
        );

        // Build a tx whose input is the coinbase output commitment.
        // The tx itself has invalid crypto (zeroed sig/proof) but the cut-through
        // check fires BEFORE per-tx cryptographic validation.
        let tx = Transaction {
            inputs: vec![TransactionInput {
                commitment: coinbase_output_commit,
            }],
            outputs: vec![TransactionOutput {
                commitment: h_point(),
                proof: vec![0u8; 100],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(0).unwrap(),
                lock_height: 0,
                excess: g_point(),
                excess_signature: [0u8; 65],
            }],
            offset: [0u8; 32],
        };

        // Build a block manually so the coinbase output uses coinbase_blinding.
        let total_fees = 0u64;
        let (proof, _) = dom_crypto::bp2_prove(
            dom_core::block_reward(BlockHeight(1)).noms(),
            &coinbase_blinding,
        )
        .expect("coinbase proof");
        let excess = Commitment::commit(0, &coinbase_blinding);
        let secret = SecretKey::from_bytes(coinbase_blinding.as_bytes()).expect("secret");
        let msg = {
            use dom_core::{KERNEL_FEAT_COINBASE, TAG_KERNEL_MSG_COINBASE};
            let explicit_value = dom_core::block_reward(BlockHeight(1)).noms() + total_fees;
            let mut data = Vec::with_capacity(1 + 8);
            data.push(KERNEL_FEAT_COINBASE);
            data.extend_from_slice(&explicit_value.to_le_bytes());
            dom_crypto::hash::blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
        };
        let sig = schnorr_sign(&secret, msg.as_bytes(), &[0x11u8; 32]).expect("sig");
        let (cb_proof, _) = dom_crypto::bp2_prove(
            dom_core::block_reward(BlockHeight(1)).noms(),
            &coinbase_blinding,
        )
        .expect("cb proof");
        let coinbase = CoinbaseTransaction {
            output: TransactionOutput {
                commitment: Commitment::commit(
                    dom_core::block_reward(BlockHeight(1)).noms(),
                    &coinbase_blinding,
                ),
                proof: cb_proof,
            },
            kernel: CoinbaseKernel {
                features: dom_core::KERNEL_FEAT_COINBASE,
                explicit_value: dom_core::block_reward(BlockHeight(1)).noms() + total_fees,
                excess,
                excess_signature: sig.to_bytes(),
            },
            offset: [0u8; 32],
        };
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, std::slice::from_ref(&tx)).expect("pmmr roots");
        let _ = proof; // used via cb_proof
        let block = Block {
            header: BlockHeader {
                version: dom_core::PROTOCOL_VERSION,
                height: BlockHeight(1),
                prev_hash: Hash256::from_bytes([0x55; 32]),
                timestamp: Timestamp(1_704_067_260),
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset: [0u8; 32],
                target: CompactTarget(0x1f00_ffff),
                total_difficulty: U256::from(2u64),
                pow: crate::block::ProofOfWork {
                    nonce: 7,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase,
            transactions: vec![tx],
        };

        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(1),
                chain_id: [0x11; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .expect_err("spending coinbase output in same block must be rejected");
        assert!(
            err.to_string().contains("cut-through"),
            "expected cut-through rejection, got: {err}"
        );
    }

    /// A coinbase that claims more fees than the block's transactions actually
    /// pay is rejected by validate_block_transactions() → validate_explicit_value().
    /// This covers the value-inflation vector via coinbase overpay: if a miner
    /// inflates the coinbase explicit_value beyond (block_reward + sum_fees),
    /// the block is rejected before the aggregate balance equation is even checked.
    #[test]
    fn coinbase_explicit_value_overpay_is_rejected() {
        // tx has fee = 0 (input == output value).
        let tx = build_valid_spend_tx(100, scalar(5), 100, scalar(6), None);
        // build_coinbase(7, chain_id) produces explicit_value = block_reward + 7.
        // The coinbase is cryptographically self-consistent for that value, but
        // the block's actual transaction fees are 0 — a mismatch by 7 noms.
        let coinbase = build_coinbase(7, &[0x11; 32]);
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, std::slice::from_ref(&tx.tx)).expect("pmmr roots");
        let block = Block {
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
                pow: crate::block::ProofOfWork {
                    nonce: 7,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase,
            transactions: vec![tx.tx],
        };
        let err = validate_block(
            &block,
            &ValidationContext {
                current_height: BlockHeight(1),
                chain_id: [0x11; 32],
                now: Timestamp(u64::MAX),
            },
        )
        .expect_err("coinbase that overpays fees must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("explicit_value") || msg.contains("coinbase") || msg.contains("fee"),
            "expected coinbase overpay rejection, got: {msg}"
        );
    }

    /// Calling validate_block() twice with identical bytes (simulating the same
    /// block arriving at two independent nodes) MUST produce the same outcome.
    /// This is a hard requirement for distributed consensus: no node may accept
    /// a block that another node rejects when both received the same bytes.
    #[test]
    fn block_validation_result_is_deterministic_across_deserialization() {
        let ctx = ValidationContext {
            current_height: BlockHeight(1),
            chain_id: [0x11; 32],
            now: Timestamp(u64::MAX),
        };

        // Valid block: serialise → deserialise independently on two "nodes".
        let tx = build_valid_spend_tx(100, scalar(5), 85, scalar(6), None);
        let block = valid_block_with_transactions(vec![tx.tx]);
        let bytes = block.to_bytes().expect("serialize");
        let node_a = Block::from_bytes(&bytes).expect("node A deserialize");
        let node_b = Block::from_bytes(&bytes).expect("node B deserialize");
        validate_block(&node_a, &ctx).expect("node A must accept the valid block");
        validate_block(&node_b, &ctx).expect("node B must accept the valid block");

        // Invalid block: same serialised bytes on both nodes must produce the
        // exact same rejection string.
        let mut bad = block.clone();
        bad.header.total_kernel_offset = [0xAAu8; 32];
        let bad_bytes = bad.to_bytes().expect("serialize invalid");
        let bad_a = Block::from_bytes(&bad_bytes).expect("node A deserialize invalid");
        let bad_b = Block::from_bytes(&bad_bytes).expect("node B deserialize invalid");
        let err_a = validate_block(&bad_a, &ctx).unwrap_err().to_string();
        let err_b = validate_block(&bad_b, &ctx).unwrap_err().to_string();
        assert_eq!(
            err_a, err_b,
            "all nodes must derive identical rejection from identical bytes"
        );
    }
}

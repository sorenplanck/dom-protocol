#![allow(missing_docs)]

use crate::{
    block::validate_header_syntax, validate_block_transactions, BlockHeader, CoinbaseTransaction,
    Transaction, ValidationContext,
};
use dom_core::{DomError, MAX_BLOCK_TXS, MAX_BLOCK_WEIGHT, WEIGHT_COINBASE_KERNEL, WEIGHT_OUTPUT};
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
        let overflow = || DomError::Invalid("block weight overflow".into());
        let mut total: u32 = 0;
        total = total
            .checked_add(self.coinbase.kernel.weight())
            .ok_or_else(overflow)?;
        total = total
            .checked_add(WEIGHT_COINBASE_KERNEL)
            .ok_or_else(overflow)?;
        total = total.checked_add(WEIGHT_OUTPUT).ok_or_else(overflow)?;
        for tx in &self.transactions {
            total = total.checked_add(tx.weight()).ok_or_else(overflow)?;
        }
        Ok(total)
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

    let total_fees = block.total_fees()?;

    validate_block_transactions(
        &block.transactions,
        &block.coinbase,
        ctx,
        block.header.height,
        total_fees,
    )?;

    // RFC-0007 step 17: validate PMMR roots
    crate::validate_pmmr_roots(block)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        CoinbaseKernel, TransactionInput, TransactionKernel, TransactionOutput,
    };
    use dom_core::{
        Amount, BlockHeight, Hash256, Timestamp, INITIAL_BLOCK_REWARD, KERNEL_FEAT_COINBASE,
        KERNEL_FEAT_PLAIN, PROTOCOL_VERSION,
    };
    use dom_crypto::pedersen::Commitment;
    use dom_pow::CompactTarget;
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
        let expected = dummy_coinbase().kernel.weight() + WEIGHT_COINBASE_KERNEL + WEIGHT_OUTPUT;
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
}

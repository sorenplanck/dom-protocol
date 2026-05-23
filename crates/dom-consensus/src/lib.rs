#![allow(missing_docs)]
//! # dom-consensus
//!
//! Consensus validation pipeline — orchestrated per RFC-0007 + RFC-0010.
//!
//! AUDIT FIX: Previous version had validate_range_proofs, validate_balance_equation,
//! and schnorr_verify as isolated functions never called by connect_block.
//! This module now exposes a single orchestrated validate_transaction() and
//! validate_block() that call ALL required steps in the correct order.
//!
//! ## Transaction Validation (RFC-0007 steps 1-10, RFC-0010 amendments)
//!
//! 1.  canonical decode
//! 2.  primitive validation (limits, kernel features, coinbase maturity)
//!     2b. lock_height check
//! 3.  scalar validation
//! 4.  point validation
//! 5.  duplicate detection
//! 6.  Bulletproofs+ range proof validation (via secp256k1-zkp)
//! 7.  kernel signature validation (Schnorr via secp256k1-zkp)
//! 8.  fee calculation
//! 9.  weight calculation
//! 10. transaction balance equation
//!
//! ## Block Validation (RFC-0007 steps 1-14, RFC-0010 amendments)
//!
//! 1.  canonical decode
//! 2.  header syntax
//! 3.  parent lookup
//! 4.  median-time-past
//! 5.  future timestamp
//! 6.  PoW validation (RandomX, RFC-0011) — active
//! 7.  total difficulty
//! 8.  transaction validation (each tx, steps above)
//!     9a. duplicate detection before cut-through
//!     9b. deterministic cut-through
//!     9c. duplicate detection after cut-through
//! 10. PMMR update
//! 11. PMMR root verification
//! 12. aggregate block balance equation
//! 13. weight validation
//! 14. atomic state commit (in dom-store)

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod block;
pub mod block_full;
pub mod cutthrough;
pub mod transaction;

pub use block::BlockHeader;
pub use block_full::{validate_block, Block};
pub use cutthrough::apply_cut_through;
pub use transaction::{
    validate_balance_equation, validate_lock_heights, validate_range_proofs,
    validate_transaction_structure, CoinbaseKernel, CoinbaseTransaction, Transaction,
    TransactionInput, TransactionKernel, TransactionOutput,
};

use dom_core::{BlockHeight, DomError, Timestamp, MAX_BLOCK_WEIGHT};

/// Context required for transaction and block validation.
pub struct ValidationContext {
    /// Current block height (for lock_height and coinbase maturity checks).
    pub current_height: BlockHeight,
    /// Chain ID (for Schnorr signature verification).
    pub chain_id: [u8; 32],
    /// Current wall-clock time (for future timestamp check).
    pub now: Timestamp,
}

/// Validate a complete transaction — ALL RFC-0007 steps in order.
///
/// This is the ONLY function that should be called for transaction validation.
/// It calls every validation step — structural, cryptographic, and arithmetic.
///
/// All cryptographic steps (PoW, range proofs, kernel signatures) are
/// active. Any failure returns the appropriate DomError variant which
/// determines peer ban scoring.
pub fn validate_transaction(tx: &Transaction, ctx: &ValidationContext) -> Result<(), DomError> {
    // Step 1: canonical decode — done by caller (DomDeserialize::from_bytes)

    // Step 2: primitive validation + coinbase restriction + lock_height
    validate_transaction_structure(tx)?;

    // Step 2b: lock_height temporal check
    validate_lock_heights(tx, ctx.current_height)?;

    // Steps 3-4: scalar and point validation — performed inside
    // validate_transaction_structure (kernel features, SEC1 commitment parsing)

    // Step 5: duplicate detection — inside validate_transaction_structure

    // Step 6: Bulletproofs+ range proof validation
    validate_range_proofs(tx)?;

    // Step 7: Kernel signature validation (Schnorr)
    validate_kernel_signatures(tx, &ctx.chain_id)?;

    // Step 8: fee calculation (checked sum, no overflow)
    tx.total_fee()?;

    // Step 9: weight validation
    let w = tx.weight();
    if w > dom_core::MAX_TX_WEIGHT {
        return Err(DomError::Invalid(format!(
            "tx weight {w} > MAX_TX_WEIGHT {}",
            dom_core::MAX_TX_WEIGHT
        )));
    }

    // Step 10: transaction balance equation
    validate_balance_equation(tx)?;

    Ok(())
}

/// Validate Schnorr signatures on all transaction kernels.
///
/// Each kernel must have a valid Schnorr signature over its kernel_message
/// which includes the chain_id (replay protection).
///
/// Uses dom_crypto::schnorr_verify which is backed by secp256k1-zkp.
pub fn validate_kernel_signatures(tx: &Transaction, chain_id: &[u8; 32]) -> Result<(), DomError> {
    use dom_core::TAG_KERNEL_MSG;
    use dom_crypto::hash::blake2b_256_tagged;

    for (i, kernel) in tx.kernels.iter().enumerate() {
        // Build the kernel message that was signed.
        // chain_id is NOT included here — it is bound in schnorr_challenge() directly.
        // (RFC-0009 §2.1: chain_id enters the challenge, not the message preimage)
        // Including chain_id here AND in the challenge would be double-binding
        // (harmless but redundant). Single source of truth: schnorr_challenge.
        let kernel_message = {
            let mut data = Vec::with_capacity(1 + 8 + 8);
            data.push(kernel.features);
            data.extend_from_slice(&kernel.fee.noms().to_le_bytes());
            data.extend_from_slice(&kernel.lock_height.to_le_bytes());
            blake2b_256_tagged(TAG_KERNEL_MSG, &data)
        };

        // Parse signature
        let sig = dom_crypto::SchnorrSignature::from_bytes(&kernel.excess_signature)
            .map_err(|e| DomError::Invalid(format!("kernel {i} bad signature: {e}")))?;

        // Parse public key from excess (kernel excess = r*G, used as signing key)
        // In Mimblewimble, the excess commitment IS the public key for the signature
        let pk = dom_crypto::PublicKey::from_compressed_bytes(kernel.excess.as_bytes())
            .map_err(|e| DomError::Invalid(format!("kernel {i} bad excess point: {e}")))?;

        // Verify Schnorr signature — chain_id is included in the challenge
        match dom_crypto::schnorr_verify(&sig, &pk, chain_id, kernel_message.as_bytes()) {
            Ok(true) => {}
            Ok(false) => {
                return Err(DomError::Invalid(format!(
                    "kernel {i} Schnorr signature invalid"
                )));
            }
            Err(DomError::Internal(msg)) => {
                return Err(DomError::Internal(format!("kernel sig: {msg}")));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Validate a complete block — ALL RFC-0007 + RFC-0010 steps in order.
///
/// Returns Ok(()) only if every step passes. Any failure returns the
/// appropriate DomError variant which determines peer ban scoring.
///
/// All crypto steps active — any failure is a real consensus rejection, until
/// the required dependencies are integrated. These MUST NOT be
/// bypassed in production builds.
pub fn validate_block_transactions(
    transactions: &[Transaction],
    coinbase: &CoinbaseTransaction,
    ctx: &ValidationContext,
    block_height: BlockHeight,
    claimed_total_fees: u64,
) -> Result<(), DomError> {
    // Step 8: Validate each non-coinbase transaction
    let mut actual_total_fees: u64 = 0;
    let mut total_block_weight: u32 = 0;

    for (i, tx) in transactions.iter().enumerate() {
        validate_transaction(tx, ctx)?;

        let tx_fees = tx
            .total_fee()
            .map_err(|e| DomError::Invalid(format!("tx {i} fee error: {e}")))?;
        actual_total_fees = actual_total_fees
            .checked_add(tx_fees)
            .ok_or_else(|| DomError::Invalid("block total fees overflow".into()))?;

        total_block_weight = total_block_weight
            .checked_add(tx.weight())
            .ok_or_else(|| DomError::Invalid("block weight overflow".into()))?;
    }

    // Step 13: Block weight check
    if total_block_weight > MAX_BLOCK_WEIGHT {
        return Err(DomError::Invalid(format!(
            "block weight {total_block_weight} > MAX_BLOCK_WEIGHT {MAX_BLOCK_WEIGHT}"
        )));
    }

    // Coinbase validation (RFC-0008 §3): explicit_value == reward + fees
    coinbase.validate(block_height, actual_total_fees, &ctx.chain_id)?;

    // Verify claimed_total_fees matches actual
    if claimed_total_fees != actual_total_fees {
        return Err(DomError::Invalid(format!(
            "claimed fees {claimed_total_fees} != actual fees {actual_total_fees}"
        )));
    }

    Ok(())
}

/// Derive chain_id from network magic and genesis hash (RFC-0009 §4.1).
/// Validate that the three PMMR roots in the block header match the roots
/// recomputed from the block body.
///
/// Output MMR: one leaf per output (coinbase + tx outputs), payload = commitment bytes (33).
/// Kernel MMR: one leaf per kernel (coinbase + tx kernels), payload = excess bytes (33).
/// Rangeproof MMR: one leaf per output (coinbase + tx outputs), payload = proof bytes.
///
/// This is RFC-0007 step 17.
pub fn validate_pmmr_roots(block: &Block) -> Result<(), dom_core::DomError> {
    use dom_pmmr::Pmmr;

    let mut output_mmr = Pmmr::new();
    let mut kernel_mmr = Pmmr::new();
    let mut rangeproof_mmr = Pmmr::new();

    // Coinbase output and kernel first
    output_mmr.push(block.coinbase.output.commitment.as_bytes())?;
    rangeproof_mmr.push(&block.coinbase.output.proof)?;
    kernel_mmr.push(block.coinbase.kernel.excess.as_bytes())?;

    // Transaction outputs and kernels
    for tx in &block.transactions {
        for output in &tx.outputs {
            output_mmr.push(output.commitment.as_bytes())?;
            rangeproof_mmr.push(&output.proof)?;
        }
        for kernel in &tx.kernels {
            kernel_mmr.push(kernel.excess.as_bytes())?;
        }
    }

    let computed_output_root = output_mmr.root();
    let computed_kernel_root = kernel_mmr.root();
    let computed_rangeproof_root = rangeproof_mmr.root();

    if computed_output_root != block.header.output_root {
        return Err(dom_core::DomError::Invalid(format!(
            "output_root mismatch: header={} computed={}",
            block.header.output_root, computed_output_root,
        )));
    }
    if computed_kernel_root != block.header.kernel_root {
        return Err(dom_core::DomError::Invalid(format!(
            "kernel_root mismatch: header={} computed={}",
            block.header.kernel_root, computed_kernel_root,
        )));
    }
    if computed_rangeproof_root != block.header.rangeproof_root {
        return Err(dom_core::DomError::Invalid(format!(
            "rangeproof_root mismatch: header={} computed={}",
            block.header.rangeproof_root, computed_rangeproof_root,
        )));
    }

    Ok(())
}

/// Derive the chain ID from the network magic and genesis hash (RFC-0009).
pub fn derive_chain_id(network_magic: u32, genesis_hash: &dom_core::Hash256) -> dom_core::Hash256 {
    use dom_core::TAG_CHAIN_ID;
    use dom_crypto::hash::blake2b_256_tagged;
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&network_magic.to_be_bytes());
    data.extend_from_slice(genesis_hash.as_bytes());
    blake2b_256_tagged(TAG_CHAIN_ID, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TransactionKernel, TransactionOutput};
    use dom_core::{Amount, BlockHeight, Timestamp, KERNEL_FEAT_PLAIN};
    use dom_crypto::pedersen::Commitment;

    fn g_point() -> Commitment {
        let g = [
            0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        Commitment::from_compressed_bytes(&g).unwrap()
    }

    fn test_ctx() -> ValidationContext {
        ValidationContext {
            current_height: BlockHeight(1000),
            chain_id: [0x01u8; 32],
            now: Timestamp(u64::MAX),
        }
    }

    fn minimal_tx() -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: g_point(),
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
        }
    }

    #[test]
    fn validate_transaction_rejects_minimal_tx() {
        // minimal_tx() builds a transaction with zeroed range proof bytes and
        // zeroed Schnorr signature bytes. Both are cryptographically invalid,
        // so validate_transaction MUST reject it.
        //
        // This test guards against accidental regression where a validation
        // step is silently removed or short-circuited to Ok(()).
        let tx = minimal_tx();
        let ctx = test_ctx();
        let result = validate_transaction(&tx, &ctx);
        assert!(
            result.is_err(),
            "validate_transaction must reject a transaction with invalid crypto, got Ok(())"
        );
    }

    #[test]
    fn chain_id_derivation_deterministic() {
        use dom_core::Hash256;
        let h = Hash256::from_bytes([0xAAu8; 32]);
        let id1 = derive_chain_id(dom_core::NETWORK_MAGIC_MAINNET, &h);
        let id2 = derive_chain_id(dom_core::NETWORK_MAGIC_MAINNET, &h);
        assert_eq!(id1, id2);
    }

    #[test]
    fn mainnet_testnet_different_chain_ids() {
        use dom_core::Hash256;
        let h = Hash256::from_bytes([0u8; 32]);
        let id_main = derive_chain_id(dom_core::NETWORK_MAGIC_MAINNET, &h);
        let id_test = derive_chain_id(dom_core::NETWORK_MAGIC_TESTNET, &h);
        assert_ne!(id_main, id_test);
    }
}

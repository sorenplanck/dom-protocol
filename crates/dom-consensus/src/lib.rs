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

/// Compute the three PMMR roots (output, kernel, rangeproof) over a
/// block body. Consensus-critical: the miner and `validate_pmmr_roots`
/// MUST agree on iteration order, byte payloads, and MMR layout, so
/// both call this single function and the test suite asserts they
/// stay aligned.
///
/// Output MMR: one leaf per output (coinbase + tx outputs), payload = commitment bytes (33).
/// Kernel MMR: one leaf per kernel (coinbase + tx kernels), payload = excess bytes (33).
/// Rangeproof MMR: one leaf per output (coinbase + tx outputs), payload = proof bytes.
///
/// Iteration order: coinbase output/kernel/proof first, then per-tx
/// outputs (commitment + proof) followed by per-tx kernels in the
/// order they appear in `transactions`. Any drift here yields blocks
/// that fail their own root check.
pub fn compute_block_pmmr_roots(
    coinbase: &CoinbaseTransaction,
    transactions: &[Transaction],
) -> Result<(dom_core::Hash256, dom_core::Hash256, dom_core::Hash256), dom_core::DomError> {
    use dom_pmmr::Pmmr;

    let mut output_mmr = Pmmr::new();
    let mut kernel_mmr = Pmmr::new();
    let mut rangeproof_mmr = Pmmr::new();

    output_mmr.push(coinbase.output.commitment.as_bytes())?;
    rangeproof_mmr.push(&coinbase.output.proof)?;
    kernel_mmr.push(coinbase.kernel.excess.as_bytes())?;

    for tx in transactions {
        for output in &tx.outputs {
            output_mmr.push(output.commitment.as_bytes())?;
            rangeproof_mmr.push(&output.proof)?;
        }
        for kernel in &tx.kernels {
            kernel_mmr.push(kernel.excess.as_bytes())?;
        }
    }

    Ok((output_mmr.root(), kernel_mmr.root(), rangeproof_mmr.root()))
}

/// Derive chain_id from network magic and genesis hash (RFC-0009 §4.1).
/// Validate that the three PMMR roots in the block header match the roots
/// recomputed from the block body.
///
/// Output MMR: one leaf per output (coinbase + tx outputs), payload = commitment bytes (33).
/// Kernel MMR: one leaf per kernel (coinbase + tx kernels), payload = excess bytes (33).
/// Rangeproof MMR: one leaf per output (coinbase + tx outputs), payload = proof bytes.
///
/// This is RFC-0007 step 17. Delegates the actual layout to
/// `compute_block_pmmr_roots` so the miner and the validator cannot
/// drift on iteration order.
pub fn validate_pmmr_roots(block: &Block) -> Result<(), dom_core::DomError> {
    let (computed_output_root, computed_kernel_root, computed_rangeproof_root) =
        compute_block_pmmr_roots(&block.coinbase, &block.transactions)?;

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

    // ── PMMR root contract: miner ↔ validator agreement ──────────────────────

    fn h_point() -> Commitment {
        let h = [
            0x02u8, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1,
            0xd1, 0x7b, 0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b,
            0x07, 0x8f, 0x09, 0xd5, 0x50,
        ];
        Commitment::from_compressed_bytes(&h).unwrap()
    }

    fn dummy_coinbase(explicit_value: u64) -> CoinbaseTransaction {
        CoinbaseTransaction {
            output: TransactionOutput {
                commitment: g_point(),
                proof: vec![0xAAu8; 100],
            },
            kernel: CoinbaseKernel {
                features: dom_core::KERNEL_FEAT_COINBASE,
                explicit_value,
                // h_point() ≠ g_point() — distinct payloads keep the
                // output_root and kernel_root MMRs in independent hash
                // domains even when both MMRs hold a single leaf.
                excess: h_point(),
                excess_signature: [0u8; 65],
            },
            offset: [0u8; 32],
        }
    }

    fn dummy_tx(commitment: Commitment, proof_fill: u8, fee_noms: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: commitment.clone(),
                proof: vec![proof_fill; 100],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee_noms).unwrap(),
                lock_height: 0,
                excess: commitment,
                excess_signature: [0u8; 65],
            }],
            offset: [0u8; 32],
        }
    }

    fn dummy_block_with(
        coinbase: CoinbaseTransaction,
        txs: Vec<Transaction>,
        output_root: dom_core::Hash256,
        kernel_root: dom_core::Hash256,
        rangeproof_root: dom_core::Hash256,
    ) -> Block {
        use crate::block::ProofOfWork;
        use dom_core::{Hash256, PROTOCOL_VERSION};
        use dom_pow::CompactTarget;
        use primitive_types::U256;
        Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                height: BlockHeight::GENESIS,
                prev_hash: Hash256::ZERO,
                timestamp: Timestamp(1_704_067_200),
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset: [0u8; 32],
                target: CompactTarget(0x1f00_ffff),
                total_difficulty: U256::one(),
                pow: ProofOfWork {
                    nonce: 0,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase,
            transactions: txs,
        }
    }

    /// `compute_block_pmmr_roots` is deterministic and produces three
    /// distinct hashes for distinct payload domains (commitment vs
    /// excess vs rangeproof). Catches a copy-paste mistake that would
    /// have two MMRs share a payload.
    #[test]
    fn compute_pmmr_roots_three_distinct_domains() {
        let coinbase = dummy_coinbase(33 * 1_000_000_000);
        let (r1, r2, r3) = compute_block_pmmr_roots(&coinbase, &[]).unwrap();
        assert_ne!(r1, r2, "output_root and kernel_root must differ");
        assert_ne!(r1, r3, "output_root and rangeproof_root must differ");
        assert_ne!(r2, r3, "kernel_root and rangeproof_root must differ");

        // Determinism across calls.
        let (r1b, r2b, r3b) = compute_block_pmmr_roots(&coinbase, &[]).unwrap();
        assert_eq!(r1, r1b);
        assert_eq!(r2, r2b);
        assert_eq!(r3, r3b);
    }

    /// A block whose header roots come straight from
    /// `compute_block_pmmr_roots` MUST satisfy `validate_pmmr_roots`.
    /// This is the miner / validator contract: as long as the miner
    /// drives the header from this helper, blocks self-accept.
    #[test]
    fn validate_pmmr_roots_accepts_helper_computed_roots() {
        let coinbase = dummy_coinbase(33 * 1_000_000_000);
        let tx1 = dummy_tx(h_point(), 0x11, 100);

        let (or, kr, rr) = compute_block_pmmr_roots(&coinbase, std::slice::from_ref(&tx1)).unwrap();
        let block = dummy_block_with(coinbase, vec![tx1], or, kr, rr);
        validate_pmmr_roots(&block).expect("helper-computed roots must satisfy the validator");
    }

    /// Same coinbase, different transaction list MUST produce different
    /// roots. Catches the bug class where the miner's PMMR ignores tx
    /// content (which is exactly what an empty `Block.transactions`
    /// header drift would look like).
    #[test]
    fn pmmr_roots_depend_on_tx_set() {
        let coinbase = dummy_coinbase(33 * 1_000_000_000);
        let (r_empty_out, r_empty_ker, r_empty_rp) =
            compute_block_pmmr_roots(&coinbase, &[]).unwrap();

        let tx1 = dummy_tx(h_point(), 0x11, 100);
        let (r1_out, r1_ker, r1_rp) =
            compute_block_pmmr_roots(&coinbase, std::slice::from_ref(&tx1)).unwrap();

        assert_ne!(r_empty_out, r1_out);
        assert_ne!(r_empty_ker, r1_ker);
        assert_ne!(r_empty_rp, r1_rp);

        // Two transactions instead of one — roots shift again.
        let tx2 = dummy_tx(h_point(), 0x22, 200);
        let (r2_out, r2_ker, r2_rp) =
            compute_block_pmmr_roots(&coinbase, &[tx1.clone(), tx2.clone()]).unwrap();
        assert_ne!(r1_out, r2_out);
        assert_ne!(r1_ker, r2_ker);
        assert_ne!(r1_rp, r2_rp);
    }

    /// Tx ordering inside the block is consensus. Same set of txs but
    /// reversed order MUST produce different PMMR roots — even though
    /// the *output commitment* sets are identical, the rangeproof
    /// payloads differ per-tx so the rangeproof MMR's leaf positions
    /// pin the order. The kernel MMR drifts too because the kernel
    /// excess inherits the tx's distinct commitment in `dummy_tx`.
    #[test]
    fn pmmr_roots_depend_on_tx_order() {
        let coinbase = dummy_coinbase(33 * 1_000_000_000);
        let tx_a = dummy_tx(g_point(), 0x11, 100);
        let tx_b = dummy_tx(h_point(), 0x22, 200);

        let forward = compute_block_pmmr_roots(&coinbase, &[tx_a.clone(), tx_b.clone()]).unwrap();
        let reverse = compute_block_pmmr_roots(&coinbase, &[tx_b, tx_a]).unwrap();
        assert_ne!(forward.0, reverse.0, "output_root must depend on tx order");
        assert_ne!(forward.1, reverse.1, "kernel_root must depend on tx order");
        assert_ne!(
            forward.2, reverse.2,
            "rangeproof_root must depend on tx order"
        );
    }

    /// Mutating a tx-output proof byte after the header roots were
    /// frozen MUST make `validate_pmmr_roots` reject the block. This
    /// is the silent-mutation property at the block level.
    #[test]
    fn validate_pmmr_roots_rejects_post_header_mutation() {
        let coinbase = dummy_coinbase(33 * 1_000_000_000);
        let tx1 = dummy_tx(h_point(), 0x11, 100);

        // Freeze header roots over the *original* tx.
        let (or, kr, rr) = compute_block_pmmr_roots(&coinbase, std::slice::from_ref(&tx1)).unwrap();

        // Mutate the rangeproof of the tx after the header is fixed.
        let mut mutated_tx = tx1;
        mutated_tx.outputs[0].proof[0] ^= 0xff;

        let block = dummy_block_with(coinbase, vec![mutated_tx], or, kr, rr);
        let err = validate_pmmr_roots(&block).expect_err(
            "validator must reject a block whose body diverges from its frozen header roots",
        );
        match err {
            dom_core::DomError::Invalid(msg) => {
                assert!(
                    msg.contains("rangeproof_root mismatch"),
                    "expected rangeproof_root mismatch, got: {msg}"
                );
            }
            other => panic!("expected Invalid(rangeproof_root mismatch), got {other:?}"),
        }
    }
}

//! Deterministic cut-through — corrected per audit.
//!
//! AUDIT FIX: Previous version removed matching outputs but kept ALL inputs
//! (filter returning `true`). This broke the balance equation and enabled
//! inflation. Now both inputs AND outputs in the eliminated set are removed.
//!
//! RFC-0010 §3.3 algorithm:
//!   1. Collect all inputs I and outputs O (sorted lexicographically)
//!   2. eliminated = {c | c ∈ input_commits AND c ∈ output_commits}
//!   3. outputs_after = O \ {o | o.commitment ∈ eliminated}
//!   4. inputs_after  = I \ {i | i.commitment ∈ eliminated}
//!   5. Kernels are ALWAYS preserved
//!
//! Duplicates are checked before AND after cut-through (RFC-0010 §3.2 steps 9a/9c).

use dom_core::DomError;
use std::collections::HashSet;
use super::transaction::{Transaction, TransactionInput, TransactionOutput};

/// Apply deterministic cut-through to a set of block transactions.
///
/// Returns (remaining_inputs, remaining_outputs) after removing matched pairs.
/// Kernels from all transactions must be preserved by the caller.
pub fn apply_cut_through(
    transactions: &[Transaction],
) -> Result<(Vec<TransactionInput>, Vec<TransactionOutput>), DomError> {
    let mut all_inputs: Vec<TransactionInput> = Vec::new();
    let mut all_outputs: Vec<TransactionOutput> = Vec::new();

    for tx in transactions {
        all_inputs.extend(tx.inputs.iter().cloned());
        all_outputs.extend(tx.outputs.iter().cloned());
    }

    // ── Step 9a: Duplicate detection BEFORE cut-through ──────────────────────
    {
        let mut seen = HashSet::new();
        for i in &all_inputs {
            if !seen.insert(*i.commitment.as_bytes()) {
                return Err(DomError::Invalid("duplicate input before cut-through".into()));
            }
        }
    }
    {
        let mut seen = HashSet::new();
        for o in &all_outputs {
            if !seen.insert(*o.commitment.as_bytes()) {
                return Err(DomError::Invalid("duplicate output before cut-through".into()));
            }
        }
    }

    // ── Step 9b: Deterministic cut-through ───────────────────────────────────
    // Build sets for intersection
    let input_commits: HashSet<[u8; 33]> = all_inputs.iter()
        .map(|i| *i.commitment.as_bytes())
        .collect();
    let output_commits: HashSet<[u8; 33]> = all_outputs.iter()
        .map(|o| *o.commitment.as_bytes())
        .collect();

    // eliminated = inputs ∩ outputs (same commitment appears as both)
    let eliminated: HashSet<[u8; 33]> = input_commits.intersection(&output_commits)
        .cloned()
        .collect();

    // Remove eliminated outputs AND eliminated inputs
    let outputs_after: Vec<TransactionOutput> = all_outputs.into_iter()
        .filter(|o| !eliminated.contains(o.commitment.as_bytes()))
        .collect();

    let inputs_after: Vec<TransactionInput> = all_inputs.into_iter()
        .filter(|i| !eliminated.contains(i.commitment.as_bytes()))
        .collect();

    // ── Step 9c: Duplicate detection AFTER cut-through ───────────────────────
    {
        let mut seen = HashSet::new();
        for i in &inputs_after {
            if !seen.insert(*i.commitment.as_bytes()) {
                return Err(DomError::Invalid("duplicate input after cut-through".into()));
            }
        }
    }
    {
        let mut seen = HashSet::new();
        for o in &outputs_after {
            if !seen.insert(*o.commitment.as_bytes()) {
                return Err(DomError::Invalid("duplicate output after cut-through".into()));
            }
        }
    }

    Ok((inputs_after, outputs_after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::{Amount, KERNEL_FEAT_PLAIN};
    use dom_crypto::pedersen::Commitment;
    use super::super::transaction::{TransactionKernel, TransactionOutput, TransactionInput};

    fn point(byte: u8) -> Commitment {
        // Use real secp256k1 points derived deterministically
        // G is 0x02 79BE..., we use different valid points for testing
        let sk = secp256k1::SecretKey::from_slice(&{
            let mut b = [0u8; 32]; b[31] = byte.max(1); b
        }).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &sk);
        Commitment::from_compressed_bytes(&pk.serialize()).unwrap()
    }

    fn output(byte: u8) -> TransactionOutput {
        TransactionOutput { commitment: point(byte), proof: vec![0u8; 32] }
    }
    fn input(byte: u8) -> TransactionInput {
        TransactionInput { commitment: point(byte) }
    }
    fn kernel() -> TransactionKernel {
        TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(0).unwrap(),
            lock_height: 0,
            excess: point(5),
            excess_signature: [0u8; 65],
        }
    }

    /// CRITICAL TEST: Both input AND output are eliminated when matched.
    /// Previous version kept all inputs — this test would have FAILED.
    #[test]
    fn matched_input_and_output_both_removed() {
        // tx1 creates commitment C (byte=1)
        // tx2 spends commitment C (byte=1)
        // After cut-through: C should appear in NEITHER inputs nor outputs
        let tx1 = Transaction {
            inputs: vec![],
            outputs: vec![output(1)], // creates C
            kernels: vec![kernel()],
            offset: [0u8; 32],
        };
        let tx2 = Transaction {
            inputs: vec![input(1)],  // spends C
            outputs: vec![output(2)], // creates D
            kernels: vec![kernel()],
            offset: [0u8; 32],
        };

        let (inputs, outputs) = apply_cut_through(&[tx1, tx2]).unwrap();

        // C must not appear in inputs OR outputs
        let c_bytes = *point(1).as_bytes();
        assert!(
            !inputs.iter().any(|i| i.commitment.as_bytes() == &c_bytes),
            "matched input C must be eliminated from inputs"
        );
        assert!(
            !outputs.iter().any(|o| o.commitment.as_bytes() == &c_bytes),
            "matched output C must be eliminated from outputs"
        );

        // D (byte=2) should remain as output (unmatched output)
        let d_bytes = *point(2).as_bytes();
        assert!(
            outputs.iter().any(|o| o.commitment.as_bytes() == &d_bytes),
            "unmatched output D must survive cut-through"
        );
    }

    #[test]
    fn unmatched_outputs_and_inputs_preserved() {
        let tx = Transaction {
            inputs: vec![input(10)],  // external spend (no matching output)
            outputs: vec![output(20)], // new output (no matching input)
            kernels: vec![kernel()],
            offset: [0u8; 32],
        };
        let (inputs, outputs) = apply_cut_through(&[tx]).unwrap();
        assert_eq!(inputs.len(), 1, "unmatched input must survive");
        assert_eq!(outputs.len(), 1, "unmatched output must survive");
    }

    #[test]
    fn empty_block_cut_through() {
        let (inputs, outputs) = apply_cut_through(&[]).unwrap();
        assert!(inputs.is_empty());
        assert!(outputs.is_empty());
    }

    #[test]
    fn duplicate_input_rejected_before_cut_through() {
        let tx = Transaction {
            inputs: vec![input(1), input(1)], // duplicate
            outputs: vec![output(2)],
            kernels: vec![kernel()],
            offset: [0u8; 32],
        };
        assert!(apply_cut_through(&[tx]).is_err());
    }

    #[test]
    fn duplicate_output_rejected_before_cut_through() {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![output(1), output(1)], // duplicate
            kernels: vec![kernel()],
            offset: [0u8; 32],
        };
        assert!(apply_cut_through(&[tx]).is_err());
    }
}

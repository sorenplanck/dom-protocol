//! Coin selection algorithms for transaction building.
//!
//! Provides multiple strategies for selecting UTXOs to spend in a transaction,
//! optimizing for different criteria (fewest inputs, defragmentation, FIFO).
//!
//! These algorithms operate on an abstract [`SelectableUtxo`] type,
//! independent of the wallet's concrete `OwnedOutput` type, for
//! testability and reuse.

use thiserror::Error;

/// Errors that can occur during coin selection.
#[derive(Debug, Error)]
pub enum SelectionError {
    /// Not enough funds available to cover target + fee.
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds {
        /// Total value of UTXOs we have.
        have: u64,
        /// Total value we need (target + fee).
        need: u64,
    },

    /// No UTXOs were provided for selection.
    #[error("no UTXOs available")]
    NoUtxos,
}

/// An abstract spendable UTXO for coin selection.
///
/// This is a minimal representation containing only the fields needed
/// for selection decisions. The actual wallet output type can be mapped
/// to this for selection, then mapped back for transaction building.
#[derive(Debug, Clone)]
pub struct SelectableUtxo {
    /// Value of the UTXO in noms.
    pub value: u64,
    /// Age of the UTXO in blocks (current_height - created_at).
    pub age_blocks: u64,
    /// Stable index for matching back to the source wallet output.
    pub index: usize,
}

/// Strategy for choosing which UTXOs to spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// Largest UTXOs first — minimizes input count and transaction fees.
    Greedy,

    /// Smallest UTXOs first — defragments the wallet by consolidating dust.
    SmallestFirst,

    /// Oldest UTXOs first — FIFO ordering for predictable spending.
    AgeWeighted,
}

/// Coin selection algorithms.
pub struct CoinSelector;

impl CoinSelector {
    /// Select UTXOs to cover `target + fee` using the given strategy.
    ///
    /// Returns the selected UTXOs in the order they were chosen. The total
    /// value will be at least `target + fee` (any excess becomes change
    /// at the transaction-building layer).
    ///
    /// # Errors
    /// Returns [`SelectionError::NoUtxos`] if `utxos` is empty, or
    /// [`SelectionError::InsufficientFunds`] if even after selecting
    /// all available UTXOs the total is less than `target + fee`.
    pub fn select(
        utxos: &[SelectableUtxo],
        target: u64,
        fee: u64,
        strategy: SelectionStrategy,
    ) -> Result<Vec<SelectableUtxo>, SelectionError> {
        if utxos.is_empty() {
            return Err(SelectionError::NoUtxos);
        }

        let needed = target.saturating_add(fee);
        let mut sorted = utxos.to_vec();
        match strategy {
            SelectionStrategy::Greedy => sorted.sort_by_key(|b| std::cmp::Reverse(b.value)),
            SelectionStrategy::SmallestFirst => sorted.sort_by_key(|a| a.value),
            SelectionStrategy::AgeWeighted => {
                sorted.sort_by_key(|b| std::cmp::Reverse(b.age_blocks))
            }
        }

        let mut selected = Vec::new();
        let mut total: u64 = 0;
        for utxo in sorted {
            if total >= needed {
                break;
            }
            total = total.saturating_add(utxo.value);
            selected.push(utxo);
        }

        if total < needed {
            return Err(SelectionError::InsufficientFunds {
                have: total,
                need: needed,
            });
        }
        Ok(selected)
    }

    /// Estimate transaction fee from input and output counts.
    ///
    /// Uses a simple linear model:
    /// `BASE_FEE + (inputs * INPUT_FEE) + (outputs * OUTPUT_FEE)`
    ///
    /// where `BASE_FEE = 1000`, `INPUT_FEE = 100`, `OUTPUT_FEE = 200` noms.
    /// Real-fee estimation should consider mempool weight (see `dom-mempool`).
    pub fn estimate_fee(input_count: usize, output_count: usize) -> u64 {
        const BASE_FEE: u64 = 1_000;
        const INPUT_FEE: u64 = 100;
        const OUTPUT_FEE: u64 = 200;
        BASE_FEE + (input_count as u64) * INPUT_FEE + (output_count as u64) * OUTPUT_FEE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_utxos() -> Vec<SelectableUtxo> {
        vec![
            SelectableUtxo {
                value: 1000,
                age_blocks: 100,
                index: 0,
            },
            SelectableUtxo {
                value: 2000,
                age_blocks: 50,
                index: 1,
            },
            SelectableUtxo {
                value: 500,
                age_blocks: 200,
                index: 2,
            },
            SelectableUtxo {
                value: 3000,
                age_blocks: 10,
                index: 3,
            },
        ]
    }

    #[test]
    fn greedy_picks_largest_first() {
        let utxos = mock_utxos();
        let selected = CoinSelector::select(&utxos, 2500, 100, SelectionStrategy::Greedy).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 3000);
    }

    #[test]
    fn smallest_first_defragments() {
        let utxos = mock_utxos();
        let selected =
            CoinSelector::select(&utxos, 2500, 100, SelectionStrategy::SmallestFirst).unwrap();
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn age_weighted_prefers_old() {
        let utxos = mock_utxos();
        let selected =
            CoinSelector::select(&utxos, 400, 50, SelectionStrategy::AgeWeighted).unwrap();
        assert_eq!(selected[0].age_blocks, 200);
    }

    #[test]
    fn insufficient_funds_rejected() {
        let utxos = vec![SelectableUtxo {
            value: 100,
            age_blocks: 1,
            index: 0,
        }];
        assert!(matches!(
            CoinSelector::select(&utxos, 1000, 100, SelectionStrategy::Greedy),
            Err(SelectionError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn empty_utxos_rejected() {
        assert!(matches!(
            CoinSelector::select(&[], 100, 10, SelectionStrategy::Greedy),
            Err(SelectionError::NoUtxos)
        ));
    }
}

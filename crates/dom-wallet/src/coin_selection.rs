//! Coin selection algorithms for transaction building.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SelectionError {
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("no UTXOs available")]
    NoUtxos,
}

#[derive(Debug, Clone)]
pub struct SelectableUtxo {
    pub value: u64,
    pub age_blocks: u64,
    pub index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    Greedy,
    SmallestFirst,
    AgeWeighted,
}

pub struct CoinSelector;

impl CoinSelector {
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
            SelectionStrategy::Greedy => sorted.sort_by(|a, b| b.value.cmp(&a.value)),
            SelectionStrategy::SmallestFirst => sorted.sort_by(|a, b| a.value.cmp(&b.value)),
            SelectionStrategy::AgeWeighted => sorted.sort_by(|a, b| b.age_blocks.cmp(&a.age_blocks)),
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
            return Err(SelectionError::InsufficientFunds { have: total, need: needed });
        }
        Ok(selected)
    }

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
            SelectableUtxo { value: 1000, age_blocks: 100, index: 0 },
            SelectableUtxo { value: 2000, age_blocks: 50, index: 1 },
            SelectableUtxo { value: 500, age_blocks: 200, index: 2 },
            SelectableUtxo { value: 3000, age_blocks: 10, index: 3 },
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
        let selected = CoinSelector::select(&utxos, 2500, 100, SelectionStrategy::SmallestFirst).unwrap();
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn age_weighted_prefers_old() {
        let utxos = mock_utxos();
        let selected = CoinSelector::select(&utxos, 400, 50, SelectionStrategy::AgeWeighted).unwrap();
        assert_eq!(selected[0].age_blocks, 200);
    }

    #[test]
    fn insufficient_funds_rejected() {
        let utxos = vec![SelectableUtxo { value: 100, age_blocks: 1, index: 0 }];
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

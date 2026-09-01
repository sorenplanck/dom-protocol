//! Independent-node quorum selection.

use futures::future::join_all;
use std::{collections::HashMap, hash::Hash};

use crate::{
    CanonicalTip, NodeObservation, XmrNetwork, XmrObserverError, XmrRpc, XmrTransactionStatus,
};

/// Multi-node observer pool.
pub struct XmrRpcPool<R> {
    nodes: Vec<R>,
    expected_network: XmrNetwork,
    min_quorum: usize,
}

impl<R> core::fmt::Debug for XmrRpcPool<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrRpcPool")
            .field("node_count", &self.nodes.len())
            .field("expected_network", &self.expected_network)
            .field("min_quorum", &self.min_quorum)
            .finish()
    }
}

impl<R: XmrRpc> XmrRpcPool<R> {
    /// Creates a fail-closed quorum pool.
    pub fn new(
        nodes: Vec<R>,
        expected_network: XmrNetwork,
        min_quorum: usize,
    ) -> Result<Self, XmrObserverError> {
        if min_quorum == 0 || min_quorum > nodes.len() {
            return Err(XmrObserverError::InvalidQuorum {
                required: min_quorum,
                available: nodes.len(),
            });
        }
        Ok(Self {
            nodes,
            expected_network,
            min_quorum,
        })
    }

    /// Required votes.
    pub const fn min_quorum(&self) -> usize {
        self.min_quorum
    }

    /// Unique canonical-tip quorum.
    pub async fn canonical_tip(&self) -> Result<CanonicalTip, XmrObserverError> {
        let results = join_all(
            self.nodes
                .iter()
                .map(|node| node.observe_tip(self.expected_network)),
        )
        .await;
        let valid: Vec<NodeObservation> = results.into_iter().filter_map(Result::ok).collect();
        unique_quorum(
            valid.iter().map(NodeObservation::canonical_tip),
            self.min_quorum,
            XmrObserverError::ConflictingCanonicalTip,
        )
    }

    /// Unique transaction-status quorum.
    pub async fn transaction_status(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<XmrTransactionStatus, XmrObserverError> {
        let results = join_all(
            self.nodes
                .iter()
                .map(|node| node.transaction_status(tx_hash)),
        )
        .await;
        unique_quorum(
            results.into_iter().filter_map(Result::ok),
            self.min_quorum,
            XmrObserverError::ConflictingTransactionStatus,
        )
    }

    /// Unique block-hash quorum.
    pub async fn block_hash(&self, height: u64) -> Result<[u8; 32], XmrObserverError> {
        let results = join_all(self.nodes.iter().map(|node| node.block_hash(height))).await;
        unique_quorum(
            results
                .into_iter()
                .filter_map(Result::ok)
                .filter(|hash| *hash != [0; 32]),
            self.min_quorum,
            XmrObserverError::ConflictingBlockHash,
        )
    }
}

fn unique_quorum<T>(
    values: impl IntoIterator<Item = T>,
    minimum: usize,
    conflict: XmrObserverError,
) -> Result<T, XmrObserverError>
where
    T: Copy + Eq + Hash,
{
    let mut votes = HashMap::<T, usize>::new();
    for value in values {
        *votes.entry(value).or_default() += 1;
    }
    let mut winners = votes.into_iter().filter(|(_, count)| *count >= minimum);
    let winner = winners.next().ok_or_else(|| conflict.clone())?;
    if winners.next().is_some() {
        return Err(conflict);
    }
    Ok(winner.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_winner_is_required() {
        assert_eq!(
            unique_quorum([1_u8, 1, 2], 2, XmrObserverError::ConflictingBlockHash),
            Ok(1)
        );
        assert_eq!(
            unique_quorum([1_u8, 1, 2, 2], 2, XmrObserverError::ConflictingBlockHash),
            Err(XmrObserverError::ConflictingBlockHash),
        );
    }
}

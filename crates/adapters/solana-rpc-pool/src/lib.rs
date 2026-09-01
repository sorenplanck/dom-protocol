//! Multi-RPC quorum for Solana account, block and transaction evidence.

#![forbid(unsafe_code)]

use solana_rpc::{RpcError, SolanaRpc};
use solana_types::{
    Commitment, SolanaAccountSnapshot, SolanaBlockAnchor, SolanaPubkey, SolanaSignature,
    SolanaSignatureStatus, SolanaTransactionRecord,
};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuorumError {
    #[error("invalid RPC quorum configuration")]
    InvalidConfiguration,
    #[error("not enough available Solana RPC nodes")]
    Unavailable,
    #[error("Solana RPC nodes did not reach a unique quorum")]
    NoQuorum,
    #[error("Solana RPC finalized tips are too far apart")]
    StaleNode,
}

pub struct SolanaRpcPool<R> {
    nodes: Vec<Arc<R>>,
    quorum: usize,
}

impl<R> Clone for SolanaRpcPool<R> {
    fn clone(&self) -> Self {
        Self {
            nodes: self.nodes.clone(),
            quorum: self.quorum,
        }
    }
}

impl<R: SolanaRpc> SolanaRpcPool<R> {
    pub fn new(nodes: Vec<Arc<R>>, quorum: usize) -> Result<Self, QuorumError> {
        if quorum == 0 || quorum > nodes.len() {
            return Err(QuorumError::InvalidConfiguration);
        }
        Ok(Self { nodes, quorum })
    }

    pub const fn quorum(&self) -> usize {
        self.quorum
    }

    /// The configured nodes, for callers that need a non-quorum operation
    /// (fetching a blockhash, fanning out a broadcast) over the same set.
    pub fn nodes(&self) -> &[Arc<R>] {
        &self.nodes
    }

    pub fn finalized_tip_floor(&self, max_lag: u64) -> Result<u64, QuorumError> {
        let mut slots: Vec<u64> = self
            .nodes
            .iter()
            .filter_map(|node| node.get_slot(Commitment::Finalized).ok())
            .collect();
        if slots.len() < self.quorum {
            return Err(QuorumError::Unavailable);
        }
        slots.sort_unstable();
        let selected = &slots[slots.len() - self.quorum..];
        let first = selected[0];
        let last = *selected.last().ok_or(QuorumError::Unavailable)?;
        if last.saturating_sub(first) > max_lag {
            return Err(QuorumError::StaleNode);
        }
        Ok(first)
    }

    pub fn block_anchor(&self, slot: u64) -> Result<SolanaBlockAnchor, QuorumError> {
        let values = self
            .nodes
            .iter()
            .filter_map(|node| node.get_block_anchor(slot).ok().flatten())
            .collect();
        unique_vote(values, self.quorum, |value| value.blockhash.0)
    }

    pub fn account(
        &self,
        key: SolanaPubkey,
        commitment: Commitment,
    ) -> Result<Option<SolanaAccountSnapshot>, QuorumError> {
        let mut absent = 0usize;
        let mut values = Vec::new();
        for node in &self.nodes {
            match node.get_account(key, commitment) {
                Ok(Some(value)) => values.push(value),
                Ok(None) => absent += 1,
                Err(_) => {}
            }
        }
        if absent >= self.quorum {
            return Ok(None);
        }
        if values.len() < self.quorum {
            return Err(QuorumError::Unavailable);
        }
        Ok(Some(unique_vote(values, self.quorum, |value| {
            value.commitment_hash()
        })?))
    }

    pub fn signature_status(
        &self,
        signature: SolanaSignature,
    ) -> Result<Option<SolanaSignatureStatus>, QuorumError> {
        let mut absent = 0usize;
        let mut values = Vec::new();
        for node in &self.nodes {
            match node.get_signature_status(signature) {
                Ok(Some(value)) => values.push(value),
                Ok(None) => absent += 1,
                Err(_) => {}
            }
        }
        if absent >= self.quorum {
            return Ok(None);
        }
        if values.len() < self.quorum {
            return Err(QuorumError::Unavailable);
        }
        Ok(Some(unique_vote(values, self.quorum, |value| {
            let commitment = match value.confirmation {
                Commitment::Processed => 1u8,
                Commitment::Confirmed => 2,
                Commitment::Finalized => 3,
            };
            let mut key = [0u8; 10];
            key[..8].copy_from_slice(&value.slot.to_be_bytes());
            key[8] = commitment;
            key[9] = u8::from(value.failed);
            key
        })?))
    }

    pub fn transaction(
        &self,
        signature: SolanaSignature,
        commitment: Commitment,
    ) -> Result<Option<SolanaTransactionRecord>, QuorumError> {
        let mut absent = 0usize;
        let mut values = Vec::new();
        for node in &self.nodes {
            match node.get_transaction(signature, commitment) {
                Ok(Some(value)) => values.push(value),
                Ok(None) => absent += 1,
                Err(_) => {}
            }
        }
        if absent >= self.quorum {
            return Ok(None);
        }
        if values.len() < self.quorum {
            return Err(QuorumError::Unavailable);
        }
        Ok(Some(unique_vote(values, self.quorum, |value| {
            value.commitment_hash()
        })?))
    }
}

fn unique_vote<T: Clone, K: Ord>(
    values: Vec<T>,
    quorum: usize,
    key: impl Fn(&T) -> K,
) -> Result<T, QuorumError> {
    let mut votes: BTreeMap<K, Vec<T>> = BTreeMap::new();
    for value in values {
        votes.entry(key(&value)).or_default().push(value);
    }
    let mut winners = votes.into_values().filter(|values| values.len() >= quorum);
    let winner = winners.next().ok_or(QuorumError::NoQuorum)?;
    if winners.next().is_some() {
        return Err(QuorumError::NoQuorum);
    }
    winner.into_iter().next().ok_or(QuorumError::NoQuorum)
}

impl From<RpcError> for QuorumError {
    fn from(_: RpcError) -> Self {
        Self::Unavailable
    }
}

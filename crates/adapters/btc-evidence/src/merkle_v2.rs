//! Internal mutation-aware Bitcoin transaction Merkle verification.
//!
//! No compact branch or txid-only proof is exported from this crate. A compact
//! path cannot establish that an opaque off-path subtree is free of the
//! duplicate-last mutation identified by CVE-2012-2459, and a txid-only list
//! cannot rule out a 64-byte transaction being interpreted as an inner node.

use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction};

use crate::evidence_v2::MAX_TRANSACTIONS_V2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MerkleProofErrorV2 {
    /// No leaf was supplied.
    #[error("empty transaction set")]
    EmptyTransactionSet,
    /// The caller-provided or decoded transaction count exceeds the hard cap.
    #[error("transaction count exceeds V2 bound")]
    TransactionCountBoundExceeded,
    /// The selected leaf does not exist.
    #[error("transaction position is outside the tree")]
    PositionOutOfRange,
    /// An internal compact path exceeds its defensive cap.
    #[error("merkle branch exceeds V2 depth bound")]
    BranchTooDeep,
    /// A compact path cannot have the claimed complete-tree shape.
    #[error("merkle branch length does not match transaction count")]
    BranchLengthMismatch,
    /// A real adjacent pair is equal before odd-node duplication.
    #[error("mutated merkle tree")]
    MutationDetected,
    /// A compact path supplied a different sibling where Core duplicates the
    /// unpaired final node.
    #[error("non-canonical odd merkle duplication")]
    NonCanonicalOddDuplication,
    /// A transaction has the exact stripped size that can masquerade as an
    /// internal Merkle node.
    #[error("ambiguous 64-byte transaction")]
    AmbiguousTransactionSize,
    /// The mutation-checked complete tree does not match the block header.
    #[error("full block merkle root mismatch")]
    MerkleRootMismatch,
}

/// Hard bound for any internal compact-path construction.
const MAX_MERKLE_DEPTH_V2: usize = 32;

/// A compact path is deliberately named untrusted and remains module-private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UntrustedCompactMerkleBranchV2 {
    /// Caller-claimed complete leaf count.
    pub(crate) total_transactions: u32,
    /// Zero-based caller-claimed leaf position.
    pub(crate) position: u32,
    /// Caller-provided sibling hashes from leaf to root.
    pub(crate) siblings: Vec<[u8; 32]>,
}

impl UntrustedCompactMerkleBranchV2 {
    /// Constructs a shape-checked but unauthenticated compact branch.
    pub(crate) fn new(
        total_transactions: u32,
        position: u32,
        siblings: Vec<[u8; 32]>,
    ) -> Result<Self, MerkleProofErrorV2> {
        validate_shape(total_transactions, position, siblings.len())?;
        Ok(Self {
            total_transactions,
            position,
            siblings,
        })
    }
}

/// Result of inspecting a caller-provided complete txid list.
///
/// This type is intentionally distinct from [`FullBlockMerkleProofV2`]. It is
/// useful only while constructing and testing the tree and never represents a
/// header-anchored block proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TxidSetMerkleTreeV2 {
    /// Mutation-checked root derived from caller-provided txids.
    pub(crate) merkle_root: [u8; 32],
    /// Compact path derived for the selected caller-provided txid.
    pub(crate) branch: UntrustedCompactMerkleBranchV2,
}

/// Result obtainable only after inspecting every transaction in a full block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FullBlockMerkleProofV2 {
    /// Mutation-checked transaction Merkle root from the complete block.
    pub(crate) merkle_root: [u8; 32],
    /// Exact number of transactions inspected in the complete block.
    pub(crate) total_transactions: u32,
    /// Exact zero-based position inspected in the complete block.
    pub(crate) transaction_position: u32,
}

fn validate_transaction_size_v2(transaction: &Transaction) -> Result<(), MerkleProofErrorV2> {
    if transaction.base_size() == 64 {
        return Err(MerkleProofErrorV2::AmbiguousTransactionSize);
    }
    Ok(())
}

/// Folds only the visible path. This must never be treated as proof of global
/// mutation freedom and consequently is not exposed outside this module.
pub(crate) fn fold_untrusted_compact_branch_v2(
    txid: [u8; 32],
    branch: &UntrustedCompactMerkleBranchV2,
) -> Result<[u8; 32], MerkleProofErrorV2> {
    let mut accumulator = txid;
    let mut index = u64::from(branch.position);
    let mut width = u64::from(branch.total_transactions);

    for sibling in &branch.siblings {
        let sibling_is_real = index & 1 == 1 || index.saturating_add(1) < width;
        if sibling_is_real {
            if *sibling == accumulator {
                return Err(MerkleProofErrorV2::MutationDetected);
            }
        } else if *sibling != accumulator {
            return Err(MerkleProofErrorV2::NonCanonicalOddDuplication);
        }

        accumulator = if index & 1 == 0 {
            merkle_parent(accumulator, *sibling)
        } else {
            merkle_parent(*sibling, accumulator)
        };
        index >>= 1;
        width = next_width(width);
    }

    if index != 0 || width != 1 {
        return Err(MerkleProofErrorV2::BranchLengthMismatch);
    }
    Ok(accumulator)
}

/// Mirrors Bitcoin Core's mutation scan: compare every real adjacent pair at
/// every level before duplicating an unpaired final node.
pub(crate) fn build_mutation_checked_txid_set_v2(
    txids: &[[u8; 32]],
    transaction_position: usize,
) -> Result<TxidSetMerkleTreeV2, MerkleProofErrorV2> {
    let total_transactions = bounded_transaction_count(txids.len())?;
    let position =
        u32::try_from(transaction_position).map_err(|_| MerkleProofErrorV2::PositionOutOfRange)?;
    if position >= total_transactions {
        return Err(MerkleProofErrorV2::PositionOutOfRange);
    }

    let mut level = txids.to_vec();
    let mut index = transaction_position;
    let mut siblings = Vec::with_capacity(expected_depth(total_transactions));

    while level.len() > 1 {
        let sibling_index = if index & 1 == 0 {
            index.saturating_add(1).min(level.len().saturating_sub(1))
        } else {
            index.saturating_sub(1)
        };
        let sibling = level
            .get(sibling_index)
            .copied()
            .ok_or(MerkleProofErrorV2::PositionOutOfRange)?;
        siblings.push(sibling);

        let mut next = Vec::with_capacity(next_width_usize(level.len()));
        let mut pair_start = 0usize;
        while pair_start < level.len() {
            let left = level
                .get(pair_start)
                .copied()
                .ok_or(MerkleProofErrorV2::BranchLengthMismatch)?;
            let maybe_right = level.get(pair_start.saturating_add(1)).copied();
            if maybe_right == Some(left) {
                return Err(MerkleProofErrorV2::MutationDetected);
            }
            let right = maybe_right.unwrap_or(left);
            next.push(merkle_parent(left, right));
            pair_start = pair_start.saturating_add(2);
        }
        level = next;
        index >>= 1;
    }

    let merkle_root = level
        .first()
        .copied()
        .ok_or(MerkleProofErrorV2::EmptyTransactionSet)?;
    let branch = UntrustedCompactMerkleBranchV2::new(total_transactions, position, siblings)?;
    let selected_txid = txids
        .get(transaction_position)
        .copied()
        .ok_or(MerkleProofErrorV2::PositionOutOfRange)?;
    if fold_untrusted_compact_branch_v2(selected_txid, &branch)? != merkle_root {
        return Err(MerkleProofErrorV2::BranchLengthMismatch);
    }
    Ok(TxidSetMerkleTreeV2 {
        merkle_root,
        branch,
    })
}

/// Inspects every transaction, rejects every stripped 64-byte transaction,
/// applies the Bitcoin Core mutation scan globally, and checks the header root.
pub(crate) fn verify_full_block_merkle_v2(
    block: &Block,
    transaction_position: usize,
) -> Result<FullBlockMerkleProofV2, MerkleProofErrorV2> {
    let total_transactions = bounded_transaction_count(block.txdata.len())?;
    if transaction_position >= block.txdata.len() {
        return Err(MerkleProofErrorV2::PositionOutOfRange);
    }

    let mut txids = Vec::with_capacity(block.txdata.len());
    for transaction in &block.txdata {
        validate_transaction_size_v2(transaction)?;
        txids.push(transaction.compute_txid().to_raw_hash().to_byte_array());
    }
    let tree = build_mutation_checked_txid_set_v2(&txids, transaction_position)?;
    if tree.merkle_root != block.header.merkle_root.to_raw_hash().to_byte_array() {
        return Err(MerkleProofErrorV2::MerkleRootMismatch);
    }
    Ok(FullBlockMerkleProofV2 {
        merkle_root: tree.merkle_root,
        total_transactions,
        transaction_position: u32::try_from(transaction_position)
            .map_err(|_| MerkleProofErrorV2::PositionOutOfRange)?,
    })
}

fn bounded_transaction_count(count: usize) -> Result<u32, MerkleProofErrorV2> {
    if count == 0 {
        return Err(MerkleProofErrorV2::EmptyTransactionSet);
    }
    let count =
        u32::try_from(count).map_err(|_| MerkleProofErrorV2::TransactionCountBoundExceeded)?;
    if count > MAX_TRANSACTIONS_V2 {
        return Err(MerkleProofErrorV2::TransactionCountBoundExceeded);
    }
    Ok(count)
}

fn validate_shape(
    total_transactions: u32,
    position: u32,
    sibling_count: usize,
) -> Result<(), MerkleProofErrorV2> {
    if total_transactions == 0 {
        return Err(MerkleProofErrorV2::EmptyTransactionSet);
    }
    if total_transactions > MAX_TRANSACTIONS_V2 {
        return Err(MerkleProofErrorV2::TransactionCountBoundExceeded);
    }
    if position >= total_transactions {
        return Err(MerkleProofErrorV2::PositionOutOfRange);
    }
    if sibling_count > MAX_MERKLE_DEPTH_V2 {
        return Err(MerkleProofErrorV2::BranchTooDeep);
    }
    if sibling_count != expected_depth(total_transactions) {
        return Err(MerkleProofErrorV2::BranchLengthMismatch);
    }
    Ok(())
}

fn expected_depth(total_transactions: u32) -> usize {
    let mut width = u64::from(total_transactions);
    let mut depth = 0usize;
    while width > 1 {
        width = next_width(width);
        depth = depth.saturating_add(1);
    }
    depth
}

fn next_width(width: u64) -> u64 {
    width / 2 + width % 2
}

fn next_width_usize(width: usize) -> usize {
    width / 2 + width % 2
}

fn merkle_parent(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    bitcoin::hashes::sha256d::Hash::hash(&bytes).to_byte_array()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::absolute::LockTime;
    use bitcoin::blockdata::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
        TxOut, Txid, Witness,
    };

    use super::*;

    fn legacy_root(txids: &[[u8; 32]]) -> [u8; 32] {
        let mut level = txids.to_vec();
        while level.len() > 1 {
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                next.push(merkle_parent(left, right));
            }
            level = next;
        }
        level[0]
    }

    fn transaction(tag: u8, output_script_bytes: usize, with_witness: bool) -> Transaction {
        let mut witness = Witness::new();
        if with_witness {
            witness.push([0x11; 64]);
        }
        Transaction {
            version: TxVersion(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([tag; 32])),
                    vout: u32::from(tag),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000 + u64::from(tag)),
                script_pubkey: ScriptBuf::from_bytes(vec![tag; output_script_bytes]),
            }],
        }
    }

    fn block(transactions: Vec<Transaction>, merkle_root: [u8; 32]) -> Block {
        Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::from_raw_hash(Hash::from_byte_array(merkle_root)),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: transactions,
        }
    }

    #[test]
    fn core_duplicate_last_vector_is_rejected_at_every_level() {
        let original = vec![[1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]];
        let mut mutated = original.clone();
        mutated.extend_from_slice(&[[5; 32], [6; 32]]);

        assert_eq!(legacy_root(&original), legacy_root(&mutated));
        assert!(build_mutation_checked_txid_set_v2(&original, 0).is_ok());
        assert_eq!(
            build_mutation_checked_txid_set_v2(&mutated, 0).unwrap_err(),
            MerkleProofErrorV2::MutationDetected
        );
        assert_eq!(
            build_mutation_checked_txid_set_v2(&[[1; 32], [2; 32], [1; 32], [2; 32]], 3)
                .unwrap_err(),
            MerkleProofErrorV2::MutationDetected
        );
    }

    #[test]
    fn bitcoin_core_block_170_kat_fixes_multi_tx_byte_order() {
        let txids = [
            Txid::from_str("b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082")
                .expect("Core block 170 coinbase txid")
                .to_raw_hash()
                .to_byte_array(),
            Txid::from_str("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
                .expect("Core block 170 spend txid")
                .to_raw_hash()
                .to_byte_array(),
        ];
        let expected = TxMerkleNode::from_str(
            "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff",
        )
        .expect("Core block 170 Merkle root")
        .to_raw_hash()
        .to_byte_array();

        assert_eq!(
            hex::encode(txids[0]),
            "82501c1178fa0b222c1f3d474ec726b832013f0a532b44bb620cce8624a5feb1"
        );
        assert_eq!(
            hex::encode(txids[1]),
            "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4"
        );
        assert_eq!(
            hex::encode(expected),
            "ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d"
        );

        let tree = build_mutation_checked_txid_set_v2(&txids, 1).expect("known Core tree");
        assert_eq!(tree.merkle_root, expected);
        assert_eq!(tree.branch.total_transactions, 2);
        assert_eq!(tree.branch.position, 1);
    }

    #[test]
    fn shape_and_odd_duplication_are_exact() {
        for (count, expected_depth) in [(1usize, 0usize), (2, 1), (3, 2), (5, 3), (6, 3), (7, 3)] {
            let leaves: Vec<[u8; 32]> = (0..count)
                .map(|index| [(index.saturating_add(1)) as u8; 32])
                .collect();
            for position in 0..count {
                let tree = build_mutation_checked_txid_set_v2(&leaves, position)
                    .expect("valid vector tree");
                assert_eq!(tree.branch.total_transactions, count as u32);
                assert_eq!(tree.branch.position, position as u32);
                assert_eq!(tree.branch.siblings.len(), expected_depth);
                assert_eq!(
                    fold_untrusted_compact_branch_v2(leaves[position], &tree.branch)
                        .expect("canonical branch"),
                    tree.merkle_root
                );
            }
        }

        let leaf = [7; 32];
        let wrong_odd = UntrustedCompactMerkleBranchV2::new(3, 2, vec![[8; 32], [9; 32]])
            .expect("shape is valid independently of hashes");
        assert_eq!(
            fold_untrusted_compact_branch_v2(leaf, &wrong_odd).unwrap_err(),
            MerkleProofErrorV2::NonCanonicalOddDuplication
        );
    }

    #[test]
    fn full_block_rejects_any_ambiguous_64_byte_transaction() {
        let safe = transaction(1, 3, false);
        let ambiguous_with_witness = transaction(2, 4, true);
        assert_eq!(ambiguous_with_witness.base_size(), 64);
        assert!(ambiguous_with_witness.total_size() > 64);

        let transactions = vec![safe, ambiguous_with_witness];
        let txids: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| tx.compute_txid().to_raw_hash().to_byte_array())
            .collect();
        let root = build_mutation_checked_txid_set_v2(&txids, 0)
            .expect("txid list alone cannot detect the ambiguity")
            .merkle_root;
        let candidate_block = block(transactions, root);
        assert_eq!(
            verify_full_block_merkle_v2(&candidate_block, 0).unwrap_err(),
            MerkleProofErrorV2::AmbiguousTransactionSize
        );

        let ambiguous_without_witness = transaction(3, 4, false);
        assert_eq!(ambiguous_without_witness.base_size(), 64);
        assert_eq!(ambiguous_without_witness.total_size(), 64);
        let txids = [ambiguous_without_witness
            .compute_txid()
            .to_raw_hash()
            .to_byte_array()];
        let root = build_mutation_checked_txid_set_v2(&txids, 0)
            .expect("txid list alone cannot detect the ambiguity")
            .merkle_root;
        let candidate_block = block(vec![ambiguous_without_witness], root);
        assert_eq!(
            verify_full_block_merkle_v2(&candidate_block, 0).unwrap_err(),
            MerkleProofErrorV2::AmbiguousTransactionSize
        );
    }
}

//! The evidence verifier (Annex M M.9.3).
//!
//! Fail-closed: incomplete, contradictory, or cross-network proof is
//! rejected. Every parser enforces its cap before allocating (M.10.6).
//! The audited `bitcoin` crate provides double-SHA256, the header target
//! and transaction/witness parsing — never reimplemented (M.0.4).

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{block::Header, Network, Transaction};

use crate::evidence::{
    BitcoinEvidenceNetworkV1, BitcoinOutcomeV1, BoundedMerkleBranchV1, KeystoneBitcoinEvidenceV1,
    VerifiedBitcoinOutcomeV1,
};

/// Verification failures. No variant carries secret material (M.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// The evidence names a known network but carries another network's
    /// genesis hash. Public Signet evidence must never be accepted as a
    /// regtest or custom-Signet artefact (M.13.2).
    #[error("network genesis mismatch")]
    NetworkGenesisMismatch,
    /// The Merkle branch exceeds the depth cap (M.10.6).
    #[error("merkle branch too deep")]
    MerkleBranchTooDeep,
    /// The header did not parse or failed its own proof-of-work target.
    #[error("invalid header or insufficient work")]
    InvalidHeader,
    /// A confirmation header does not link to its predecessor.
    #[error("broken header chain")]
    BrokenHeaderChain,
    /// The txid is not included under the header's Merkle root.
    #[error("merkle inclusion failed")]
    MerkleInclusionFailed,
    /// The raw transaction did not parse.
    #[error("transaction parse failed")]
    TransactionParseFailed,
    /// The transaction's txid does not match the claimed txid.
    #[error("txid mismatch")]
    TxidMismatch,
    /// The transaction's wtxid does not match the claimed wtxid.
    #[error("wtxid mismatch")]
    WtxidMismatch,
    /// The transaction does not spend the expected contractual outpoint.
    #[error("expected outpoint not spent")]
    OutpointNotSpent,
    /// The witness shape contradicts the claimed outcome (e.g. a 65-byte
    /// key-path signature, or an annex — M.9.4).
    #[error("witness shape contradicts outcome")]
    WitnessShapeInvalid,
    /// No confirmations were supplied.
    #[error("insufficient confirmations")]
    InsufficientConfirmations,
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    bitcoin::hashes::sha256d::Hash::hash(bytes).to_byte_array()
}

/// Folds a txid up the Merkle branch and returns the derived root, in the
/// internal byte order used inside the header.
fn merkle_root_from_branch(txid: &[u8; 32], branch: &BoundedMerkleBranchV1) -> [u8; 32] {
    let mut acc = *txid;
    let mut index = branch.position;
    for sibling in &branch.siblings {
        let mut buf = [0u8; 64];
        if index & 1 == 0 {
            buf[..32].copy_from_slice(&acc);
            buf[32..].copy_from_slice(sibling);
        } else {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&acc);
        }
        acc = double_sha256(&buf);
        index >>= 1;
    }
    acc
}

/// Verifies one piece of evidence, returning the verified public outcome
/// (M.9.3). The USPE consumes the return value; `t` never appears here.
pub fn verify_evidence(
    evidence: &KeystoneBitcoinEvidenceV1,
) -> Result<VerifiedBitcoinOutcomeV1, EvidenceError> {
    // Cap the Merkle branch before any work (M.10.6).
    if evidence.txid_merkle_branch.siblings.len() > BoundedMerkleBranchV1::MAX_DEPTH {
        return Err(EvidenceError::MerkleBranchTooDeep);
    }

    // The network enum is not merely a label. Regtest and the globally
    // defined public Signet have canonical genesis blocks; their bytes must
    // agree with the evidence before any header or witness is trusted. A
    // custom Signet has an operator-pinned identity outside this reusable
    // verifier, so its genesis remains an explicit caller commitment.
    let canonical_network = match evidence.network {
        BitcoinEvidenceNetworkV1::Regtest => Some(Network::Regtest),
        BitcoinEvidenceNetworkV1::PublicSignet => Some(Network::Signet),
        BitcoinEvidenceNetworkV1::CustomSignet => None,
    };
    if let Some(network) = canonical_network {
        let expected = genesis_block(network)
            .block_hash()
            .to_raw_hash()
            .to_byte_array();
        if evidence.network_genesis_hash != expected {
            return Err(EvidenceError::NetworkGenesisMismatch);
        }
    }

    // 1. Header parses and meets its own stated proof-of-work target.
    let header: Header =
        deserialize(&evidence.block_header).map_err(|_| EvidenceError::InvalidHeader)?;
    let target = header.target();
    let block_hash = header
        .validate_pow(target)
        .map_err(|_| EvidenceError::InvalidHeader)?;

    // 2. Confirmation chain links header-to-header (M.9.3 step 5).
    if evidence.confirmation_headers.is_empty() {
        return Err(EvidenceError::InsufficientConfirmations);
    }
    let mut prev = block_hash;
    for raw in &evidence.confirmation_headers {
        let next: Header = deserialize(raw).map_err(|_| EvidenceError::InvalidHeader)?;
        let next_hash = next
            .validate_pow(next.target())
            .map_err(|_| EvidenceError::InvalidHeader)?;
        if next.prev_blockhash != prev {
            return Err(EvidenceError::BrokenHeaderChain);
        }
        prev = next_hash;
    }
    let confirmation_depth = u32::try_from(evidence.confirmation_headers.len()).unwrap_or(u32::MAX);

    // 3. Merkle inclusion of the txid under the header's root.
    let derived_root = merkle_root_from_branch(&evidence.txid, &evidence.txid_merkle_branch);
    let header_root = header.merkle_root.to_raw_hash().to_byte_array();
    if derived_root != header_root {
        return Err(EvidenceError::MerkleInclusionFailed);
    }

    // 4. Transaction parses; its txid and wtxid match the claim.
    let tx: Transaction = deserialize(&evidence.raw_transaction)
        .map_err(|_| EvidenceError::TransactionParseFailed)?;
    if tx.compute_txid().to_raw_hash().to_byte_array() != evidence.txid {
        return Err(EvidenceError::TxidMismatch);
    }
    if tx.compute_wtxid().to_raw_hash().to_byte_array() != evidence.wtxid {
        return Err(EvidenceError::WtxidMismatch);
    }

    // 5. It spends the expected contractual outpoint.
    let input = tx
        .input
        .iter()
        .find(|i| {
            i.previous_output.txid.to_raw_hash().to_byte_array() == evidence.expected_outpoint.txid
                && i.previous_output.vout == evidence.expected_outpoint.vout
        })
        .ok_or(EvidenceError::OutpointNotSpent)?;

    // 6. The witness shape matches the claimed outcome (M.9.4).
    verify_witness_shape(&input.witness, evidence.outcome)?;

    Ok(VerifiedBitcoinOutcomeV1 {
        settlement_id: evidence.settlement_id,
        terms_hash: evidence.terms_hash,
        outcome: evidence.outcome,
        txid: evidence.txid,
        wtxid: evidence.wtxid,
        block_hash: block_hash.to_raw_hash().to_byte_array(),
        block_height: evidence.block_height,
        confirmation_depth,
    })
}

/// The key-path claim witness is exactly one 64-byte BIP340 signature (a
/// 65-byte signature — an explicit sighash byte — is rejected, M.9.4). The
/// script-path refund is `[signature, leaf_script, control_block]`. An
/// annex (a final element beginning 0x50 when there are ≥ 2 elements) is
/// forbidden in F5 (M.2.1).
fn verify_witness_shape(
    witness: &bitcoin::Witness,
    outcome: BitcoinOutcomeV1,
) -> Result<(), EvidenceError> {
    let items: Vec<&[u8]> = witness.iter().collect();
    // Reject an annex outright (M.2.1): forbidden in F5 on any path.
    if items.len() >= 2 {
        if let Some(last) = items.last() {
            if last.first() == Some(&0x50) {
                return Err(EvidenceError::WitnessShapeInvalid);
            }
        }
    }
    match outcome {
        BitcoinOutcomeV1::KeyPathClaim => {
            if items.len() != 1 || items[0].len() != 64 {
                return Err(EvidenceError::WitnessShapeInvalid);
            }
        }
        BitcoinOutcomeV1::CsvScriptPathRefund => {
            // signature, leaf script, control block (no annex).
            if items.len() != 3 {
                return Err(EvidenceError::WitnessShapeInvalid);
            }
        }
    }
    Ok(())
}

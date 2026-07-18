//! Node-backed [`dom_wallet::ChainScanSource`] for wallet restore / rescan.
//!
//! Deterministic restore in `dom-wallet`
//! ([`dom_wallet::Wallet::rescan_canonical_chain`],
//! [`dom_wallet::restore_from_phrase`]) reconstructs a wallet's recoverable
//! output set from a [`dom_wallet::ChainScanSource`]: the seed is the sole
//! authority for ownership, but the on-chain coinbases it owns are only
//! discoverable by walking the canonical chain. The trait is the abstraction
//! boundary; until now no node-backed implementation existed — the CLI restored
//! against an empty [`dom_wallet::InMemoryChainScan`] (`recovered_outputs: 0`)
//! and the desktop never scanned at all, so a wallet restored from a seed that
//! already owned coinbases showed a zero balance.
//!
//! This module fills that gap: it reads the canonical blocks the embedded node
//! already has on disk and projects each into a [`dom_wallet::ScanBlock`].
//!
//! ## Coinbase output placement (critical)
//!
//! A block's coinbase output lives in `block.coinbase.output`, NOT in
//! `block.transactions`. The wallet's live mining path never needs to scan it
//! because [`dom_wallet::Wallet::build_coinbase`] registers the owned output
//! directly at mine time. A RESTORED wallet did not mine, so the ONLY way it
//! can recover those rewards is by matching the coinbase commitment from the
//! block. We therefore MUST include `block.coinbase.output.commitment` in the
//! `ScanBlock`'s `output_commitments`, or deterministic coinbase recovery can
//! never match.

use dom_consensus::Block;
use dom_core::DomError;
use dom_serialization::DomDeserialize;
use dom_store::DomStore;
use dom_wallet::{InMemoryChainScan, ScanBlock};

/// Walk canonical heights `0..=tip_height` in `store` and collect a
/// [`ScanBlock`] per height into an in-memory scan source.
///
/// Reads only what the wallet rescan needs — every output commitment (coinbase
/// included), every input commitment, the canonical block hash and the block's
/// total fees — and nothing else (no proofs, no kernels). Collecting into an
/// owned [`InMemoryChainScan`] lets the caller release the chain lock BEFORE the
/// CPU-heavy deterministic rescan (per-height blinding derivation + Pedersen
/// re-commitment) runs, so block connection is not stalled by the scan.
///
/// Heights with no committed block (pruned / gap) are skipped, mirroring the
/// `Ok(None)` contract of [`dom_wallet::ChainScanSource::block_at`].
pub fn collect_chain_scan(
    store: &DomStore,
    tip_height: u64,
) -> Result<InMemoryChainScan, DomError> {
    let mut scan = InMemoryChainScan::new();
    for height in 0..=tip_height {
        if let Some(block) = scan_block_at(store, height)? {
            scan.insert(block);
        }
    }
    Ok(scan)
}

/// Project the canonical block at `height` into a [`ScanBlock`] (coinbase output
/// included, every tx output/input commitment, the block hash and total fees),
/// or `None` if no block is committed there (pruned / gap).
///
/// The single per-block extractor reused by [`collect_chain_scan`] (the embedded
/// rescan) and by the node's `/chain/scan` RPC, so the two never diverge.
pub fn scan_block_at(store: &DomStore, height: u64) -> Result<Option<ScanBlock>, DomError> {
    let Some(hash) = store.get_hash_at_height(height)? else {
        return Ok(None);
    };
    let Some(body) = store.get_block_body(&hash)? else {
        return Ok(None);
    };
    if height == 0 && dom_chain::validate_mainnet_genesis_identity(&body).is_ok() {
        return Ok(Some(ScanBlock {
            height,
            block_hash: Some(hash),
            output_commitments: Vec::new(),
            input_commitments: Vec::new(),
            total_fees_noms: 0,
        }));
    }
    let block = Block::from_bytes(&body).map_err(|e| {
        DomError::Internal(format!("decode canonical block at height {height}: {e}"))
    })?;

    // Coinbase output first (it lives outside `transactions`), then every
    // non-coinbase output. Inputs feed the wallet's spent/unspent rebuild.
    let mut output_commitments = Vec::with_capacity(1 + block.transactions.len());
    output_commitments.push(*block.coinbase.output.commitment.as_bytes());
    let mut input_commitments = Vec::new();
    for tx in &block.transactions {
        for output in &tx.outputs {
            output_commitments.push(*output.commitment.as_bytes());
        }
        for input in &tx.inputs {
            input_commitments.push(*input.commitment.as_bytes());
        }
    }

    let total_fees_noms = block
        .total_fees()
        .map_err(|e| DomError::Internal(format!("total fees at height {height}: {e}")))?;

    Ok(Some(ScanBlock {
        height,
        block_hash: Some(hash),
        output_commitments,
        input_commitments,
        total_fees_noms,
    }))
}

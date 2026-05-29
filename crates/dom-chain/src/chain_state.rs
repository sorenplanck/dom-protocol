#![allow(missing_docs)]
//! Chain state — current tip, validation, block commitment.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_consensus::block::{
    validate_future_timestamp_with_limit, validate_header_syntax, validate_median_time_past,
    validate_parent_timestamp_progression, validate_pow_for_network, BlockHeader,
};
use dom_consensus::{derive_chain_id, validate_block, Block, Transaction, ValidationContext};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp};
use dom_pow::{
    compute_expected_target, genesis_anchor, pow_params_for_network, randomx_seed_height,
    target_to_difficulty, AsertAnchor,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_store::utxo::UtxoEntry;
use dom_store::{DomStore, METADATA_UTXO_SET_DIGEST_KEY};
use primitive_types::U256;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{debug, info};

use crate::reorg::{check_reorg_depth, find_common_ancestor};

/// Sentinel substring callers grep for to recognise a chainstate
/// corruption distinctly from other `DomError::Internal` cases. When
/// `ChainState::open` returns an error containing this string, the
/// safe operator response is "stop the node, move the data_dir aside,
/// re-sync from genesis" — continuing on a corrupted state would
/// fork the local chain from itself.
pub const CHAIN_CORRUPT_SENTINEL: &str = "CHAIN_CORRUPT";
const UTXO_SET_DIGEST_DOMAIN: &[u8] = b"DOM_CANONICAL_UTXO_SET_V1";

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];
type UtxoUpdate = ([u8; 33], Option<Vec<u8>>);
type KernelUpdate = ([u8; 33], Option<[u8; 32]>);

const DEFAULT_SIDE_CHAIN_MAX_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_SIDE_CHAIN_MAX_BRANCHES: usize = 16;

/// Policy for retaining non-canonical side-chain blocks for future reorgs.
///
/// This is chain-selection policy, not consensus. A pruned side branch may be
/// re-delivered and revalidated later; pruning must never make an invalid block
/// valid or mutate canonical state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideChainRetentionPolicy {
    /// Maximum accepted fork depth from the current canonical tip.
    pub max_depth: u64,
    /// Maximum competing side branches retained.
    pub max_branches: usize,
    /// Maximum retained side-chain header/body bytes.
    pub max_bytes: usize,
}

impl Default for SideChainRetentionPolicy {
    fn default() -> Self {
        Self {
            max_depth: dom_core::MAX_REORG_DEPTH_POLICY,
            max_branches: DEFAULT_SIDE_CHAIN_MAX_BRANCHES,
            max_bytes: DEFAULT_SIDE_CHAIN_MAX_BYTES,
        }
    }
}

impl SideChainRetentionPolicy {
    /// Construct a retention policy. Zero values mean "retain none" for that
    /// dimension, which is useful for tests and constrained nodes.
    pub fn new(max_depth: u64, max_branches: usize, max_bytes: usize) -> Self {
        Self {
            max_depth,
            max_branches,
            max_bytes,
        }
    }
}

pub struct ChainState {
    pub store: DomStore,
    pub tip_hash: Hash256,
    pub tip_height: BlockHeight,
    pub tip_difficulty: U256,
    pub genesis_hash: Hash256,
    pub asert_anchor: AsertAnchor,
    pub network_magic: u32,
    /// Bounded retention policy for valid non-canonical side branches.
    pub side_chain_retention: SideChainRetentionPolicy,
    /// Coinbase maturity threshold derived from `network_magic`.
    ///
    /// `COINBASE_MATURITY` for Mainnet/Testnet, `REGTEST_COINBASE_MATURITY`
    /// for Regtest. Stored on the state so the consensus path can apply
    /// the network-specific rule without re-deriving on every block —
    /// and without dragging `dom-config` into the consensus crate.
    pub coinbase_maturity: u64,
}

/// Deterministic expected-target metadata for the next or validated block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTarget {
    /// Previous canonical target expanded from the parent header.
    pub previous_target: [u8; 32],
    /// Canonical target expected for the child header.
    pub next_target: [u8; 32],
    /// Child height minus ASERT anchor height.
    pub height_delta: u64,
    /// Child timestamp minus ASERT anchor timestamp.
    pub actual_elapsed_secs: u64,
    /// Ideal elapsed time for `height_delta` under network ASERT params.
    pub expected_elapsed_secs: u64,
}

/// Deterministic transaction delta produced by a canonical reorganization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReorgDelta {
    /// Common ancestor height that remains canonical after disconnecting the
    /// old branch. Wallet and mempool rollback must rewind effects strictly
    /// above this height before applying the promoted branch.
    pub common_ancestor_height: u64,
    /// Blocks disconnected from the former canonical branch, ordered by
    /// rollback order (old tip back toward the common ancestor).
    pub disconnected_blocks: Vec<ReorgBlockDelta>,
    /// Blocks connected on the promoted branch, ordered from the common
    /// ancestor forward to the new tip.
    pub connected_blocks: Vec<ReorgBlockDelta>,
    /// Transactions disconnected from the former canonical branch, ordered by
    /// rollback order (old tip back toward the common ancestor).
    pub disconnected_txs: Vec<Transaction>,
    /// Transactions connected on the promoted branch, ordered from the common
    /// ancestor forward to the new tip.
    pub connected_txs: Vec<Transaction>,
}

/// Canonical block-level wallet/mempool effect metadata for reorg recovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReorgBlockDelta {
    /// Canonical block hash.
    pub block_hash: [u8; 32],
    /// Canonical block height.
    pub block_height: u64,
    /// Transactions carried by this block.
    pub transactions: Vec<Transaction>,
}

/// Result of one side-chain retention pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SideChainRetentionReport {
    /// Non-canonical blocks kept for possible future reorg work.
    pub retained: Vec<[u8; 32]>,
    /// Non-canonical blocks pruned from header/body storage.
    pub pruned: Vec<[u8; 32]>,
    /// Number of side-branch tips selected by policy.
    pub retained_branches: usize,
    /// Total retained side-chain header/body bytes after shared ancestors are
    /// counted once.
    pub retained_bytes: usize,
}

#[derive(Debug, Clone)]
struct SideBlockInfo {
    header: BlockHeader,
    bytes: usize,
}

#[derive(Debug, Clone)]
struct SideBranch {
    tip_hash: [u8; 32],
    tip_height: u64,
    total_difficulty: U256,
    blocks: Vec<[u8; 32]>,
}

/// Map a 32-bit network magic to the coinbase maturity rule that applies
/// to that network. Mainnet/Testnet/unknown all use the canonical
/// `COINBASE_MATURITY`; Regtest uses `REGTEST_COINBASE_MATURITY`.
///
/// Keeping the resolution here (rather than in `dom-config`) avoids a
/// dependency cycle and keeps `dom-chain` self-contained.
fn coinbase_maturity_for_magic(magic: u32) -> u64 {
    if magic == dom_core::NETWORK_MAGIC_REGTEST {
        dom_core::REGTEST_COINBASE_MATURITY
    } else {
        dom_core::COINBASE_MATURITY
    }
}

fn compute_side_chain_retention(
    store: &DomStore,
    tip_height: u64,
    policy: SideChainRetentionPolicy,
) -> Result<SideChainRetentionReport, DomError> {
    let mut canonical_hashes = BTreeSet::new();
    for height in 0..=tip_height {
        if let Some(hash) = store.get_hash_at_height(height)? {
            canonical_hashes.insert(hash);
        }
    }

    let raw_headers = store.read_all_block_headers_raw()?;
    let mut side_blocks = BTreeMap::new();
    let mut pruned: BTreeSet<[u8; 32]> = BTreeSet::new();

    for (hash, header_bytes) in raw_headers {
        if canonical_hashes.contains(&hash) {
            continue;
        }
        let Ok(header) = BlockHeader::from_bytes(&header_bytes) else {
            pruned.insert(hash);
            continue;
        };
        let Some(body) = store.get_block_body(&hash)? else {
            pruned.insert(hash);
            continue;
        };
        side_blocks.insert(
            hash,
            SideBlockInfo {
                header,
                bytes: header_bytes.len().saturating_add(body.len()),
            },
        );
    }

    let mut side_parents = BTreeSet::new();
    for info in side_blocks.values() {
        let parent = *info.header.prev_hash.as_bytes();
        if side_blocks.contains_key(&parent) {
            side_parents.insert(parent);
        }
    }

    let mut branches = Vec::new();
    for hash in side_blocks.keys() {
        if side_parents.contains(hash) {
            continue;
        }
        if let Some(branch) = collect_side_branch(
            *hash,
            &side_blocks,
            &canonical_hashes,
            tip_height,
            policy.max_depth,
        )? {
            branches.push(branch);
        } else {
            pruned.insert(*hash);
        }
    }

    branches.sort_by(|a, b| {
        b.total_difficulty
            .cmp(&a.total_difficulty)
            .then_with(|| b.tip_height.cmp(&a.tip_height))
            .then_with(|| a.tip_hash.cmp(&b.tip_hash))
    });

    let mut retained = BTreeSet::new();
    let mut retained_bytes = 0usize;
    let mut retained_branches = 0usize;

    for branch in branches {
        if retained_branches >= policy.max_branches {
            continue;
        }
        let incremental_bytes = branch
            .blocks
            .iter()
            .filter(|hash| !retained.contains(*hash))
            .map(|hash| side_blocks.get(hash).map(|info| info.bytes).unwrap_or(0))
            .sum::<usize>();
        if retained_bytes.saturating_add(incremental_bytes) > policy.max_bytes {
            continue;
        }
        for hash in branch.blocks {
            retained.insert(hash);
        }
        retained_bytes = retained_bytes.saturating_add(incremental_bytes);
        retained_branches += 1;
    }

    for hash in side_blocks.keys() {
        if !retained.contains(hash) {
            pruned.insert(*hash);
        }
    }

    Ok(SideChainRetentionReport {
        retained: retained.into_iter().collect(),
        pruned: pruned.into_iter().collect(),
        retained_branches,
        retained_bytes,
    })
}

fn collect_side_branch(
    tip_hash: [u8; 32],
    side_blocks: &BTreeMap<[u8; 32], SideBlockInfo>,
    canonical_hashes: &BTreeSet<[u8; 32]>,
    canonical_tip_height: u64,
    max_depth: u64,
) -> Result<Option<SideBranch>, DomError> {
    let mut blocks = Vec::new();
    let mut cursor = tip_hash;
    let mut seen = BTreeSet::new();

    let ancestor_height = loop {
        if !seen.insert(cursor) {
            return Err(DomError::Internal(
                "side-chain retention cycle detected".into(),
            ));
        }
        let Some(info) = side_blocks.get(&cursor) else {
            return Ok(None);
        };
        blocks.push(cursor);
        let parent = *info.header.prev_hash.as_bytes();
        if canonical_hashes.contains(&parent) {
            // Parent is canonical, so the child's height proves the fork
            // point height without trusting any side-chain index.
            break info.header.height.0.saturating_sub(1);
        }
        cursor = parent;
    };

    let Some(tip) = side_blocks.get(&tip_hash) else {
        return Ok(None);
    };
    let fork_depth = canonical_tip_height.saturating_sub(ancestor_height);
    if fork_depth > max_depth {
        return Ok(None);
    }
    blocks.reverse();
    Ok(Some(SideBranch {
        tip_hash,
        tip_height: tip.header.height.0,
        total_difficulty: tip.header.total_difficulty,
        blocks,
    }))
}

impl ChainState {
    pub fn open(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
    ) -> Result<Self, DomError> {
        let asert_anchor = genesis_anchor(network_magic)
            .map_err(|e| DomError::Internal(format!("genesis anchor: {e}")))?;

        let (tip_hash, tip_height, tip_difficulty) = match store.get_chain_tip()? {
            Some(hash) => {
                let header_bytes = store.get_block_header(&hash)?.ok_or_else(|| {
                    DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: chain_tip {} points at missing header",
                        hex::encode(hash)
                    ))
                })?;
                let header = BlockHeader::from_bytes(&header_bytes)?;
                // Body MUST exist alongside the header — commit_block writes
                // them in the same atomic LMDB txn (RFC-0007 §14). A
                // header-without-body is one of the partial-persistence
                // states the chain-init layer is contractually required to
                // detect (see dom-store/src/db.rs § "Partial-persistence
                // contract").
                if store.get_block_body(&hash)?.is_none() {
                    return Err(DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: tip {} has header but no body",
                        hex::encode(hash)
                    )));
                }
                // The height index MUST match the header's recorded height.
                // A divergence means an interrupted prior write left the two
                // databases pointing at different blocks and continuing to
                // mine from here would fork the local view from itself.
                match store.get_hash_at_height(header.height.0)? {
                    Some(indexed) if indexed == hash => {}
                    Some(other) => {
                        return Err(DomError::Internal(format!(
                            "{CHAIN_CORRUPT_SENTINEL}: height_index[{}] = {} but tip = {}",
                            header.height.0,
                            hex::encode(other),
                            hex::encode(hash)
                        )));
                    }
                    None => {
                        return Err(DomError::Internal(format!(
                            "{CHAIN_CORRUPT_SENTINEL}: tip {} has no height_index entry at height {}",
                            hex::encode(hash),
                            header.height.0
                        )));
                    }
                }
                rebuild_kernel_index_from_canonical_chain(&store, header.height)?;
                ensure_canonical_utxo_set(&store, header.height)?;
                (
                    Hash256::from_bytes(hash),
                    header.height,
                    header.total_difficulty,
                )
            }
            None => {
                ensure_canonical_utxo_set(&store, BlockHeight::GENESIS)?;
                (Hash256::ZERO, BlockHeight::GENESIS, U256::zero())
            }
        };

        Ok(Self {
            store,
            tip_hash,
            tip_height,
            tip_difficulty,
            genesis_hash,
            asert_anchor,
            network_magic,
            coinbase_maturity: coinbase_maturity_for_magic(network_magic),
            side_chain_retention: SideChainRetentionPolicy::default(),
        })
    }

    /// Override side-chain retention bounds.
    ///
    /// Primarily used by tests and constrained deployments. Changing this does
    /// not change consensus validity; it only controls how many valid
    /// non-canonical candidates are kept locally for future reorg promotion.
    pub fn set_side_chain_retention_policy(&mut self, policy: SideChainRetentionPolicy) {
        self.side_chain_retention = policy;
    }

    pub fn connect_block(
        &mut self,
        block: &Block,
        now: Timestamp,
    ) -> Result<ConnectResult, DomError> {
        let header = &block.header;
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_hash(&header_bytes);

        // DOM-SEC-RELAY-LOOP fix: early-return for already-known blocks.
        // Without this check, duplicate blocks (e.g. from relay loops between
        // peers) would re-execute full validation, re-write the store with
        // identical data, and trigger another rebroadcast — creating an
        // infinite amplification loop. Discovered via Doc 8 two_node test
        // on 2026-05-23.
        //
        // DOM-DUP-002 NOTE (audit follow-up, deliberately not implemented):
        // The auditor suggested checking BOTH header AND body to detect
        // partial-write corruption. After analysis, the suggestion was
        // not adopted because:
        //   1. commit_block in dom-store is atomic (RFC-0007 step 14:
        //      all puts under a single txn.commit()). Header existence
        //      implies body existence by construction.
        //   2. If a future refactor breaks that atomicity, the
        //      WriteFlags::NO_OVERWRITE protection from DOM-LMDB-001
        //      (commit 1b26b13) would detect the resulting partial
        //      state on the next connect attempt: re-committing a
        //      header that already exists triggers a KeyExist error
        //      with a loud-fail message identifying the bug.
        //   3. A check that allowed re-commit on partial state would
        //      conflict with the NO_OVERWRITE protection — the
        //      recovery write would itself fail. Better to keep the
        //      loud-fail signal than to mask it with a silent retry.
        // If a future change splits commit_block writes across multiple
        // transactions, the DOM-DUP-002 hardening should be revisited
        // jointly with that change.
        if self
            .store
            .get_block_header(block_hash.as_bytes())?
            .is_some()
        {
            return Ok(ConnectResult::AlreadyHave);
        }

        validate_header_syntax(header)?;

        let parent = if header.height != BlockHeight::GENESIS {
            let parent_bytes = self
                .store
                .get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Orphan(format!("parent {} not found", header.prev_hash))
                })?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;
            let expected_height = parent
                .height
                .checked_next()
                .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
            if header.height != expected_height {
                return Err(DomError::Invalid(format!(
                    "height mismatch: expected {expected_height}, got {}",
                    header.height
                )));
            }
            validate_parent_timestamp_progression(header, &parent)?;
            let ancestors = self.get_recent_timestamps(header.height.0, 11)?;
            validate_median_time_past(header, &ancestors)?;
            Some(parent)
        } else {
            None
        };

        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        let seed = self.compute_randomx_seed(header.height.0)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;

        if let Some(parent_header) = parent.as_ref() {
            self.validate_expected_target(header, parent_header)?;
        }

        let parent_difficulty = parent
            .as_ref()
            .map(|header| header.total_difficulty)
            .unwrap_or_else(U256::zero);

        let block_diff = target_to_difficulty(
            &header
                .target
                .to_target()
                .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
        );
        let expected_total = parent_difficulty.saturating_add(U256::from(block_diff));
        if header.total_difficulty != expected_total {
            return Err(DomError::Invalid(format!(
                "total_difficulty mismatch: expected {expected_total}, got {}",
                header.total_difficulty
            )));
        }

        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        let ctx = ValidationContext {
            current_height: header.height,
            chain_id: *chain_id.as_bytes(),
            now,
        };

        validate_block(block, &ctx).map_err(|e| {
            DomError::Invalid(format!(
                "block validation failed: hash={block_hash}, error={e}"
            ))
        })?;

        // Serialize full block body for IBD responses (peers ask for bodies by hash).
        let block_body_bytes = block.to_bytes()?;
        let kernel_excesses = extract_kernel_excesses(block, block_hash);

        let is_direct_extension =
            header.height == BlockHeight::GENESIS || header.prev_hash == self.tip_hash;
        let extends_best_chain = header.total_difficulty > self.tip_difficulty;

        if is_direct_extension {
            if !extends_best_chain {
                return Err(DomError::Invalid(format!(
                    "direct extension did not increase total_difficulty: new={} current={}",
                    header.total_difficulty, self.tip_difficulty
                )));
            }
            let (new_utxos, spent_utxos) = build_utxo_changeset(block);
            self.validate_direct_extension_inputs(block)?;
            self.store.commit_block(
                block_hash.as_bytes(),
                header.height.0,
                &header_bytes,
                &block_body_bytes,
                &new_utxos,
                &spent_utxos,
                &kernel_excesses,
            )?;
            self.tip_hash = block_hash;
            self.tip_height = header.height;
            self.tip_difficulty = header.total_difficulty;
            info!(
                "New chain tip: height={}, hash={}",
                header.height, block_hash
            );
            Ok(ConnectResult::BestChain)
        } else {
            self.store.store_known_block(
                block_hash.as_bytes(),
                &header_bytes,
                &block_body_bytes,
            )?;
            if extends_best_chain {
                let reorg = self.promote_heavier_known_tip(block_hash)?;
                self.enforce_side_chain_retention()?;
                return Ok(ConnectResult::Reorg(reorg));
            }
            self.enforce_side_chain_retention()?;
            debug!(
                "Side chain block: height={}, hash={}",
                header.height, block_hash
            );
            Ok(ConnectResult::SideChain)
        }
    }

    /// Validate an inbound IBD header batch before requesting any block bodies.
    ///
    /// This is a non-mutating prefilter for the live headers-first path:
    /// every header must decode, link contiguously within the batch, attach to
    /// a known parent (or genesis), and satisfy the same header-only consensus
    /// rules `connect_block` will later enforce once the full block body arrives.
    ///
    /// Returns only the hashes we do not already know, preserving duplicate
    /// suppression while ensuring malformed or discontinuous batches are rejected
    /// before they can trigger body downloads.
    pub fn validate_ibd_headers_batch(
        &self,
        raw_headers: &[Vec<u8>],
        now: Timestamp,
    ) -> Result<Vec<[u8; 32]>, DomError> {
        let mut decoded = Vec::with_capacity(raw_headers.len());
        for header_bytes in raw_headers {
            let header = BlockHeader::from_bytes(header_bytes)?;
            let hash = compute_block_hash(header_bytes);
            let is_known = self.store.get_block_header(hash.as_bytes())?.is_some();
            decoded.push((header, hash, is_known));
        }

        let mut missing_hashes = Vec::with_capacity(decoded.len());
        let mut prior_headers: Vec<BlockHeader> = Vec::with_capacity(decoded.len());

        for (idx, (header, hash, is_known)) in decoded.iter().enumerate() {
            if idx == 0 {
                if header.height != BlockHeight::GENESIS
                    && self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .is_none()
                {
                    return Err(DomError::Orphan(format!(
                        "IBD header batch starts at unknown parent {}",
                        header.prev_hash
                    )));
                }
            } else {
                let (prev_header, prev_hash, _) = &decoded[idx - 1];
                let expected_height = prev_header
                    .height
                    .checked_next()
                    .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
                if header.height != expected_height {
                    return Err(DomError::Invalid(format!(
                        "IBD header gap: expected height {expected_height}, got {}",
                        header.height
                    )));
                }
                if header.prev_hash != *prev_hash {
                    return Err(DomError::Invalid(format!(
                        "IBD header prev_hash mismatch at height {}: expected {}, got {}",
                        header.height, prev_hash, header.prev_hash
                    )));
                }
            }

            if !is_known {
                validate_header_syntax(header)?;

                if header.height != BlockHeight::GENESIS {
                    let parent = if idx == 0 {
                        let parent_bytes = self
                            .store
                            .get_block_header(header.prev_hash.as_bytes())?
                            .ok_or_else(|| {
                                DomError::Internal(
                                    "parent missing after IBD parent precheck".into(),
                                )
                            })?;
                        BlockHeader::from_bytes(&parent_bytes)?
                    } else {
                        decoded[idx - 1].0.clone()
                    };
                    validate_parent_timestamp_progression(header, &parent)?;
                    let ancestors =
                        self.collect_ibd_ancestor_timestamps(header.height.0, &prior_headers, 11)?;
                    validate_median_time_past(header, &ancestors)?;
                }

                validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
                let seed = self.compute_randomx_seed(header.height.0)?;
                validate_pow_for_network(self.network_magic, header, &seed)?;

                if let Some(parent_header) =
                    self.batch_parent_for_index(&decoded, idx, &prior_headers)?
                {
                    self.validate_expected_target(header, &parent_header)?;
                }

                let parent_difficulty = if header.height == BlockHeight::GENESIS {
                    U256::zero()
                } else if idx == 0 {
                    let parent_bytes = self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .ok_or_else(|| {
                            DomError::Internal("parent missing after IBD parent precheck".into())
                        })?;
                    BlockHeader::from_bytes(&parent_bytes)?.total_difficulty
                } else {
                    decoded[idx - 1].0.total_difficulty
                };

                let block_diff = target_to_difficulty(
                    &header
                        .target
                        .to_target()
                        .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
                );
                let expected_total = parent_difficulty.saturating_add(U256::from(block_diff));
                if header.total_difficulty != expected_total {
                    return Err(DomError::Invalid(format!(
                        "total_difficulty mismatch: expected {expected_total}, got {}",
                        header.total_difficulty
                    )));
                }

                missing_hashes.push(*hash.as_bytes());
            }

            prior_headers.push(header.clone());
        }

        Ok(missing_hashes)
    }

    /// Validate exactly one persisted IBD header step without re-validating the
    /// previously verified prefix.
    ///
    /// `verified_header_count` is the number of headers in `raw_headers` whose
    /// ordering and consensus checks have already completed and whose resulting
    /// missing-block hashes are recorded in `prior_missing_hashes`.
    ///
    /// This method re-decodes the ordered prefix only to confirm that the
    /// persisted queue still matches the saved deterministic checkpoint. It
    /// then applies the full header-only consensus checks to the next header at
    /// `verified_header_count`, returning the updated missing-block queue and
    /// the validated header height.
    pub fn validate_ibd_header_step(
        &self,
        raw_headers: &[Vec<u8>],
        verified_header_count: usize,
        prior_missing_hashes: &[[u8; 32]],
        now: Timestamp,
    ) -> Result<(u64, Vec<[u8; 32]>), DomError> {
        if verified_header_count >= raw_headers.len() {
            return Err(DomError::PolicyRejected(format!(
                "persisted header cursor {} exceeds pending header count {}",
                verified_header_count,
                raw_headers.len()
            )));
        }

        let mut decoded_prefix: Vec<(BlockHeader, Hash256, bool)> =
            Vec::with_capacity(verified_header_count.saturating_add(1));
        let mut observed_missing = Vec::with_capacity(prior_missing_hashes.len().saturating_add(1));

        for (idx, header_bytes) in raw_headers
            .iter()
            .take(verified_header_count.saturating_add(1))
            .enumerate()
        {
            let header = BlockHeader::from_bytes(header_bytes)?;
            let hash = compute_block_hash(header_bytes);
            let is_known = self.store.get_block_header(hash.as_bytes())?.is_some();

            if idx == 0 {
                if header.height != BlockHeight::GENESIS
                    && self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .is_none()
                {
                    return Err(DomError::Orphan(format!(
                        "IBD header batch starts at unknown parent {}",
                        header.prev_hash
                    )));
                }
            } else {
                let (prev_header, prev_hash, _) = &decoded_prefix[idx - 1];
                let expected_height = prev_header
                    .height
                    .checked_next()
                    .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
                if header.height != expected_height {
                    return Err(DomError::Invalid(format!(
                        "IBD header gap: expected height {expected_height}, got {}",
                        header.height
                    )));
                }
                if header.prev_hash != *prev_hash {
                    return Err(DomError::Invalid(format!(
                        "IBD header prev_hash mismatch at height {}: expected {}, got {}",
                        header.height, prev_hash, header.prev_hash
                    )));
                }
            }

            if idx < verified_header_count {
                if !is_known {
                    observed_missing.push(*hash.as_bytes());
                }
                decoded_prefix.push((header, hash, is_known));
                continue;
            }

            if observed_missing != prior_missing_hashes {
                return Err(DomError::PolicyRejected(format!(
                    "persisted IBD header prefix mismatch: observed {} missing hashes, expected {}",
                    observed_missing.len(),
                    prior_missing_hashes.len()
                )));
            }

            if !is_known {
                validate_header_syntax(&header)?;

                if header.height != BlockHeight::GENESIS {
                    let parent = if decoded_prefix.is_empty() {
                        let parent_bytes = self
                            .store
                            .get_block_header(header.prev_hash.as_bytes())?
                            .ok_or_else(|| {
                                DomError::Internal(
                                    "parent missing after IBD parent precheck".into(),
                                )
                            })?;
                        BlockHeader::from_bytes(&parent_bytes)?
                    } else {
                        decoded_prefix
                            .last()
                            .expect("decoded prefix not empty")
                            .0
                            .clone()
                    };
                    validate_parent_timestamp_progression(&header, &parent)?;
                    let prior_headers: Vec<BlockHeader> = decoded_prefix
                        .iter()
                        .map(|(prior_header, _, _)| prior_header.clone())
                        .collect();
                    let ancestors =
                        self.collect_ibd_ancestor_timestamps(header.height.0, &prior_headers, 11)?;
                    validate_median_time_past(&header, &ancestors)?;
                }

                validate_future_timestamp_with_limit(&header, now, self.max_future_block_time())?;
                let seed = self.compute_randomx_seed(header.height.0)?;
                validate_pow_for_network(self.network_magic, &header, &seed)?;

                if let Some(parent_header) =
                    self.batch_parent_for_decoded_prefix(&header, &decoded_prefix)?
                {
                    self.validate_expected_target(&header, &parent_header)?;
                }

                let parent_difficulty = if header.height == BlockHeight::GENESIS {
                    U256::zero()
                } else if decoded_prefix.is_empty() {
                    let parent_bytes = self
                        .store
                        .get_block_header(header.prev_hash.as_bytes())?
                        .ok_or_else(|| {
                            DomError::Internal("parent missing after IBD parent precheck".into())
                        })?;
                    BlockHeader::from_bytes(&parent_bytes)?.total_difficulty
                } else {
                    decoded_prefix
                        .last()
                        .expect("decoded prefix not empty")
                        .0
                        .total_difficulty
                };

                let block_diff = target_to_difficulty(
                    &header
                        .target
                        .to_target()
                        .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
                );
                let expected_total = parent_difficulty.saturating_add(U256::from(block_diff));
                if header.total_difficulty != expected_total {
                    return Err(DomError::Invalid(format!(
                        "total_difficulty mismatch: expected {expected_total}, got {}",
                        header.total_difficulty
                    )));
                }

                observed_missing.push(*hash.as_bytes());
            }

            return Ok((header.height.0, observed_missing));
        }

        Err(DomError::Internal(
            "IBD header step finished without validating a header".into(),
        ))
    }

    pub fn validate_header_only(
        &self,
        header: &BlockHeader,
        now: Timestamp,
    ) -> Result<(), DomError> {
        // DOM-IBD-DUP-001 defense: short-circuit if we already have this header.
        // Avoids re-running RandomX (expensive ~10ms) for known-good headers.
        // Currently this function has no production callers (verified via grep),
        // but the early-return is added as defense-in-depth for any future
        // IBD/sync codepath that adopts header-first validation.
        let header_bytes = header.to_bytes()?;
        let header_hash = compute_block_hash(&header_bytes);
        if self
            .store
            .get_block_header(header_hash.as_bytes())?
            .is_some()
        {
            return Ok(());
        }

        validate_header_syntax(header)?;
        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        if header.height != BlockHeight::GENESIS {
            let parent_bytes = self
                .store
                .get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Orphan(format!("parent {} not found", header.prev_hash))
                })?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;
            self.validate_expected_target(header, &parent)?;
        }
        let seed = self.compute_randomx_seed(header.height.0)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;
        Ok(())
    }

    fn max_future_block_time(&self) -> u64 {
        if self.network_magic == dom_core::NETWORK_MAGIC_TESTNET {
            dom_core::TESTNET_MAX_FUTURE_BLOCK_TIME
        } else {
            dom_core::MAX_FUTURE_BLOCK_TIME
        }
    }

    pub fn next_block_target(&self) -> Result<ExpectedTarget, DomError> {
        if self.tip_hash == Hash256::ZERO && self.tip_height == BlockHeight::GENESIS {
            let target = compute_expected_target(
                self.network_magic,
                self.asert_anchor.timestamp,
                BlockHeight::GENESIS,
            )?;
            return Ok(ExpectedTarget {
                previous_target: target,
                next_target: target,
                height_delta: 0,
                actual_elapsed_secs: 0,
                expected_elapsed_secs: 0,
            });
        }

        let tip_bytes = self
            .store
            .get_block_header(self.tip_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("chain tip header missing".into()))?;
        let tip = BlockHeader::from_bytes(&tip_bytes)?;
        let params = pow_params_for_network(self.network_magic);
        let next_height = tip
            .height
            .checked_next()
            .ok_or_else(|| DomError::Invalid("block height overflow".into()))?;
        let next_timestamp = tip
            .timestamp
            .checked_add_secs(params.target_spacing)
            .ok_or_else(|| DomError::Invalid("next block timestamp overflow".into()))?;
        self.expected_target_for_child(&tip, next_timestamp, next_height)
    }

    /// Compute the RandomX seed for a block at `height`.
    ///
    /// Seed = hash of block at `randomx_seed_height(height)`.
    /// For early blocks where the seed_height has no block yet (chain bootstrap),
    /// returns [0u8; 32] by convention.
    fn compute_randomx_seed(&self, height: u64) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);
        match self.store.get_hash_at_height(seed_height)? {
            Some(hash) => Ok(hash),
            None => Ok([0u8; 32]),
        }
    }

    fn validate_expected_target(
        &self,
        header: &BlockHeader,
        parent: &BlockHeader,
    ) -> Result<(), DomError> {
        let expected = self.expected_target_for_child(parent, header.timestamp, header.height)?;
        let actual_target = header
            .target
            .to_target()
            .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?;
        if actual_target != expected.next_target {
            return Err(DomError::Invalid(format!(
                "target mismatch at height {}: expected={} got={} height_delta={} actual_elapsed={} expected_elapsed={}",
                header.height.0,
                hex::encode(expected.next_target),
                hex::encode(actual_target),
                expected.height_delta,
                expected.actual_elapsed_secs,
                expected.expected_elapsed_secs,
            )));
        }
        Ok(())
    }

    fn expected_target_for_child(
        &self,
        parent: &BlockHeader,
        child_timestamp: Timestamp,
        child_height: BlockHeight,
    ) -> Result<ExpectedTarget, DomError> {
        let previous_target = parent
            .target
            .to_target()
            .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?;
        let next_target =
            compute_expected_target(self.network_magic, child_timestamp, child_height)?;
        let params = pow_params_for_network(self.network_magic);
        let height_delta = child_height
            .0
            .checked_sub(self.asert_anchor.height.0)
            .ok_or_else(|| DomError::Invalid("height before ASERT anchor".into()))?;
        let actual_elapsed_secs = child_timestamp
            .0
            .checked_sub(self.asert_anchor.timestamp.0)
            .ok_or_else(|| DomError::Invalid("timestamp before ASERT anchor".into()))?;
        let expected_elapsed_secs = params
            .target_spacing
            .checked_mul(height_delta)
            .ok_or_else(|| DomError::Invalid("ASERT expected elapsed overflow".into()))?;

        Ok(ExpectedTarget {
            previous_target,
            next_target,
            height_delta,
            actual_elapsed_secs,
            expected_elapsed_secs,
        })
    }

    fn batch_parent_for_index(
        &self,
        decoded: &[(BlockHeader, Hash256, bool)],
        idx: usize,
        prior_headers: &[BlockHeader],
    ) -> Result<Option<BlockHeader>, DomError> {
        if decoded[idx].0.height == BlockHeight::GENESIS {
            return Ok(None);
        }
        if idx > 0 {
            return Ok(Some(decoded[idx - 1].0.clone()));
        }
        let parent_bytes = self
            .store
            .get_block_header(decoded[idx].0.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("parent missing after IBD parent precheck".into()))?;
        let parent = BlockHeader::from_bytes(&parent_bytes)?;
        let _ = prior_headers;
        Ok(Some(parent))
    }

    fn batch_parent_for_decoded_prefix(
        &self,
        header: &BlockHeader,
        decoded_prefix: &[(BlockHeader, Hash256, bool)],
    ) -> Result<Option<BlockHeader>, DomError> {
        if header.height == BlockHeight::GENESIS {
            return Ok(None);
        }
        if let Some((parent, _, _)) = decoded_prefix.last() {
            return Ok(Some(parent.clone()));
        }
        let parent_bytes = self
            .store
            .get_block_header(header.prev_hash.as_bytes())?
            .ok_or_else(|| DomError::Internal("parent missing after IBD parent precheck".into()))?;
        Ok(Some(BlockHeader::from_bytes(&parent_bytes)?))
    }

    fn collect_ibd_ancestor_timestamps(
        &self,
        current_height: u64,
        prior_headers: &[BlockHeader],
        count: usize,
    ) -> Result<Vec<Timestamp>, DomError> {
        let mut timestamps = Vec::with_capacity(count);

        for header in prior_headers.iter().rev().take(count) {
            timestamps.push(header.timestamp);
        }

        if timestamps.len() == count {
            return Ok(timestamps);
        }

        let mut h = current_height.saturating_sub(prior_headers.len() as u64 + 1);
        loop {
            if let Some(hash) = self.store.get_hash_at_height(h)? {
                if let Some(header_bytes) = self.store.get_block_header(&hash)? {
                    if let Ok(header) = BlockHeader::from_bytes(&header_bytes) {
                        timestamps.push(header.timestamp);
                        if timestamps.len() == count {
                            break;
                        }
                    }
                }
            }
            if h == 0 {
                break;
            }
            h -= 1;
        }

        Ok(timestamps)
    }

    fn get_recent_timestamps(
        &self,
        current_height: u64,
        count: usize,
    ) -> Result<Vec<Timestamp>, DomError> {
        let mut timestamps = Vec::with_capacity(count);
        let start = current_height.saturating_sub(count as u64);
        for h in (start..current_height).rev() {
            if let Some(hash) = self.store.get_hash_at_height(h)? {
                if let Some(header_bytes) = self.store.get_block_header(&hash)? {
                    if let Ok(header) = BlockHeader::from_bytes(&header_bytes) {
                        timestamps.push(header.timestamp);
                    }
                }
            }
        }
        Ok(timestamps)
    }

    pub fn is_synced(&self, best_peer_height: u64) -> bool {
        self.tip_height.0 + 10 >= best_peer_height
    }

    /// Promote a previously-known heavier side-chain tip into the canonical chain.
    ///
    /// The tip and every ancestor block up to the fork point MUST already be
    /// present in the store via `commit_block` or `store_known_block`.
    pub fn promote_heavier_known_tip(
        &mut self,
        new_tip_hash: Hash256,
    ) -> Result<ReorgDelta, DomError> {
        let new_tip_header = self
            .store
            .get_block_header(new_tip_hash.as_bytes())?
            .ok_or_else(|| {
                DomError::Internal(format!(
                    "reorg target header missing: {}",
                    hex::encode(new_tip_hash.as_bytes())
                ))
            })
            .and_then(|bytes| BlockHeader::from_bytes(&bytes))?;

        if new_tip_header.total_difficulty <= self.tip_difficulty {
            return Err(DomError::PolicyRejected(format!(
                "reorg target is not heavier: new={} current={}",
                new_tip_header.total_difficulty, self.tip_difficulty
            )));
        }

        let ancestor = find_common_ancestor(&self.store, self.tip_hash, new_tip_hash)?
            .filter(|h| *h != Hash256::ZERO)
            .ok_or_else(|| DomError::Invalid("heavier side chain has no common ancestor".into()))?;

        let ancestor_height = if ancestor == self.tip_hash {
            self.tip_height.0
        } else {
            let ancestor_bytes = self
                .store
                .get_block_header(ancestor.as_bytes())?
                .ok_or_else(|| {
                    DomError::Internal(format!(
                        "reorg ancestor header missing: {}",
                        hex::encode(ancestor.as_bytes())
                    ))
                })?;
            BlockHeader::from_bytes(&ancestor_bytes)?.height.0
        };

        let disconnect_blocks = collect_branch_blocks(&self.store, self.tip_hash, ancestor)?;
        check_reorg_depth(disconnect_blocks.len() as u64)?;
        let mut connect_blocks = collect_branch_blocks(&self.store, new_tip_hash, ancestor)?;
        connect_blocks.reverse();
        let chain_id = derive_chain_id(self.network_magic, &self.genesis_hash);
        for (block_hash, block) in &connect_blocks {
            let ctx = ValidationContext {
                current_height: block.header.height,
                chain_id: *chain_id.as_bytes(),
                now: Timestamp(u64::MAX),
            };
            validate_block(block, &ctx).map_err(|e| {
                DomError::Invalid(format!(
                    "reorg candidate block validation failed: hash={}, error={e}",
                    block_hash
                ))
            })?;
        }
        let reorg_delta = ReorgDelta {
            common_ancestor_height: ancestor_height,
            disconnected_blocks: disconnect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            connected_blocks: connect_blocks
                .iter()
                .map(|(block_hash, block)| ReorgBlockDelta {
                    block_hash: *block_hash.as_bytes(),
                    block_height: block.header.height.0,
                    transactions: block.transactions.clone(),
                })
                .collect(),
            disconnected_txs: disconnect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
            connected_txs: connect_blocks
                .iter()
                .flat_map(|(_, block)| block.transactions.clone())
                .collect(),
        };

        let mut disconnect_output_index = HashMap::new();
        for (_, block) in &disconnect_blocks {
            record_block_outputs(block, &mut disconnect_output_index);
        }

        let mut utxo_overlay: BTreeMap<[u8; 33], Option<UtxoEntry>> = BTreeMap::new();
        let mut kernel_overlay: BTreeMap<[u8; 33], Option<[u8; 32]>> = BTreeMap::new();

        for (block_hash, block) in &disconnect_blocks {
            apply_disconnect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                ancestor_height,
                &disconnect_output_index,
            )?;
        }

        for (block_hash, block) in &connect_blocks {
            apply_connect(
                &self.store,
                &mut utxo_overlay,
                &mut kernel_overlay,
                *block_hash,
                block,
                self.coinbase_maturity,
            )?;
        }

        let mut height_updates = BTreeMap::new();
        for height in (ancestor_height + 1)..=self.tip_height.0 {
            height_updates.insert(height, None);
        }
        for (block_hash, block) in &connect_blocks {
            height_updates.insert(block.header.height.0, Some(*block_hash.as_bytes()));
        }
        let height_updates: Vec<(u64, Option<[u8; 32]>)> = height_updates.into_iter().collect();

        let utxo_updates = build_utxo_updates(&self.store, &utxo_overlay)?;
        let kernel_updates = build_kernel_updates(&self.store, &kernel_overlay)?;

        self.store.apply_reorg(
            new_tip_hash.as_bytes(),
            &height_updates,
            &utxo_updates,
            &kernel_updates,
        )?;

        self.tip_hash = new_tip_hash;
        self.tip_height = new_tip_header.height;
        self.tip_difficulty = new_tip_header.total_difficulty;
        info!(
            "Reorg applied: new tip height={}, hash={}, ancestor={}",
            self.tip_height, self.tip_hash, ancestor
        );
        Ok(reorg_delta)
    }

    /// Enforce bounded side-chain retention.
    ///
    /// Canonical blocks are never deleted. Non-canonical branches are ranked by
    /// cumulative difficulty, then height, then hash. For each retained branch,
    /// the full side-chain path back to the canonical fork point is retained so
    /// promotion has every required body. Branches deeper than policy, beyond
    /// the branch cap, or beyond the byte cap are pruned by deleting their
    /// retained header/body pairs only.
    pub fn enforce_side_chain_retention(&mut self) -> Result<SideChainRetentionReport, DomError> {
        let report = compute_side_chain_retention(
            &self.store,
            self.tip_height.0,
            self.side_chain_retention,
        )?;
        for hash in &report.pruned {
            self.store.delete_known_block(hash)?;
        }
        Ok(report)
    }

    fn validate_direct_extension_inputs(&self, block: &Block) -> Result<(), DomError> {
        let header = &block.header;
        for tx in &block.transactions {
            for input in &tx.inputs {
                let commitment_bytes = input.commitment.as_bytes();
                let entry = self.store.get_utxo(commitment_bytes)?.ok_or_else(|| {
                    DomError::Invalid(format!(
                        "input commitment not found in UTXO set: {}",
                        hex::encode(commitment_bytes)
                    ))
                })?;
                if entry.is_coinbase
                    && !entry.is_mature_for(header.height.0, self.coinbase_maturity)
                {
                    return Err(DomError::Invalid(format!(
                        "immature coinbase spend at height {} (created at {}, maturity {})",
                        header.height.0, entry.block_height, self.coinbase_maturity
                    )));
                }
            }
        }
        Ok(())
    }
}

fn ensure_canonical_utxo_set(store: &DomStore, tip_height: BlockHeight) -> Result<(), DomError> {
    let canonical = reconstruct_canonical_utxo_set(store, tip_height)?;
    let canonical_digest = digest_utxo_entries(&canonical);
    let persisted = store.read_all_utxos_raw()?;
    let persisted_digest = store.get_metadata(METADATA_UTXO_SET_DIGEST_KEY)?;
    let canonical_raw: BTreeMap<Vec<u8>, Vec<u8>> = canonical
        .iter()
        .map(|(commitment, entry)| (commitment.to_vec(), entry.clone()))
        .collect();

    if persisted == canonical_raw {
        if persisted_digest.as_deref() != Some(canonical_digest.as_slice()) {
            store.persist_utxo_set_digest(&canonical_digest)?;
        }
        return Ok(());
    }

    info!(
        "Canonical UTXO reconstruction diverged on reopen; replacing persisted set (persisted_entries={}, canonical_entries={})",
        persisted.len(),
        canonical.len()
    );
    store.replace_utxo_set(&canonical, &canonical_digest)
}

fn reconstruct_canonical_utxo_set(
    store: &DomStore,
    tip_height: BlockHeight,
) -> Result<BTreeMap<[u8; 33], Vec<u8>>, DomError> {
    let mut utxos = BTreeMap::new();
    for h in 1..=tip_height.0 {
        let hash = store.get_hash_at_height(h)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: missing canonical height_index entry at height {h} during UTXO rebuild"
            ))
        })?;
        let body = store.get_block_body(&hash)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} has no body during UTXO rebuild",
                hex::encode(hash)
            ))
        })?;
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} body decode failed during UTXO rebuild: {e}",
                hex::encode(hash)
            ))
        })?;
        let header_bytes = block.header.to_bytes()?;
        let computed = compute_block_hash(&header_bytes);
        if computed.as_bytes() != &hash {
            return Err(DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block body/header hash mismatch at height {h} during UTXO rebuild: height_index={} body_header={}",
                hex::encode(hash),
                computed
            )));
        }

        let coinbase_commitment = *block.coinbase.output.commitment.as_bytes();
        let coinbase_entry = UtxoEntry {
            block_height: block.header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        };
        if utxos
            .insert(coinbase_commitment, coinbase_entry.to_bytes())
            .is_some()
        {
            return Err(DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: duplicate coinbase UTXO commitment {} at height {} during UTXO rebuild",
                hex::encode(coinbase_commitment),
                h
            )));
        }

        for tx in &block.transactions {
            for input in &tx.inputs {
                let commitment = *input.commitment.as_bytes();
                if utxos.remove(&commitment).is_none() {
                    return Err(DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: canonical spend references missing UTXO {} at height {} during UTXO rebuild",
                        hex::encode(commitment),
                        h
                    )));
                }
            }
            for output in &tx.outputs {
                let commitment = *output.commitment.as_bytes();
                let entry = UtxoEntry {
                    block_height: block.header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                };
                if utxos.insert(commitment, entry.to_bytes()).is_some() {
                    return Err(DomError::Internal(format!(
                        "{CHAIN_CORRUPT_SENTINEL}: duplicate output UTXO commitment {} at height {} during UTXO rebuild",
                        hex::encode(commitment),
                        h
                    )));
                }
            }
        }
    }
    Ok(utxos)
}

fn digest_utxo_entries(utxos: &BTreeMap<[u8; 33], Vec<u8>>) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut hasher = B2b256::new();
    hasher.update(UTXO_SET_DIGEST_DOMAIN);
    for (commitment, entry) in utxos {
        hasher.update(commitment);
        hasher.update((entry.len() as u32).to_le_bytes());
        hasher.update(entry);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn rebuild_kernel_index_from_canonical_chain(
    store: &DomStore,
    tip_height: BlockHeight,
) -> Result<(), DomError> {
    for h in 1..=tip_height.0 {
        let hash = store.get_hash_at_height(h)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: missing canonical height_index entry at height {h}"
            ))
        })?;
        let body = store.get_block_body(&hash)?.ok_or_else(|| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} has no body",
                hex::encode(hash)
            ))
        })?;
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} body decode failed during kernel-index rebuild: {e}",
                hex::encode(hash)
            ))
        })?;
        let header_bytes = block.header.to_bytes()?;
        let computed = compute_block_hash(&header_bytes);
        if computed.as_bytes() != &hash {
            return Err(DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block body/header hash mismatch at height {h}: height_index={} body_header={}",
                hex::encode(hash),
                computed
            )));
        }
        let kernel_excesses = extract_kernel_excesses(&block, computed);
        store.ensure_kernel_indices(&kernel_excesses)?;
    }
    Ok(())
}

fn extract_kernel_excesses(block: &Block, block_hash: Hash256) -> Vec<([u8; 33], [u8; 32])> {
    let mut out = Vec::with_capacity(
        1 + block
            .transactions
            .iter()
            .map(|tx| tx.kernels.len())
            .sum::<usize>(),
    );
    out.push((
        *block.coinbase.kernel.excess.as_bytes(),
        *block_hash.as_bytes(),
    ));
    for tx in &block.transactions {
        for kernel in &tx.kernels {
            out.push((*kernel.excess.as_bytes(), *block_hash.as_bytes()));
        }
    }
    out
}

fn build_utxo_changeset(block: &Block) -> (Vec<UtxoBytes>, Vec<SpentCommitment>) {
    let header = &block.header;
    let mut new_utxos: Vec<([u8; 33], Vec<u8>)> = Vec::new();
    let coinbase_entry = UtxoEntry {
        block_height: header.height.0,
        is_coinbase: true,
        proof: block.coinbase.output.proof.clone(),
    };
    new_utxos.push((
        *block.coinbase.output.commitment.as_bytes(),
        coinbase_entry.to_bytes(),
    ));

    let mut spent_utxos: Vec<[u8; 33]> = Vec::new();
    for tx in &block.transactions {
        for input in &tx.inputs {
            spent_utxos.push(*input.commitment.as_bytes());
        }
        for output in &tx.outputs {
            let entry = UtxoEntry {
                block_height: header.height.0,
                is_coinbase: false,
                proof: output.proof.clone(),
            };
            new_utxos.push((*output.commitment.as_bytes(), entry.to_bytes()));
        }
    }
    (new_utxos, spent_utxos)
}

fn collect_branch_blocks(
    store: &DomStore,
    mut tip: Hash256,
    ancestor: Hash256,
) -> Result<Vec<(Hash256, Block)>, DomError> {
    let mut out = Vec::new();
    while tip != ancestor {
        let body = store.get_block_body(tip.as_bytes())?.ok_or_else(|| {
            DomError::Internal(format!(
                "reorg block body missing: {}",
                hex::encode(tip.as_bytes())
            ))
        })?;
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "reorg block body decode failed for {}: {e}",
                hex::encode(tip.as_bytes())
            ))
        })?;
        tip = block.header.prev_hash;
        out.push((compute_block_hash(&block.header.to_bytes()?), block));
    }
    Ok(out)
}

fn record_block_outputs(block: &Block, out: &mut HashMap<[u8; 33], UtxoEntry>) {
    out.insert(
        *block.coinbase.output.commitment.as_bytes(),
        UtxoEntry {
            block_height: block.header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        },
    );
    for tx in &block.transactions {
        for output in &tx.outputs {
            out.insert(
                *output.commitment.as_bytes(),
                UtxoEntry {
                    block_height: block.header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                },
            );
        }
    }
}

fn apply_disconnect(
    store: &DomStore,
    utxo_overlay: &mut BTreeMap<[u8; 33], Option<UtxoEntry>>,
    kernel_overlay: &mut BTreeMap<[u8; 33], Option<[u8; 32]>>,
    block_hash: Hash256,
    block: &Block,
    ancestor_height: u64,
    disconnect_output_index: &HashMap<[u8; 33], UtxoEntry>,
) -> Result<(), DomError> {
    utxo_overlay.insert(*block.coinbase.output.commitment.as_bytes(), None);
    for tx in &block.transactions {
        for output in &tx.outputs {
            utxo_overlay.insert(*output.commitment.as_bytes(), None);
        }
    }

    for tx in &block.transactions {
        for input in &tx.inputs {
            let commitment = *input.commitment.as_bytes();
            let resurrected = disconnect_output_index
                .get(&commitment)
                .cloned()
                .or(find_canonical_output_entry(
                    store,
                    ancestor_height,
                    &commitment,
                )?)
                .ok_or_else(|| {
                    DomError::Internal(format!(
                        "reorg disconnect could not resurrect spent output {}",
                        hex::encode(commitment)
                    ))
                })?;
            utxo_overlay.insert(commitment, Some(resurrected));
        }
    }

    for (excess, _) in extract_kernel_excesses(block, block_hash) {
        kernel_overlay.insert(excess, None);
    }
    Ok(())
}

fn apply_connect(
    store: &DomStore,
    utxo_overlay: &mut BTreeMap<[u8; 33], Option<UtxoEntry>>,
    kernel_overlay: &mut BTreeMap<[u8; 33], Option<[u8; 32]>>,
    block_hash: Hash256,
    block: &Block,
    coinbase_maturity: u64,
) -> Result<(), DomError> {
    for tx in &block.transactions {
        for input in &tx.inputs {
            let commitment = *input.commitment.as_bytes();
            let entry = lookup_utxo(store, utxo_overlay, &commitment)?.ok_or_else(|| {
                DomError::Invalid(format!(
                    "reorg connect missing input commitment {}",
                    hex::encode(commitment)
                ))
            })?;
            if entry.is_coinbase && !entry.is_mature_for(block.header.height.0, coinbase_maturity) {
                return Err(DomError::Invalid(format!(
                    "reorg connect spends immature coinbase at height {} (created at {}, maturity {})",
                    block.header.height.0, entry.block_height, coinbase_maturity
                )));
            }
            utxo_overlay.insert(commitment, None);
        }
    }

    let coinbase_commitment = *block.coinbase.output.commitment.as_bytes();
    if lookup_utxo(store, utxo_overlay, &coinbase_commitment)?.is_some() {
        return Err(DomError::Invalid(format!(
            "reorg connect duplicate output commitment {}",
            hex::encode(coinbase_commitment)
        )));
    }
    utxo_overlay.insert(
        coinbase_commitment,
        Some(UtxoEntry {
            block_height: block.header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        }),
    );

    for tx in &block.transactions {
        for output in &tx.outputs {
            let commitment = *output.commitment.as_bytes();
            if lookup_utxo(store, utxo_overlay, &commitment)?.is_some() {
                return Err(DomError::Invalid(format!(
                    "reorg connect duplicate output commitment {}",
                    hex::encode(commitment)
                )));
            }
            utxo_overlay.insert(
                commitment,
                Some(UtxoEntry {
                    block_height: block.header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                }),
            );
        }
    }

    for (excess, indexed_block) in extract_kernel_excesses(block, block_hash) {
        if lookup_kernel(store, kernel_overlay, &excess)?.is_some() {
            return Err(DomError::Invalid(format!(
                "reorg connect kernel replay detected: excess={}",
                hex::encode(excess)
            )));
        }
        kernel_overlay.insert(excess, Some(indexed_block));
    }

    Ok(())
}

fn lookup_utxo(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<UtxoEntry>>,
    commitment: &[u8; 33],
) -> Result<Option<UtxoEntry>, DomError> {
    if let Some(entry) = overlay.get(commitment) {
        return Ok(entry.clone());
    }
    store.get_utxo(commitment)
}

fn lookup_kernel(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<[u8; 32]>>,
    excess: &[u8; 33],
) -> Result<Option<[u8; 32]>, DomError> {
    if let Some(entry) = overlay.get(excess) {
        return Ok(*entry);
    }
    store.get_kernel_block(excess)
}

fn find_canonical_output_entry(
    store: &DomStore,
    ancestor_height: u64,
    commitment: &[u8; 33],
) -> Result<Option<UtxoEntry>, DomError> {
    for height in (0..=ancestor_height).rev() {
        let Some(hash) = store.get_hash_at_height(height)? else {
            continue;
        };
        let Some(body) = store.get_block_body(&hash)? else {
            continue;
        };
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "decode canonical block {} while resurrecting {}: {e}",
                hex::encode(hash),
                hex::encode(commitment)
            ))
        })?;
        if block.coinbase.output.commitment.as_bytes() == commitment {
            return Ok(Some(UtxoEntry {
                block_height: block.header.height.0,
                is_coinbase: true,
                proof: block.coinbase.output.proof.clone(),
            }));
        }
        for tx in &block.transactions {
            for output in &tx.outputs {
                if output.commitment.as_bytes() == commitment {
                    return Ok(Some(UtxoEntry {
                        block_height: block.header.height.0,
                        is_coinbase: false,
                        proof: output.proof.clone(),
                    }));
                }
            }
        }
    }
    Ok(None)
}

fn build_utxo_updates(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<UtxoEntry>>,
) -> Result<Vec<UtxoUpdate>, DomError> {
    let mut out = Vec::new();
    for (commitment, desired) in overlay {
        let current = store.get_utxo(commitment)?;
        match (current, desired) {
            (Some(current), Some(desired)) if current.to_bytes() == desired.to_bytes() => {}
            (Some(current), Some(desired)) => {
                return Err(DomError::Internal(format!(
                    "reorg utxo mismatch for existing commitment {}: current_height={} desired_height={}",
                    hex::encode(commitment),
                    current.block_height,
                    desired.block_height
                )));
            }
            (None, Some(desired)) => out.push((*commitment, Some(desired.to_bytes()))),
            (Some(_), None) => out.push((*commitment, None)),
            (None, None) => {}
        }
    }
    Ok(out)
}

fn build_kernel_updates(
    store: &DomStore,
    overlay: &BTreeMap<[u8; 33], Option<[u8; 32]>>,
) -> Result<Vec<KernelUpdate>, DomError> {
    let mut out = Vec::new();
    for (excess, desired) in overlay {
        let current = store.get_kernel_block(excess)?;
        if current != *desired {
            out.push((*excess, *desired));
        }
    }
    Ok(out)
}

/// Outcome of attempting to connect a block to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectResult {
    /// Block extended the best chain — new tip. Caller should rebroadcast.
    BestChain,
    /// Block promoted a heavier known side branch into the canonical chain.
    Reorg(ReorgDelta),
    /// Block is valid but on a side chain (lower or equal total difficulty).
    /// Caller should NOT rebroadcast — would cause network amplification.
    SideChain,
    /// Block was already known (hash already in store). No-op.
    /// Caller MUST NOT rebroadcast or re-validate. Critical for preventing
    /// relay loops (DOM-SEC-RELAY-LOOP, 2026-05-23).
    AlreadyHave,
}

fn compute_block_hash(header_bytes: &[u8]) -> Hash256 {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(header_bytes);
    let result = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Hash256::from_bytes(arr)
}

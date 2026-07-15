#![allow(missing_docs)]
//! Chain state — current tip, validation, block commitment.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_consensus::block::{
    validate_future_timestamp_with_limit, validate_header_syntax, validate_median_time_past,
    validate_parent_timestamp_progression, validate_pow_for_network, BlockHeader,
};
use dom_consensus::{
    checked_accumulated_difficulty, derive_chain_id, validate_block, Block, Transaction,
    ValidationContext,
};
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
use tracing::{debug, error, info};

use crate::reorg::{check_reorg_depth, find_common_ancestor};

/// Sentinel substring callers grep for to recognise a chainstate
/// corruption distinctly from other `DomError::Internal` cases. When
/// `ChainState::open` returns an error containing this string, the
/// safe operator response is "stop the node, move the data_dir aside,
/// re-sync from genesis" — continuing on a corrupted state would
/// fork the local chain from itself.
pub const CHAIN_CORRUPT_SENTINEL: &str = "CHAIN_CORRUPT";
const UTXO_SET_DIGEST_DOMAIN: &[u8] = b"DOM_CANONICAL_UTXO_SET_V1";
pub const MAX_RETAINED_SIDE_BRANCH_TIPS: usize = 8;
pub const MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH: u64 = dom_core::MAX_REORG_DEPTH_POLICY;
pub const MAX_RETAINED_SIDE_BRANCH_LENGTH: u64 = dom_core::MAX_REORG_DEPTH_POLICY;

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];
type KernelExcess = ([u8; 33], [u8; 32]);
type UtxoUpdate = ([u8; 33], Option<Vec<u8>>);
type KernelUpdate = ([u8; 33], Option<[u8; 32]>);

pub struct ChainState {
    pub store: DomStore,
    pub tip_hash: Hash256,
    pub tip_height: BlockHeight,
    pub tip_difficulty: U256,
    pub genesis_hash: Hash256,
    pub asert_anchor: AsertAnchor,
    pub network_magic: u32,
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

fn is_better_fork_choice_tip(
    candidate_total_difficulty: U256,
    candidate_hash: Hash256,
    current_total_difficulty: U256,
    current_hash: Hash256,
) -> bool {
    candidate_total_difficulty > current_total_difficulty
        || (candidate_total_difficulty == current_total_difficulty
            && candidate_hash.as_bytes() < current_hash.as_bytes())
}

impl ChainState {
    /// Default startup path. A divergence between the persisted UTXO set and
    /// the canonical set reconstructed from committed block history is treated
    /// as fatal corruption (FIX-020): the node refuses to open rather than
    /// silently healing a possibly-tampered set. Recovery is operator-driven
    /// via [`ChainState::open_with_utxo_repair`].
    pub fn open(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
    ) -> Result<Self, DomError> {
        Self::open_inner(store, genesis_hash, network_magic, false)
    }

    /// Explicit operator recovery entry point. Identical to [`ChainState::open`]
    /// except that a divergence between the persisted UTXO set and the canonical
    /// set reconstructed from block history is REPAIRED (the persisted set is
    /// replaced by the canonical one) instead of being rejected as fatal
    /// corruption. This is the opt-in the fatal error raised by
    /// [`ChainState::open`] instructs the operator to use; it must never be the
    /// unattended default startup path, because a node must not silently run on
    /// a divergent UTXO set without human intervention.
    pub fn open_with_utxo_repair(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
    ) -> Result<Self, DomError> {
        Self::open_inner(store, genesis_hash, network_magic, true)
    }

    fn open_inner(
        store: DomStore,
        genesis_hash: Hash256,
        network_magic: u32,
        allow_utxo_repair: bool,
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
                rebuild_kernel_index_from_canonical_chain(&store, header.height, network_magic)?;
                ensure_canonical_utxo_set(&store, header.height, network_magic, allow_utxo_repair)?;
                prune_retained_side_chains(&store, header.height, hash)?;
                (
                    Hash256::from_bytes(hash),
                    header.height,
                    header.total_difficulty,
                )
            }
            None => {
                prune_retained_side_chains(&store, BlockHeight::GENESIS, [0u8; 32])?;
                (Hash256::ZERO, BlockHeight::GENESIS, U256::zero())
            }
        };

        validate_persisted_genesis_identity(&store, genesis_hash)?;

        Ok(Self {
            store,
            tip_hash,
            tip_height,
            tip_difficulty,
            genesis_hash,
            asert_anchor,
            network_magic,
            coinbase_maturity: coinbase_maturity_for_magic(network_magic),
        })
    }

    pub fn connect_block(
        &mut self,
        block: &Block,
        now: Timestamp,
    ) -> Result<ConnectResult, DomError> {
        let header = &block.header;
        let header_bytes = header.to_bytes()?;
        let block_hash = compute_block_identifier(self.network_magic, &header_bytes)?;

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
        self.validate_genesis_identity(header, block_hash)?;

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
            let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
            validate_median_time_past(header, &ancestors)?;
            Some(parent)
        } else {
            None
        };

        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
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
        let expected_total = checked_accumulated_difficulty(parent_difficulty, block_diff)?;
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
        let extends_best_chain = is_better_fork_choice_tip(
            header.total_difficulty,
            block_hash,
            self.tip_difficulty,
            self.tip_hash,
        );

        if is_direct_extension {
            if !extends_best_chain {
                return Err(DomError::Invalid(format!(
                    "direct extension did not improve fork choice: new_total={} current_total={} new_hash={} current_hash={}",
                    header.total_difficulty, self.tip_difficulty, block_hash, self.tip_hash
                )));
            }
            let (new_utxos, spent_utxos) = build_utxo_changeset(block);
            self.validate_direct_extension_inputs(block)?;

            // R-06: explicit kernel/output uniqueness against ALREADY-PERSISTED
            // chain state, on the direct connect path, returning Invalid so a
            // replaying peer is ban-scored (DomError::increases_ban_score). The
            // storage layer's NO_OVERWRITE guard in dom-store::commit_block maps
            // the same duplicate to DomError::Internal, which does NOT raise ban
            // score; the reorg path (apply_connect) already rejects this as
            // Invalid. Mirror that wording here (swap "reorg" -> "direct").
            //
            // This runs BEFORE commit_block, so the block being connected is not
            // yet persisted and therefore cannot collide with itself; intra-block
            // duplicate outputs/inputs are already rejected by validate_block, so
            // this only catches collisions against prior persisted state. The
            // direct path has no pending overlay, so plain store lookups suffice.
            for output in std::iter::once(&block.coinbase.output)
                .chain(block.transactions.iter().flat_map(|tx| tx.outputs.iter()))
            {
                let commitment = *output.commitment.as_bytes();
                if self.store.get_utxo(&commitment)?.is_some() {
                    return Err(DomError::Invalid(format!(
                        "direct connect duplicate output commitment {}",
                        hex::encode(commitment)
                    )));
                }
            }
            for (excess, _) in &kernel_excesses {
                if self.store.get_kernel_block(excess)?.is_some() {
                    return Err(DomError::Invalid(format!(
                        "direct connect kernel replay detected: excess={}",
                        hex::encode(excess)
                    )));
                }
            }

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
            prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
            info!(
                "New chain tip: height={}, hash={}",
                header.height, block_hash
            );
            Ok(ConnectResult::BestChain)
        } else {
            // DOM-FINAL-006: side-chain quarantine is intentionally persisted
            // after full block validation but before contextual input checks.
            // `validate_block` above already verified cryptography, balance,
            // range proofs, kernel signatures, cut-through, and weight. Input
            // existence/maturity must be checked against the candidate branch
            // UTXO set, which is reconstructed during promotion; doing that for
            // every retained side block would turn branch spam into CPU work.
            // Retention is bounded by `prune_retained_side_chains`, and invalid
            // branch inputs still fail closed in `promote_heavier_known_tip`.
            self.store.store_known_block(
                block_hash.as_bytes(),
                &header_bytes,
                &block_body_bytes,
            )?;
            prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
            if extends_best_chain {
                let reorg = self.promote_heavier_known_tip(block_hash, now)?;
                return Ok(ConnectResult::Reorg(reorg));
            }
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
            let hash = compute_block_identifier(self.network_magic, header_bytes)?;
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
                self.validate_genesis_identity(header, *hash)?;

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
                let seed = self.compute_randomx_seed_with_batch(header.height.0, &decoded)?;
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
                let expected_total = checked_accumulated_difficulty(parent_difficulty, block_diff)?;
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
            let hash = compute_block_identifier(self.network_magic, header_bytes)?;
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
                self.validate_genesis_identity(&header, hash)?;

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
                let seed =
                    self.compute_randomx_seed_with_batch(header.height.0, &decoded_prefix)?;
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
                let expected_total = checked_accumulated_difficulty(parent_difficulty, block_diff)?;
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
        let header_hash = compute_block_identifier(self.network_magic, &header_bytes)?;
        if self
            .store
            .get_block_header(header_hash.as_bytes())?
            .is_some()
        {
            return Ok(());
        }

        validate_header_syntax(header)?;
        self.validate_genesis_identity(header, header_hash)?;
        validate_future_timestamp_with_limit(header, now, self.max_future_block_time())?;
        if header.height != BlockHeight::GENESIS {
            let parent_bytes = self
                .store
                .get_block_header(header.prev_hash.as_bytes())?
                .ok_or_else(|| {
                    DomError::Orphan(format!("parent {} not found", header.prev_hash))
                })?;
            let parent = BlockHeader::from_bytes(&parent_bytes)?;
            validate_parent_timestamp_progression(header, &parent)?;
            let ancestors = self.get_recent_timestamps(header.prev_hash, 11)?;
            validate_median_time_past(header, &ancestors)?;
            self.validate_expected_target(header, &parent)?;

            let block_diff = target_to_difficulty(
                &header
                    .target
                    .to_target()
                    .map_err(|e| DomError::Invalid(format!("invalid target: {e}")))?,
            );
            let expected_total =
                checked_accumulated_difficulty(parent.total_difficulty, block_diff)?;
            if header.total_difficulty != expected_total {
                return Err(DomError::Invalid(format!(
                    "total_difficulty mismatch: expected {expected_total}, got {}",
                    header.total_difficulty
                )));
            }
        }
        let seed = self.compute_randomx_seed_branch_aware(header.height.0, header.prev_hash)?;
        validate_pow_for_network(self.network_magic, header, &seed)?;
        Ok(())
    }

    fn validate_genesis_identity(
        &self,
        header: &BlockHeader,
        header_hash: Hash256,
    ) -> Result<(), DomError> {
        if header.height != BlockHeight::GENESIS {
            return Ok(());
        }

        if self.network_magic == dom_core::NETWORK_MAGIC_MAINNET {
            return Err(DomError::Invalid(
                "Mainnet genesis is accepted only through the canonical identity-envelope bootstrap path"
                    .into(),
            ));
        }

        if self.genesis_hash != Hash256::ZERO && header_hash != self.genesis_hash {
            return Err(DomError::Invalid(format!(
                "genesis hash mismatch: expected {}, got {}",
                self.genesis_hash, header_hash
            )));
        }

        if let Some(existing) = self.store.get_hash_at_height(BlockHeight::GENESIS.0)? {
            if existing != *header_hash.as_bytes() {
                return Err(DomError::Invalid(format!(
                    "alternate genesis block rejected: canonical genesis already exists as {}",
                    hex::encode(existing)
                )));
            }
        }

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
        let params = pow_params_for_network(self.network_magic)?;
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

    /// Compute the RandomX seed for a block at `height`, consulting the
    /// committed store only.
    ///
    /// Seed = hash of block at `randomx_seed_height(height)`. Used by the
    /// non-IBD paths (`connect_block`, `validate_header_only`) where the chain
    /// up to the parent is already fully committed, so the seed block is always
    /// present in the height index.
    ///
    /// Epoch 0 (`seed_height == 0`): genesis is used as the seed by convention
    /// (RFC-0011); the `[0u8; 32]` fallback covers the narrow bootstrap window
    /// before genesis is indexed. For epoch > 0 a missing seed block means the
    /// committed store is corrupt — surface it as an error rather than silently
    /// hashing against a zero seed, which would reject an otherwise valid block.
    fn compute_randomx_seed(&self, height: u64) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);
        match self.store.get_hash_at_height(seed_height)? {
            Some(hash) => Ok(hash),
            None if seed_height == 0 => Ok([0u8; 32]),
            None => Err(DomError::Internal(format!(
                "RandomX seed block at height {seed_height} missing from \
                 committed store (needed for block at height {height})"
            ))),
        }
    }

    /// Resolve the RandomX seed for a block at `height` whose parent is
    /// `parent_hash`, using the block's OWN branch history (A2-004).
    ///
    /// Decided rule (RFC-0011): the seed is the block hash at
    /// `randomx_seed_height(height)` on the block's own branch, not on whatever
    /// chain is currently canonical. `compute_randomx_seed` (canonical index) is
    /// correct only when the block extends the canonical chain; for a side-branch
    /// block validated during a reorg that crosses an epoch boundary, the
    /// canonical index can point at a different seed block, splitting consensus.
    ///
    /// Efficient in the common case: walks the parent chain backward only until
    /// it reaches a block already on the canonical chain (shared prefix), then
    /// defers to the canonical index. For a block that extends the canonical tip
    /// this returns on the first iteration and is byte-identical to
    /// `compute_randomx_seed`.
    fn compute_randomx_seed_branch_aware(
        &self,
        height: u64,
        parent_hash: Hash256,
    ) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);

        // Case 4 - epoch 0: the seed block is the genesis (or the zero fallback
        // before genesis is indexed). All branches share the genesis, so
        // branch-awareness adds nothing at epoch 0; defer to the canonical
        // resolver, which returns the genesis hash when indexed and the zero
        // fallback otherwise — exactly matching pre-fix behaviour. The offset
        // guarantees seed_height < height for epoch > 0, so for those epochs the
        // seed block always lies in the parent's history; it is never the block
        // itself.
        if seed_height == 0 {
            return self.compute_randomx_seed(height);
        }

        let max_walk = dom_core::MAX_REORG_DEPTH_POLICY;
        let mut cursor = parent_hash;
        let mut steps: u64 = 0;

        loop {
            let header_bytes =
                self.store
                    .get_block_header(cursor.as_bytes())?
                    .ok_or_else(|| {
                        DomError::Internal(format!(
                            "randomx seed walk: missing header {}",
                            hex::encode(cursor.as_bytes())
                        ))
                    })?;
            let cursor_header = BlockHeader::from_bytes(&header_bytes)?;
            let cursor_height = cursor_header.height.0;

            // Ramo (a) - shared prefix: if this cursor is the canonical block at
            // its height, all its ancestors are canonical too (the canonical
            // chain is linear). Defer to the canonical index for seed_height.
            // Covers direct extension (case 6) and branches diverging above
            // seed_height (cases 2, 5); byte-identical to the pre-fix result.
            if self.store.get_hash_at_height(cursor_height)? == Some(*cursor.as_bytes()) {
                return self.compute_randomx_seed(height);
            }

            // Ramo (b) - divergent seed block: reached seed_height on the branch
            // itself before hitting canonical. This branch's own block at
            // seed_height is the seed (cases 1, 3).
            if cursor_height == seed_height {
                return Ok(*cursor.as_bytes());
            }

            // Defensive: (a) or (b) must trigger before passing below seed_height.
            if cursor_height < seed_height {
                return Err(DomError::Internal(format!(
                    "randomx seed walk underran seed_height {seed_height} at height {cursor_height}"
                )));
            }

            steps += 1;
            if steps > max_walk {
                // Decision B1: a divergence deeper than the reorg limit is already
                // unpromotable; refuse rather than fall back to the canonical seed.
                return Err(DomError::Invalid(format!(
                    "randomx seed walk exceeded max reorg depth {max_walk} for block at height {height}"
                )));
            }
            cursor = cursor_header.prev_hash;
        }
    }

    /// Compute the RandomX seed for a block at `height` during header-first
    /// IBD, where the seed block may still be inside the in-memory header
    /// batch (not yet committed to the store).
    ///
    /// Resolution order:
    ///   1. the in-memory `batch` of headers being validated (not yet committed),
    ///   2. the committed store (headers from earlier, committed batches),
    ///   3. epoch 0 only: genesis fallback (`[0u8; 32]`).
    ///
    /// For epoch > 0, absence from both the batch and the store is a data bug
    /// and is surfaced as an error instead of silently falling back to a zero
    /// seed (the original cause of the IBD PoW split at the epoch boundary).
    fn compute_randomx_seed_with_batch(
        &self,
        height: u64,
        batch: &[(BlockHeader, Hash256, bool)],
    ) -> Result<[u8; 32], DomError> {
        let seed_height = randomx_seed_height(height);

        // 1. In-memory batch (headers validated but not yet committed).
        if let Some((_, hash, _)) = batch.iter().find(|(h, _, _)| h.height.0 == seed_height) {
            return Ok(*hash.as_bytes());
        }

        // 2. Committed store (headers from earlier batches).
        if let Some(hash) = self.store.get_hash_at_height(seed_height)? {
            return Ok(hash);
        }

        // 3. Epoch 0: genesis used as seed by convention (RFC-0011).
        if seed_height == 0 {
            return Ok([0u8; 32]);
        }

        Err(DomError::Internal(format!(
            "RandomX seed block at height {seed_height} not available \
             (needed for block at height {height})"
        )))
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
        let params = pow_params_for_network(self.network_magic)?;
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

    /// Collect the timestamps of the `count` blocks preceding a block whose
    /// parent is `parent_hash`, walking the block's OWN branch (A2-005).
    ///
    /// Mirrors the seed-resolution rule (RFC-0011 §6, applied to MTP): the
    /// median-time-past window is taken from the block's own ancestry, not from
    /// whatever chain is currently canonical. Walks back from the parent via
    /// prev_hash. For a block extending the canonical tip the parent and its
    /// ancestors are canonical, so the collected timestamps are identical to the
    /// previous canonical-index behaviour. For a side-branch block during a
    /// reorg it uses the branch's own ancestors, and always finds a full window
    /// (of length `count`, unless the chain is genuinely shorter) instead of
    /// silently returning a short window that would disable the MTP check.
    fn get_recent_timestamps(
        &self,
        parent_hash: Hash256,
        count: usize,
    ) -> Result<Vec<Timestamp>, DomError> {
        let mut timestamps = Vec::with_capacity(count);
        let mut cursor = parent_hash;

        while timestamps.len() < count {
            // Genesis has prev_hash == ZERO; stop once we walk past the root.
            if cursor == Hash256::ZERO {
                break;
            }
            let header_bytes = match self.store.get_block_header(cursor.as_bytes())? {
                Some(b) => b,
                None => break, // ancestry not fully present (early chain)
            };
            let header = BlockHeader::from_bytes(&header_bytes)?;
            timestamps.push(header.timestamp);
            cursor = header.prev_hash;
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
        now: Timestamp,
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

        if !is_better_fork_choice_tip(
            new_tip_header.total_difficulty,
            new_tip_hash,
            self.tip_difficulty,
            self.tip_hash,
        ) {
            return Err(DomError::PolicyRejected(format!(
                "reorg target is not heavier or tie-preferred: new_total={} current_total={} new_hash={} current_hash={}",
                new_tip_header.total_difficulty, self.tip_difficulty, new_tip_hash, self.tip_hash
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
            validate_future_timestamp_with_limit(&block.header, now, self.max_future_block_time())?;
            let ctx = ValidationContext {
                current_height: block.header.height,
                chain_id: *chain_id.as_bytes(),
                now,
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
        prune_retained_side_chains(&self.store, self.tip_height, *self.tip_hash.as_bytes())?;
        info!(
            "Reorg applied: new tip height={}, hash={}, ancestor={}",
            self.tip_height, self.tip_hash, ancestor
        );
        Ok(reorg_delta)
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

/// Verify the persisted UTXO set against the canonical set reconstructed from
/// committed block history.
///
/// FIX-020 — safety contract: if the two diverge, this is either on-disk
/// corruption (torn write, bit-rot) or deliberate tampering with the UTXO
/// database. A node MUST NOT silently continue on a divergent set, so the
/// default (`allow_utxo_repair == false`) refuses to open with a fatal
/// `CHAIN_CORRUPT_SENTINEL` error logged at ERROR level. The old auto-heal
/// (`replace_utxo_set`) remains available ONLY as an explicit operator opt-in
/// (`allow_utxo_repair == true`, reached via `ChainState::open_with_utxo_repair`).
/// The reconstruction logic itself is unchanged; only *when* it runs.
fn ensure_canonical_utxo_set(
    store: &DomStore,
    tip_height: BlockHeight,
    network_magic: u32,
    allow_utxo_repair: bool,
) -> Result<(), DomError> {
    let canonical = reconstruct_canonical_utxo_set(store, tip_height, network_magic)?;
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

    if !allow_utxo_repair {
        error!(
            "{CHAIN_CORRUPT_SENTINEL}: persisted UTXO set diverges from canonical reconstruction on reopen \
             (persisted_entries={}, canonical_entries={}); possible disk corruption or tampering — refusing to open",
            persisted.len(),
            canonical.len()
        );
        return Err(DomError::Internal(format!(
            "{CHAIN_CORRUPT_SENTINEL}: persisted UTXO set diverges from the canonical set \
             reconstructed from block history (persisted_entries={}, canonical_entries={}). \
             This indicates disk corruption or tampering of the UTXO database. The node refuses \
             to open on a divergent UTXO set rather than silently healing it. To rebuild the UTXO \
             set from canonical block history, restart in the explicit operator UTXO-repair mode \
             (ChainState::open_with_utxo_repair).",
            persisted.len(),
            canonical.len()
        )));
    }

    info!(
        "Operator UTXO-repair mode: persisted UTXO set diverged on reopen; rebuilding from canonical reconstruction (persisted_entries={}, canonical_entries={})",
        persisted.len(),
        canonical.len()
    );
    store.replace_utxo_set(&canonical, &canonical_digest)
}

fn reconstruct_canonical_utxo_set(
    store: &DomStore,
    tip_height: BlockHeight,
    network_magic: u32,
) -> Result<BTreeMap<[u8; 33], Vec<u8>>, DomError> {
    let mut utxos = BTreeMap::new();
    for h in 0..=tip_height.0 {
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
        if h == BlockHeight::GENESIS.0
            && network_magic == dom_core::NETWORK_MAGIC_MAINNET
            && crate::validate_mainnet_genesis_identity(&body).is_ok()
        {
            continue;
        }
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} body decode failed during UTXO rebuild: {e}",
                hex::encode(hash)
            ))
        })?;
        let header_bytes = block.header.to_bytes()?;
        let computed = compute_block_identifier(network_magic, &header_bytes)?;
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
    network_magic: u32,
) -> Result<(), DomError> {
    for h in 0..=tip_height.0 {
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
        if h == BlockHeight::GENESIS.0
            && network_magic == dom_core::NETWORK_MAGIC_MAINNET
            && crate::validate_mainnet_genesis_identity(&body).is_ok()
        {
            continue;
        }
        let block = Block::from_bytes(&body).map_err(|e| {
            DomError::Internal(format!(
                "{CHAIN_CORRUPT_SENTINEL}: canonical block {} body decode failed during kernel-index rebuild: {e}",
                hex::encode(hash)
            ))
        })?;
        let header_bytes = block.header.to_bytes()?;
        let computed = compute_block_identifier(network_magic, &header_bytes)?;
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

fn extract_kernel_excesses(block: &Block, block_hash: Hash256) -> Vec<KernelExcess> {
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

/// Canonical persistence changeset for the genesis block.
///
/// DOM-AUDIT-001: `create_genesis_block` (dom-node) MUST persist exactly the
/// changeset that the reopen path reconstructs — `reconstruct_canonical_utxo_set`
/// (UTXO) and `rebuild_kernel_index_from_canonical_chain` (kernel index). If the
/// two diverge for the spendable genesis coinbase, a freshly-created node and a
/// reopened node hold different UTXO sets, risking a chain split when the genesis
/// coinbase is spent.
///
/// This wrapper routes the create path through the *same* helpers the
/// connect/reopen paths use (`build_utxo_changeset` + `extract_kernel_excesses`),
/// so `create == reopen` holds by construction rather than by a hand-maintained
/// duplicate. Returns `(new_utxos, spent_utxos, kernel_excesses)` in the exact
/// shape `DomStore::commit_block` expects.
///
/// `block_hash` must be the canonical genesis identifier supplied by the sole
/// genesis authority. For legacy Testnet and Regtest this is Blake2b-256 of
/// the serialized header; Mainnet has an empty economic body and therefore
/// does not use this coinbase changeset helper.
pub fn genesis_canonical_changeset(
    block: &Block,
    block_hash: Hash256,
) -> (Vec<UtxoBytes>, Vec<SpentCommitment>, Vec<KernelExcess>) {
    let (new_utxos, spent_utxos) = build_utxo_changeset(block);
    let kernel_excesses = extract_kernel_excesses(block, block_hash);
    (new_utxos, spent_utxos, kernel_excesses)
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
        if height == BlockHeight::GENESIS.0
            && crate::validate_mainnet_genesis_identity(&body).is_ok()
        {
            continue;
        }
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
            // A2-001: apply_connect (the consensus layer of the reorg) has already
            // validated this transition — apply_disconnect released the shared output to
            // None and apply_connect re-admitted it past its duplicate-output guard. The
            // overlay therefore encodes an approved re-homing, and build_utxo_updates only
            // translates the overlay into store writes; it executes the approved change
            // rather than re-judging it. Re-homing is consensus-neutral: block_height is
            // only read for coinbase maturity (is_mature_for short-circuits to true for
            // non-coinbase), and coinbase maturity is enforced in apply_connect and at
            // spend time, not here. A divergence in proof or is_coinbase is NOT something
            // apply_connect can emit, so it would signal an internal bug — that still fails
            // closed.
            (Some(current), Some(desired))
                if current.proof == desired.proof && current.is_coinbase == desired.is_coinbase =>
            {
                out.push((*commitment, Some(desired.to_bytes())));
            }
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

#[derive(Debug, Clone)]
struct RetainedSideTip {
    hash: [u8; 32],
    height: u64,
    total_difficulty: U256,
}

fn prune_retained_side_chains(
    store: &DomStore,
    canonical_tip_height: BlockHeight,
    canonical_tip_hash: [u8; 32],
) -> Result<(), DomError> {
    let headers = store.read_all_block_headers_raw()?;
    if headers.is_empty() {
        return Ok(());
    }

    let canonical_hashes = canonical_hashes(store, canonical_tip_height)?;
    let noncanonical: BTreeMap<[u8; 32], BlockHeader> = headers
        .iter()
        .filter_map(|(hash, bytes)| {
            if canonical_hashes.contains(hash) {
                return None;
            }
            Some((hash, bytes))
        })
        .map(|(hash, bytes)| Ok((*hash, BlockHeader::from_bytes(bytes)?)))
        .collect::<Result<_, DomError>>()?;

    if noncanonical.is_empty() {
        return Ok(());
    }

    let mut child_parents = BTreeSet::new();
    for header in noncanonical.values() {
        child_parents.insert(*header.prev_hash.as_bytes());
    }

    let mut candidate_tips = Vec::new();
    for (hash, header) in &noncanonical {
        if child_parents.contains(hash) {
            continue;
        }
        let Some(common_ancestor) = find_common_ancestor(
            store,
            Hash256::from_bytes(canonical_tip_hash),
            Hash256::from_bytes(*hash),
        )?
        else {
            continue;
        };
        if common_ancestor == Hash256::from_bytes(*hash) {
            continue;
        }
        let ancestor_height = if common_ancestor == Hash256::ZERO {
            0
        } else {
            let Some(ancestor_header) =
                load_retention_header(store, &headers, common_ancestor.as_bytes())?
            else {
                continue;
            };
            ancestor_header.height.0
        };
        let disconnect_depth = canonical_tip_height.0.saturating_sub(ancestor_height);
        let branch_length = header.height.0.saturating_sub(ancestor_height);
        if disconnect_depth > MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH
            || branch_length > MAX_RETAINED_SIDE_BRANCH_LENGTH
        {
            continue;
        }
        candidate_tips.push(RetainedSideTip {
            hash: *hash,
            height: header.height.0,
            total_difficulty: header.total_difficulty,
        });
    }

    candidate_tips.sort_by(|left, right| {
        right
            .total_difficulty
            .cmp(&left.total_difficulty)
            .then_with(|| left.hash.as_slice().cmp(right.hash.as_slice()))
            .then_with(|| right.height.cmp(&left.height))
    });
    candidate_tips.truncate(MAX_RETAINED_SIDE_BRANCH_TIPS);

    let mut keep_hashes = canonical_hashes;
    for tip in candidate_tips {
        let mut cursor = Hash256::from_bytes(tip.hash);
        let mut walked = 0u64;
        loop {
            if keep_hashes.contains(cursor.as_bytes()) {
                break;
            }
            keep_hashes.insert(*cursor.as_bytes());
            walked = walked.saturating_add(1);
            if walked > MAX_RETAINED_SIDE_BRANCH_LENGTH {
                break;
            }
            let Some(header) = load_retention_header(store, &headers, cursor.as_bytes())? else {
                break;
            };
            if header.prev_hash == Hash256::ZERO {
                break;
            }
            cursor = header.prev_hash;
        }
    }

    let prune_hashes: BTreeSet<[u8; 32]> = noncanonical
        .keys()
        .filter(|hash| !keep_hashes.contains(*hash))
        .copied()
        .collect();
    store.prune_known_blocks(&prune_hashes)
}

fn canonical_hashes(
    store: &DomStore,
    canonical_tip_height: BlockHeight,
) -> Result<BTreeSet<[u8; 32]>, DomError> {
    let mut out = BTreeSet::new();
    for height in 0..=canonical_tip_height.0 {
        let Some(hash) = store.get_hash_at_height(height)? else {
            continue;
        };
        out.insert(hash);
    }
    Ok(out)
}

fn load_retention_header(
    store: &DomStore,
    cached_headers: &BTreeMap<[u8; 32], Vec<u8>>,
    hash: &[u8; 32],
) -> Result<Option<BlockHeader>, DomError> {
    if let Some(bytes) = cached_headers.get(hash) {
        return Ok(Some(BlockHeader::from_bytes(bytes)?));
    }
    match store.get_block_header(hash)? {
        Some(bytes) => Ok(Some(BlockHeader::from_bytes(&bytes)?)),
        None => Ok(None),
    }
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

fn validate_persisted_genesis_identity(
    store: &DomStore,
    configured_genesis_hash: Hash256,
) -> Result<(), DomError> {
    let Some(stored_genesis_hash) = store.get_hash_at_height(BlockHeight::GENESIS.0)? else {
        return Ok(());
    };

    if configured_genesis_hash != Hash256::ZERO
        && stored_genesis_hash != *configured_genesis_hash.as_bytes()
    {
        return Err(DomError::Invalid(format!(
            "stored genesis hash mismatch: expected {}, got {}",
            configured_genesis_hash,
            hex::encode(stored_genesis_hash)
        )));
    }

    Ok(())
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

fn compute_block_identifier(network_magic: u32, header_bytes: &[u8]) -> Result<Hash256, DomError> {
    crate::canonical_header_identifier(network_magic, header_bytes)
}

#[cfg(test)]
mod randomx_seed_tests {
    //! Unit tests for RandomX seed resolution in the header-first IBD path.
    //!
    //! Regression coverage for the IBD PoW consensus split at the epoch
    //! boundary: `compute_randomx_seed` used to fall back silently to a zero
    //! seed for epoch > 0 blocks whose seed-height block was not yet committed
    //! to the store (the normal state during header sync). The validator then
    //! hashed against `[0u8; 32]` while the miner used the real seed, producing
    //! a "proof-of-work invalid" rejection on otherwise valid blocks.
    use super::*;
    use dom_consensus::block::ProofOfWork;
    use dom_core::PROTOCOL_VERSION;
    use dom_pow::CompactTarget;

    const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

    fn empty_chain() -> (tempfile::TempDir, ChainState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store =
            DomStore::open_with_map_size(dir.path(), TEST_LMDB_MAP_SIZE).expect("store open");
        let chain = ChainState::open(store, Hash256::ZERO, dom_core::NETWORK_MAGIC_REGTEST)
            .expect("chain open");
        (dir, chain)
    }

    fn synth_header(height: u64) -> BlockHeader {
        BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(height),
            prev_hash: Hash256::ZERO,
            timestamp: Timestamp(1_704_067_200 + height),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::one(),
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        }
    }

    /// Epoch 1 (height 2048, seed_height 1984): the seed block lives in the
    /// in-memory batch, not the store. The seed MUST be resolved from the batch
    /// rather than silently falling back to a zero seed.
    #[test]
    fn ibd_pow_seed_resolved_from_batch() {
        let (_dir, chain) = empty_chain();

        // seed_height for height 2048 is 2048 - 64 = 1984.
        assert_eq!(randomx_seed_height(2048), 1984);

        let expected = [7u8; 32];
        // Synthetic batch including the seed-height header (1984) with a known
        // hash; the store is empty (no commits yet), mirroring header sync.
        let batch: Vec<(BlockHeader, Hash256, bool)> = vec![
            (synth_header(1983), Hash256::from_bytes([1u8; 32]), false),
            (synth_header(1984), Hash256::from_bytes(expected), false),
            (synth_header(2048), Hash256::from_bytes([2u8; 32]), false),
        ];

        let seed = chain
            .compute_randomx_seed_with_batch(2048, &batch)
            .expect("seed resolves from batch");
        assert_eq!(seed, expected, "seed must come from the in-memory batch");
        assert_ne!(seed, [0u8; 32], "must not fall back to zero seed");
    }

    /// Epoch 0 (height 100, seed_height 0): with an empty batch and an
    /// un-indexed genesis, the genesis fallback `[0u8; 32]` is correct and must
    /// NOT be promoted to an error.
    #[test]
    fn ibd_pow_seed_epoch0_uses_zero_fallback() {
        let (_dir, chain) = empty_chain();

        assert_eq!(randomx_seed_height(100), 0);

        let seed = chain
            .compute_randomx_seed_with_batch(100, &[])
            .expect("epoch 0 falls back to genesis without error");
        assert_eq!(seed, [0u8; 32]);
    }

    /// Epoch 1 on the committed-store path: a store missing the seed block at
    /// height 1984 is data corruption and MUST surface as an error rather than
    /// silently hashing against a zero seed.
    #[test]
    fn ibd_pow_seed_epoch1_missing_errors() {
        let (_dir, chain) = empty_chain();

        let result = chain.compute_randomx_seed(2048);
        assert!(
            matches!(result, Err(DomError::Internal(_))),
            "missing epoch>0 seed block must error, got {result:?}"
        );
    }

    /// A2-004: the RandomX seed for PoW validation is resolved by
    /// `compute_randomx_seed` from the CANONICAL height index (get_hash_at_height),
    /// which knows only the height — not which branch the block being validated
    /// belongs to. `connect_block` (line ~273) and `validate_header_only`
    /// (line ~762) both use this canonical path.
    ///
    /// During a reorg that crosses a RandomX epoch boundary, a side-branch block
    /// whose OWN history has a different block at seed_height is nonetheless
    /// validated against the canonical seed. If the branches differ at that
    /// seed_height, the block is validated against the wrong seed — a consensus
    /// split (a valid block rejected, or nodes disagreeing on validity).
    ///
    /// DECIDED RULE (Soren Planck): the seed comes from the block's OWN history,
    /// not the canonical chain. The branch-aware path
    /// (`compute_randomx_seed_with_batch`), already used by IBD, implements that
    /// rule. This detector pins the divergence at the resolution level: for the
    /// same block height at an epoch boundary, the canonical path and the
    /// branch-aware path return DIFFERENT seeds. The fix must make connect_block
    /// resolve the seed branch-aware; when it does, connect_block will yield the
    /// branch-aware value for a side-branch block instead of the canonical one.
    ///
    /// NOTE: mechanism-level detector (documents the resolution divergence, the
    /// root cause). It PASSES today — it asserts that the two resolution paths
    /// diverge, which is true now. Executable documentation of A2-004, not a
    /// red-until-fixed alarm.
    #[test]
    fn a2_004_seed_resolution_is_branch_blind_at_epoch_boundary() {
        let (_dir, chain) = empty_chain();

        // First block of epoch 1 is height 2048; its seed_height is 1984.
        let height = 2048;
        assert_eq!(randomx_seed_height(height), 1984);

        // Populate the CANONICAL height index at seed_height 1984 with a known
        // block hash (CANON). commit_block accepts opaque bytes for header/body —
        // dom-store does not parse them — so a minimal synthetic block suffices.
        let canon_seed_hash = [0xAAu8; 32];
        let opaque_header = vec![0xAAu8; 64];
        let opaque_body = vec![0xBBu8; 32];
        chain
            .store
            .commit_block(
                &canon_seed_hash,
                1984,
                &opaque_header,
                &opaque_body,
                &[],
                &[],
                &[],
            )
            .expect("commit canonical seed block at 1984");

        // CANONICAL path: resolves the seed for height 2048 from the height
        // index, yielding CANON. It receives only the height; it cannot know
        // any branch.
        let canonical_seed = chain
            .compute_randomx_seed(height)
            .expect("canonical seed resolves from the committed height index");
        assert_eq!(
            canonical_seed, canon_seed_hash,
            "canonical path returns the canonical block at seed_height"
        );

        // BRANCH-AWARE path: given a batch representing a SIDE branch whose own
        // block at 1984 is SIDE (!= CANON), it resolves the seed to SIDE — the
        // seed from that block's own history, per the decided rule.
        let side_seed_hash = [0xBBu8; 32];
        let side_branch: Vec<(BlockHeader, Hash256, bool)> = vec![(
            synth_header(1984),
            Hash256::from_bytes(side_seed_hash),
            false,
        )];
        let branch_aware_seed = chain
            .compute_randomx_seed_with_batch(height, &side_branch)
            .expect("branch-aware seed resolves from the side branch's own history");
        assert_eq!(
            branch_aware_seed, side_seed_hash,
            "branch-aware path uses the side branch's own seed block"
        );

        // A2-004: for the SAME block height at the epoch boundary, the canonical
        // path (which connect_block uses) and the branch-aware path (the decided
        // rule) return DIFFERENT seeds. A side-branch block would therefore be
        // validated against CANON when it must be validated against SIDE. The
        // fix must make connect_block resolve the seed from the block's own
        // history.
        assert_ne!(
            canonical_seed, branch_aware_seed,
            "A2-004: connect_block's canonical seed path validates a side-branch \
             block against the wrong seed at a RandomX epoch boundary"
        );
    }

    /// Header at height `h` with the given prev_hash and nonce; returns
    /// (header, hash). The nonce distinguishes same-height blocks on different
    /// branches (canonical vs side), yielding different hashes.
    fn header_at(h: u64, prev: Hash256, nonce: u64) -> (BlockHeader, Hash256) {
        let mut hdr = synth_header(h);
        hdr.prev_hash = prev;
        hdr.pow.nonce = nonce;
        let bytes = hdr.to_bytes().expect("serialize header");
        let hash = compute_block_hash(&bytes);
        (hdr, hash)
    }

    /// Insert a header as CANONICAL (populates the height index via commit_block;
    /// body/utxo/kernel are opaque — dom-store does not parse them).
    fn commit_canonical(chain: &ChainState, hdr: &BlockHeader, hash: Hash256) {
        let bytes = hdr.to_bytes().expect("serialize");
        chain
            .store
            .commit_block(
                hash.as_bytes(),
                hdr.height.0,
                &bytes,
                &[0xBB; 4],
                &[],
                &[],
                &[],
            )
            .expect("commit canonical");
    }

    /// Insert a header as a BRANCH block (header+body in the store, NO height
    /// index — exactly as connect_block does for side-chain quarantine).
    fn store_branch(chain: &ChainState, hdr: &BlockHeader, hash: Hash256) {
        let bytes = hdr.to_bytes().expect("serialize");
        chain
            .store
            .store_known_block(hash.as_bytes(), &bytes, &[0xCC; 4])
            .expect("store branch");
    }

    /// A2-004 FIX (main): a side-branch block whose own history has a different
    /// seed block than canonical must be validated against ITS OWN seed, not the
    /// canonical one. Would fail on the pre-fix canonical path; passes with the
    /// branch-aware resolution.
    #[test]
    fn a2_004_fix_branch_aware_uses_own_seed() {
        let (_dir, chain) = empty_chain();
        assert_eq!(randomx_seed_height(2048), 1984);

        // Canonical block at seed_height 1984 (CANON).
        let (c_hdr, canon_1984) = header_at(1984, Hash256::ZERO, 0xA0);
        commit_canonical(&chain, &c_hdr, canon_1984);

        // Side branch 1984..=2047, chained; block 1984 is SIDE (!= CANON),
        // diverging at the seed_height.
        let (b1984_hdr, side_1984) = header_at(1984, Hash256::ZERO, 0xB0);
        store_branch(&chain, &b1984_hdr, side_1984);
        let mut prev = side_1984;
        for h in 1985..=2047 {
            let (nh, nhash) = header_at(h, prev, 0xB0);
            store_branch(&chain, &nh, nhash);
            prev = nhash;
        }
        let parent_lateral = prev; // block 2047 of the side branch

        // The fix resolves the seed from the branch's own history => SIDE.
        let branch_aware = chain
            .compute_randomx_seed_branch_aware(2048, parent_lateral)
            .expect("branch-aware resolves");
        assert_eq!(
            branch_aware,
            *side_1984.as_bytes(),
            "fix: side-branch block must use its OWN seed block (SIDE)"
        );

        // The canonical path (old bug) would resolve to CANON — the divergence
        // the fix corrects.
        let canonical = chain
            .compute_randomx_seed(2048)
            .expect("canonical resolves");
        assert_eq!(canonical, *canon_1984.as_bytes());
        assert_ne!(
            branch_aware, canonical,
            "A2-004: the fix diverges from the canonical path exactly where the bug was"
        );
    }

    /// A2-004 FIX (case 6, non-regression): a block extending the canonical tip
    /// gets the SAME seed as the canonical index. The fix must not change the
    /// common path.
    #[test]
    fn a2_004_fix_direct_extension_matches_canonical() {
        let (_dir, chain) = empty_chain();

        let (c1984, canon_1984) = header_at(1984, Hash256::ZERO, 0xA0);
        commit_canonical(&chain, &c1984, canon_1984);
        let (c2047, canon_2047) = header_at(2047, Hash256::ZERO, 0xA7);
        commit_canonical(&chain, &c2047, canon_2047);

        // Canonical parent => ramo (a) fires on the first iteration => canonical
        // index. Must equal compute_randomx_seed exactly.
        let branch_aware = chain
            .compute_randomx_seed_branch_aware(2048, canon_2047)
            .expect("branch-aware resolves");
        let canonical = chain
            .compute_randomx_seed(2048)
            .expect("canonical resolves");
        assert_eq!(
            branch_aware, canonical,
            "case 6: direct extension must match the canonical seed exactly"
        );
        assert_eq!(branch_aware, *canon_1984.as_bytes());
    }

    /// A2-004 FIX (case 4, epoch 0): a height-1 block (seed_height 0) must
    /// resolve to the genesis hash once genesis is indexed — NOT the zero
    /// fallback. Regression guard for the epoch-0 blind spot: the branch-aware
    /// resolver must match the canonical resolver at epoch 0, where all branches
    /// share the genesis. (Before the case-4 fix, this returned [0u8; 32],
    /// breaking PoW validation for the entire first epoch.)
    #[test]
    fn a2_004_fix_epoch0_resolves_genesis_not_zero() {
        let (_dir, chain) = empty_chain();

        // Before genesis is indexed: both resolvers give the zero fallback.
        assert_eq!(randomx_seed_height(1), 0);
        let bare = chain
            .compute_randomx_seed_branch_aware(1, Hash256::ZERO)
            .expect("bare epoch-0 resolves");
        assert_eq!(bare, [0u8; 32], "before genesis is indexed, zero fallback");

        // After genesis is committed (indexed at height 0):
        let (g_hdr, genesis_hash) = header_at(0, Hash256::ZERO, 0x01);
        commit_canonical(&chain, &g_hdr, genesis_hash);

        let branch_aware = chain
            .compute_randomx_seed_branch_aware(1, genesis_hash)
            .expect("epoch-0 branch-aware resolves");
        let canonical = chain
            .compute_randomx_seed(1)
            .expect("epoch-0 canonical resolves");

        // Both must be the genesis hash, and must agree (epoch 0 has no branch
        // divergence — all chains share the genesis).
        assert_eq!(
            branch_aware,
            *genesis_hash.as_bytes(),
            "epoch-0 seed must be the genesis hash once indexed, not zero"
        );
        assert_eq!(
            branch_aware, canonical,
            "epoch-0 branch-aware must match canonical exactly"
        );
    }
}

#[cfg(test)]
mod mtp_branch_tests {
    //! A2-005: get_recent_timestamps must collect the median-time-past window
    //! from the block's OWN branch (via prev_hash), not the canonical height
    //! index. The pre-fix version used get_hash_at_height, which returned
    //! nothing for non-canonical (side-branch) ancestors — silently yielding a
    //! short window that disables the MTP check, and (when it did resolve)
    //! taking timestamps from a competing branch.
    use super::*;
    use dom_consensus::block::ProofOfWork;
    use dom_core::PROTOCOL_VERSION;
    use dom_pow::CompactTarget;

    const TEST_LMDB_MAP_SIZE: usize = 64 << 20;

    fn chain() -> (tempfile::TempDir, ChainState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = DomStore::open_with_map_size(dir.path(), TEST_LMDB_MAP_SIZE).expect("store");
        let c =
            ChainState::open(store, Hash256::ZERO, dom_core::NETWORK_MAGIC_REGTEST).expect("chain");
        (dir, c)
    }

    /// Build a header at height `h`, parent `prev`, with an explicit timestamp.
    fn hdr(h: u64, prev: Hash256, ts: u64) -> (BlockHeader, Hash256) {
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(h),
            prev_hash: prev,
            timestamp: Timestamp(ts),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::one(),
            pow: ProofOfWork {
                nonce: h,
                randomx_hash: Hash256::ZERO,
            },
        };
        let bytes = header.to_bytes().expect("serialize");
        let hash = compute_block_hash(&bytes);
        (header, hash)
    }

    /// Store a header as a NON-canonical branch block (no height index) — the
    /// exact state of a side-branch block during a reorg.
    fn store_branch(chain: &ChainState, h: &BlockHeader, hash: Hash256) {
        let bytes = h.to_bytes().expect("serialize");
        chain
            .store
            .store_known_block(hash.as_bytes(), &bytes, &[0xCC; 4])
            .expect("store branch");
    }

    /// A2-005: a side-branch chain of 11 blocks (NONE canonical) must still
    /// yield a full 11-timestamp window walked via prev_hash. The pre-fix
    /// canonical-index version would return an EMPTY window here (none of these
    /// blocks are in the height index), disabling the MTP check for the branch.
    #[test]
    fn a2_005_mtp_window_walks_branch_not_canonical_index() {
        let (_dir, chain) = chain();

        // Chain 12 side-branch blocks (heights 0..=11), each with a distinct
        // timestamp, linked by prev_hash. NONE are committed to the height index.
        let mut prev = Hash256::ZERO;
        let mut hashes = Vec::new();
        for h in 0..=11u64 {
            let ts = 1_000 + h * 100; // distinct, increasing
            let (header, hash) = hdr(h, prev, ts);
            store_branch(&chain, &header, hash);
            hashes.push(hash);
            prev = hash;
        }

        // Parent of a hypothetical block at height 12 is the height-11 tip.
        let parent = hashes[11];
        let window = chain
            .get_recent_timestamps(parent, 11)
            .expect("collect window");

        // The fix walks prev_hash and finds all 11 — even though none are
        // canonical. Pre-fix (canonical index) would find zero.
        assert_eq!(
            window.len(),
            11,
            "A2-005: MTP window must be walked from the branch, not the canonical index"
        );

        // And they must be the BRANCH's timestamps (heights 11 down to 1), in
        // walk order (parent first).
        let got: Vec<u64> = window.iter().map(|t| t.0).collect();
        let want: Vec<u64> = (1..=11u64).rev().map(|h| 1_000 + h * 100).collect();
        assert_eq!(got, want, "window must contain the branch's own timestamps");
    }

    /// A2-005 non-regression: fewer than `count` blocks in the ancestry returns
    /// a short window (genuinely early chain), which validate_median_time_past
    /// legitimately skips. The walk must stop cleanly at genesis (prev ZERO).
    #[test]
    fn a2_005_short_chain_stops_at_genesis() {
        let (_dir, chain) = chain();
        let mut prev = Hash256::ZERO;
        let mut last = Hash256::ZERO;
        for h in 0..=3u64 {
            let (header, hash) = hdr(h, prev, 1_000 + h * 100);
            store_branch(&chain, &header, hash);
            prev = hash;
            last = hash;
        }
        let window = chain.get_recent_timestamps(last, 11).expect("collect");
        // Only 4 blocks exist (heights 0..=3); parent is height 3, walk yields
        // heights 3,2,1,0 = 4 timestamps, then stops at ZERO.
        assert_eq!(
            window.len(),
            4,
            "short chain yields a short window, walk stops at genesis"
        );
    }
}

#[cfg(test)]
mod xdiff_hash_parity_tests {
    //! dom-shield XDIFF — the two private header-hash functions in this crate
    //! MUST agree byte-for-byte. `chain_state::compute_block_hash` is used by
    //! the live connect/validate path and `ibd::compute_hash` by the headers-
    //! first IBD path. If they ever diverged (e.g. one switched digest, domain,
    //! or input framing), an IBD-validated header would map to a different block
    //! hash than the same header connected live: duplicate suppression, parent
    //! linkage and reorg ancestry would silently split between the two paths.
    use super::compute_block_hash;
    use crate::ibd::compute_hash_probe;

    fn check(bytes: &[u8]) {
        assert_eq!(
            compute_block_hash(bytes).as_bytes(),
            &compute_hash_probe(bytes),
            "ibd::compute_hash and chain_state::compute_block_hash diverged for input len {}",
            bytes.len()
        );
    }

    #[test]
    fn empty_input_parity() {
        check(&[]);
    }

    #[test]
    fn header_sized_and_varied_inputs_parity() {
        // A spread of lengths and byte patterns, including a realistic header
        // length and adversarial all-zero / all-0xFF buffers.
        check(&[0u8; 1]);
        check(&[0xFFu8; 32]);
        check(&[0xABu8; 200]);
        let ramp: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        check(&ramp);
        let mut x = 0x9E3779B97F4A7C15u64;
        let pseudo: Vec<u8> = (0..512)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        check(&pseudo);
    }
}

//! Canonical Bitcoin Core evidence collection for `btc-evidence` and M.8.

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{block::Header, Block, Transaction};
use btc_evidence::{
    BitcoinOutPointV1, BitcoinOutcomeV1, BoundedMerkleBranchV1, KeystoneBitcoinEvidenceV1,
};
use serde_json::{json, Value};

use crate::rpc::{
    canonical_genesis_hash, decode_hex_bounded, display_txid, expected_signet_challenge,
    parse_block_hash_internal, parse_txid_internal, BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1,
    MAX_SIGNET_CHALLENGE_BYTES,
};
use crate::LiveBitcoinError;

const EVIDENCE_MAGIC: &[u8; 8] = b"DBTCEVV1";
const EVIDENCE_VERSION: u16 = 1;
const MAX_CHAIN_HEADERS: usize = 1_000_000;
const MAX_BLOCK_BYTES: usize = 4_000_000;
const MAX_TRANSACTION_BYTES: usize = 4_000_000;
const MAX_EVIDENCE_BYTES: usize = 96 * 1024 * 1024;
const SNAPSHOT_ATTEMPTS: usize = 3;

type HeaderChainV1 = (Vec<[u8; 80]>, [u8; 80], Vec<[u8; 80]>);

/// Route/outcome binding applied only after canonical RPC evidence exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinEvidenceBindingV1 {
    /// Exact one-shot settlement identifier.
    pub settlement_id: [u8; 32],
    /// Exact hash of the frozen settlement terms.
    pub terms_hash: [u8; 32],
    /// Contractual outpoint that the confirmed transaction must spend.
    pub expected_outpoint: BitcoinOutPointV1,
    /// Expected terminal Bitcoin path.
    pub outcome: BitcoinOutcomeV1,
}

/// Canonical, locally revalidated Bitcoin Core evidence snapshot.
///
/// All contents are public chain data. Fields remain private so callers cannot
/// mutate a validated object into a contradictory one; strict canonical
/// encode/decode and read-only getters provide restart transport.
pub struct CanonicalBitcoinRpcEvidenceV1 {
    network: BitcoinCoreNetworkV1,
    genesis_hash: [u8; 32],
    signet_challenge: Option<Vec<u8>>,
    raw_transaction: Vec<u8>,
    txid: [u8; 32],
    wtxid: [u8; 32],
    canonical_block: Vec<u8>,
    block_header: [u8; 80],
    block_hash: [u8; 32],
    block_height: u64,
    merkle_branch: BoundedMerkleBranchV1,
    ancestry_headers: Vec<[u8; 80]>,
    confirmation_headers: Vec<[u8; 80]>,
    tip_height: u64,
    tip_hash: [u8; 32],
}

impl CanonicalBitcoinRpcEvidenceV1 {
    /// Exact authenticated chain family.
    #[must_use]
    pub const fn network(&self) -> BitcoinCoreNetworkV1 {
        self.network
    }

    /// Exact authenticated genesis hash in internal byte order.
    #[must_use]
    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Exact transaction id in internal byte order.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Exact witness transaction id in internal byte order.
    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }

    /// Exact Signet challenge script used for network identity, when present.
    #[must_use]
    pub fn signet_challenge(&self) -> Option<&[u8]> {
        self.signet_challenge.as_deref()
    }

    /// Exact witness-bearing transaction consensus bytes.
    #[must_use]
    pub fn raw_transaction(&self) -> &[u8] {
        &self.raw_transaction
    }

    /// Exact full consensus block bytes required by the M.8 authority.
    #[must_use]
    pub fn canonical_block_bytes(&self) -> &[u8] {
        &self.canonical_block
    }

    /// Height of the containing block.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Hash of the containing block in internal byte order.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Canonical Merkle inclusion branch for the exact txid.
    #[must_use]
    pub const fn txid_merkle_branch(&self) -> &BoundedMerkleBranchV1 {
        &self.merkle_branch
    }

    /// Exactly one header per height from genesis through the parent of the
    /// containing block. This is the ancestry slice consumed by M.8.
    #[must_use]
    pub fn ancestry_headers(&self) -> &[[u8; 80]] {
        &self.ancestry_headers
    }

    /// Exact canonical successor headers after the containing block. This is
    /// the confirmation slice consumed by M.8.
    #[must_use]
    pub fn confirmation_headers(&self) -> &[[u8; 80]] {
        &self.confirmation_headers
    }

    /// Confirmation depth including the containing block.
    #[must_use]
    pub fn confirmation_depth(&self) -> u32 {
        u32::try_from(self.confirmation_headers.len())
            .ok()
            .and_then(|depth| depth.checked_add(1))
            .unwrap_or(u32::MAX)
    }

    /// Stable tip height of this collection snapshot.
    #[must_use]
    pub const fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// Stable tip hash of this collection snapshot in internal byte order.
    #[must_use]
    pub const fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    /// Builds the exact input consumed by the existing non-custodial outcome
    /// verifier. Route fields are applied here and cannot alter chain facts.
    pub fn to_keystone_evidence(
        &self,
        binding: BitcoinEvidenceBindingV1,
    ) -> Result<KeystoneBitcoinEvidenceV1, LiveBitcoinError> {
        if binding.settlement_id == [0; 32]
            || binding.terms_hash == [0; 32]
            || binding.expected_outpoint.txid == [0; 32]
            || self.confirmation_headers.is_empty()
        {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        Ok(KeystoneBitcoinEvidenceV1 {
            codec_version: 1,
            network: self.network.evidence_network(),
            network_genesis_hash: self.genesis_hash,
            settlement_id: binding.settlement_id,
            terms_hash: binding.terms_hash,
            expected_outpoint: binding.expected_outpoint,
            raw_transaction: self.raw_transaction.clone(),
            txid: self.txid,
            wtxid: self.wtxid,
            block_header: self.block_header,
            block_height: self.block_height,
            txid_merkle_branch: self.merkle_branch.clone(),
            confirmation_headers: self.confirmation_headers.clone(),
            outcome: binding.outcome,
        })
    }

    /// Strict canonical restart encoding of this public evidence object.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, LiveBitcoinError> {
        validate_evidence(self)?;
        let mut output = Vec::new();
        output.extend_from_slice(EVIDENCE_MAGIC);
        output.extend_from_slice(&EVIDENCE_VERSION.to_be_bytes());
        output.push(encode_network(self.network));
        output.extend_from_slice(&self.genesis_hash);
        put_bytes(
            &mut output,
            self.signet_challenge.as_deref().unwrap_or_default(),
        )?;
        put_bytes(&mut output, &self.raw_transaction)?;
        output.extend_from_slice(&self.txid);
        output.extend_from_slice(&self.wtxid);
        put_bytes(&mut output, &self.canonical_block)?;
        output.extend_from_slice(&self.block_header);
        output.extend_from_slice(&self.block_hash);
        output.extend_from_slice(&self.block_height.to_be_bytes());
        output.extend_from_slice(&self.merkle_branch.position.to_be_bytes());
        put_len(&mut output, self.merkle_branch.siblings.len())?;
        for sibling in &self.merkle_branch.siblings {
            output.extend_from_slice(sibling);
        }
        put_headers(&mut output, &self.ancestry_headers)?;
        put_headers(&mut output, &self.confirmation_headers)?;
        output.extend_from_slice(&self.tip_height.to_be_bytes());
        output.extend_from_slice(&self.tip_hash);
        if output.len() > MAX_EVIDENCE_BYTES {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        Ok(output)
    }

    /// Decodes and fully revalidates a canonical restart encoding against an
    /// independently retained network identity.
    ///
    /// `expected_custom_signet_challenge` must be present only for a custom
    /// Signet. Regtest and Public Signet use their compiled canonical
    /// identities. Requiring this external commitment prevents a coherent
    /// custom-Signet evidence blob from selecting its own challenge on reopen.
    pub fn decode_canonical(
        bytes: &[u8],
        expected_network: BitcoinCoreNetworkV1,
        expected_genesis_hash: [u8; 32],
        expected_custom_signet_challenge: Option<&[u8]>,
    ) -> Result<Self, LiveBitcoinError> {
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        if canonical_genesis_hash(expected_network) != expected_genesis_hash {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let expected_challenge = expected_signet_challenge(
            expected_network,
            expected_custom_signet_challenge.map(ToOwned::to_owned),
        )?;
        let mut cursor = Cursor::new(bytes);
        cursor.require_magic(EVIDENCE_MAGIC)?;
        if cursor.take_u16()? != EVIDENCE_VERSION {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        let network = decode_network(cursor.take_u8()?)?;
        let genesis_hash = cursor.take_array()?;
        let signet_challenge = match cursor.take_bytes(MAX_SIGNET_CHALLENGE_BYTES)? {
            challenge if challenge.is_empty() => None,
            challenge => Some(challenge),
        };
        let raw_transaction = cursor.take_bytes(MAX_TRANSACTION_BYTES)?;
        let txid = cursor.take_array()?;
        let wtxid = cursor.take_array()?;
        let canonical_block = cursor.take_bytes(MAX_BLOCK_BYTES)?;
        let block_header = cursor.take_array()?;
        let block_hash = cursor.take_array()?;
        let block_height = cursor.take_u64()?;
        let position = cursor.take_u32()?;
        let sibling_count = cursor.take_len(BoundedMerkleBranchV1::MAX_DEPTH)?;
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            siblings.push(cursor.take_array()?);
        }
        let ancestry_headers = cursor.take_headers()?;
        let confirmation_headers = cursor.take_headers()?;
        let tip_height = cursor.take_u64()?;
        let tip_hash = cursor.take_array()?;
        cursor.finish()?;
        let evidence = Self {
            network,
            genesis_hash,
            signet_challenge,
            raw_transaction,
            txid,
            wtxid,
            canonical_block,
            block_header,
            block_hash,
            block_height,
            merkle_branch: BoundedMerkleBranchV1 { siblings, position },
            ancestry_headers,
            confirmation_headers,
            tip_height,
            tip_hash,
        };
        if evidence.network != expected_network
            || evidence.genesis_hash != expected_genesis_hash
            || evidence.signet_challenge != expected_challenge
        {
            return Err(LiveBitcoinError::IdentityMismatch);
        }
        validate_evidence(&evidence)?;
        Ok(evidence)
    }
}

/// Concrete stable-snapshot evidence collector.
pub struct BitcoinCoreEvidenceCollectorV1<'a> {
    rpc: &'a BitcoinCoreRpcClientV1,
}

impl<'a> BitcoinCoreEvidenceCollectorV1<'a> {
    /// Binds a collector to one already authenticated Bitcoin Core client.
    #[must_use]
    pub const fn new(rpc: &'a BitcoinCoreRpcClientV1) -> Self {
        Self { rpc }
    }

    /// Collects and locally verifies one confirmed transaction snapshot.
    ///
    /// The collector retries only when the best tip changes during the walk.
    /// A returned object always contains a genesis-rooted ancestry, the full
    /// containing block, an exact txid Merkle branch, and every successor
    /// header through one stable tip.
    pub fn collect_confirmed(
        &self,
        expected_txid: [u8; 32],
        minimum_confirmations: u32,
    ) -> Result<CanonicalBitcoinRpcEvidenceV1, LiveBitcoinError> {
        if expected_txid == [0; 32]
            || minimum_confirmations == 0
            || usize::try_from(minimum_confirmations)
                .ok()
                .filter(|depth| *depth <= MAX_CHAIN_HEADERS)
                .is_none()
        {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        self.rpc.require_chain_identity()?;
        for _ in 0..SNAPSHOT_ATTEMPTS {
            match self.collect_once(expected_txid, minimum_confirmations) {
                Err(LiveBitcoinError::SnapshotChanged) => continue,
                result => return result,
            }
        }
        Err(LiveBitcoinError::SnapshotChanged)
    }

    fn collect_once(
        &self,
        expected_txid: [u8; 32],
        minimum_confirmations: u32,
    ) -> Result<CanonicalBitcoinRpcEvidenceV1, LiveBitcoinError> {
        let start_tip_height = self
            .rpc
            .node_rpc("getblockcount", json!([]))?
            .as_u64()
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        let start_tip_display = self
            .rpc
            .node_rpc("getbestblockhash", json!([]))?
            .as_str()
            .map(str::to_owned)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        let start_tip_hash = parse_block_hash_internal(&start_tip_display)?;
        if usize::try_from(start_tip_height)
            .ok()
            .filter(|height| *height < MAX_CHAIN_HEADERS)
            .is_none()
        {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        let txid_display = display_txid(expected_txid);
        let transaction_json = self
            .rpc
            .node_rpc("getrawtransaction", json!([txid_display, true]))?;
        if transaction_json
            .get("in_active_chain")
            .and_then(Value::as_bool)
            == Some(false)
        {
            return Err(LiveBitcoinError::TransactionUnavailable);
        }
        let raw_transaction = transaction_json
            .get("hex")
            .and_then(Value::as_str)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(|value| decode_hex_bounded(value, MAX_TRANSACTION_BYTES))?;
        let transaction: Transaction =
            deserialize(&raw_transaction).map_err(|_| LiveBitcoinError::InvalidRpcResponse)?;
        let txid = transaction.compute_txid().to_raw_hash().to_byte_array();
        let wtxid = transaction.compute_wtxid().to_raw_hash().to_byte_array();
        if txid != expected_txid
            || transaction_json
                .get("txid")
                .and_then(Value::as_str)
                .ok_or(LiveBitcoinError::InvalidRpcResponse)
                .and_then(parse_txid_internal)?
                != txid
            || transaction_json
                .get("hash")
                .and_then(Value::as_str)
                .ok_or(LiveBitcoinError::InvalidRpcResponse)
                .and_then(parse_txid_internal)?
                != wtxid
        {
            return Err(LiveBitcoinError::InvalidRpcResponse);
        }
        let block_display = transaction_json
            .get("blockhash")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(LiveBitcoinError::TransactionUnavailable)?;
        let block_hash = parse_block_hash_internal(&block_display)?;
        let block_information = self
            .rpc
            .node_rpc("getblockheader", json!([block_display, true]))?;
        let block_height = block_information
            .get("height")
            .and_then(Value::as_u64)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        if block_height > start_tip_height {
            return Err(LiveBitcoinError::SnapshotChanged);
        }
        let depth = start_tip_height
            .checked_sub(block_height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        if depth < u64::from(minimum_confirmations) {
            return Err(LiveBitcoinError::InsufficientConfirmations);
        }
        if transaction_json
            .get("confirmations")
            .and_then(Value::as_u64)
            != Some(depth)
        {
            return Err(LiveBitcoinError::SnapshotChanged);
        }
        let canonical_block = self
            .rpc
            .node_rpc("getblock", json!([block_display, 0]))?
            .as_str()
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(|value| decode_hex_bounded(value, MAX_BLOCK_BYTES))?;
        let block: Block =
            deserialize(&canonical_block).map_err(|_| LiveBitcoinError::InvalidRpcResponse)?;
        if block.block_hash().to_raw_hash().to_byte_array() != block_hash
            || !block.check_merkle_root()
        {
            return Err(LiveBitcoinError::InvalidRpcResponse);
        }
        let positions: Vec<usize> = block
            .txdata
            .iter()
            .enumerate()
            .filter_map(|(position, candidate)| {
                (candidate.compute_txid().to_raw_hash().to_byte_array() == txid).then_some(position)
            })
            .collect();
        if positions.len() != 1 || serialize(&block.txdata[positions[0]]) != raw_transaction {
            return Err(LiveBitcoinError::InvalidRpcResponse);
        }
        let merkle_branch = merkle_branch(&block, positions[0])?;
        let (ancestry_headers, funding_header, confirmation_headers) =
            self.collect_header_chain(block_height, start_tip_height, block_hash)?;
        self.rpc.require_chain_identity()?;
        let end_tip_height = self
            .rpc
            .node_rpc("getblockcount", json!([]))?
            .as_u64()
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        let end_tip_display = self
            .rpc
            .node_rpc("getbestblockhash", json!([]))?
            .as_str()
            .map(str::to_owned)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        if end_tip_height != start_tip_height || end_tip_display != start_tip_display {
            return Err(LiveBitcoinError::SnapshotChanged);
        }
        let evidence = CanonicalBitcoinRpcEvidenceV1 {
            network: self.rpc.network(),
            genesis_hash: self.rpc.genesis_hash(),
            signet_challenge: self.rpc.signet_challenge().map(ToOwned::to_owned),
            raw_transaction,
            txid,
            wtxid,
            canonical_block,
            block_header: funding_header,
            block_hash,
            block_height,
            merkle_branch,
            ancestry_headers,
            confirmation_headers,
            tip_height: start_tip_height,
            tip_hash: start_tip_hash,
        };
        validate_evidence(&evidence)?;
        Ok(evidence)
    }

    fn collect_header_chain(
        &self,
        block_height: u64,
        tip_height: u64,
        expected_block_hash: [u8; 32],
    ) -> Result<HeaderChainV1, LiveBitcoinError> {
        let ancestry_capacity =
            usize::try_from(block_height).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
        let confirmation_capacity = tip_height
            .checked_sub(block_height)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(LiveBitcoinError::BoundsExceeded)?;
        if ancestry_capacity > MAX_CHAIN_HEADERS || confirmation_capacity > MAX_CHAIN_HEADERS {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        let mut ancestry = Vec::with_capacity(ancestry_capacity);
        let mut previous = None;
        for height in 0..block_height {
            let (hash, raw, header) = self.header_at(height)?;
            if height == 0 {
                if hash != self.rpc.genesis_hash() {
                    return Err(LiveBitcoinError::IdentityMismatch);
                }
            } else if header.prev_blockhash.to_raw_hash().to_byte_array()
                != previous.ok_or(LiveBitcoinError::InvalidRpcResponse)?
            {
                return Err(LiveBitcoinError::InvalidRpcResponse);
            }
            previous = Some(hash);
            ancestry.push(raw);
        }
        let (funding_hash, funding_raw, funding_header) = self.header_at(block_height)?;
        if funding_hash != expected_block_hash
            || (block_height > 0
                && funding_header.prev_blockhash.to_raw_hash().to_byte_array()
                    != previous.ok_or(LiveBitcoinError::InvalidRpcResponse)?)
        {
            return Err(LiveBitcoinError::InvalidRpcResponse);
        }
        let mut confirmations = Vec::with_capacity(confirmation_capacity);
        previous = Some(funding_hash);
        for height in block_height.saturating_add(1)..=tip_height {
            let (hash, raw, header) = self.header_at(height)?;
            if header.prev_blockhash.to_raw_hash().to_byte_array()
                != previous.ok_or(LiveBitcoinError::InvalidRpcResponse)?
            {
                return Err(LiveBitcoinError::InvalidRpcResponse);
            }
            previous = Some(hash);
            confirmations.push(raw);
        }
        Ok((ancestry, funding_raw, confirmations))
    }

    fn header_at(&self, height: u64) -> Result<([u8; 32], [u8; 80], Header), LiveBitcoinError> {
        let display = self
            .rpc
            .node_rpc("getblockhash", json!([height]))?
            .as_str()
            .map(str::to_owned)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        let expected_hash = parse_block_hash_internal(&display)?;
        let bytes = self
            .rpc
            .node_rpc("getblockheader", json!([display, false]))?
            .as_str()
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(|value| decode_hex_bounded(value, 80))?;
        let raw: [u8; 80] = bytes
            .try_into()
            .map_err(|_| LiveBitcoinError::InvalidRpcResponse)?;
        let header: Header = deserialize(&raw).map_err(|_| LiveBitcoinError::InvalidRpcResponse)?;
        let hash = header
            .validate_pow(header.target())
            .map_err(|_| LiveBitcoinError::InvalidRpcResponse)?
            .to_raw_hash()
            .to_byte_array();
        if hash != expected_hash {
            return Err(LiveBitcoinError::InvalidRpcResponse);
        }
        Ok((hash, raw, header))
    }
}

fn merkle_branch(
    block: &Block,
    transaction_position: usize,
) -> Result<BoundedMerkleBranchV1, LiveBitcoinError> {
    if block.txdata.is_empty() || transaction_position >= block.txdata.len() {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    }
    let position =
        u32::try_from(transaction_position).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    let mut index = transaction_position;
    let mut level: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|transaction| transaction.compute_txid().to_raw_hash().to_byte_array())
        .collect();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if siblings.len() >= BoundedMerkleBranchV1::MAX_DEPTH {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        let sibling_index = if index & 1 == 0 {
            (index + 1).min(level.len() - 1)
        } else {
            index - 1
        };
        siblings.push(level[sibling_index]);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair_start in (0..level.len()).step_by(2) {
            let left = level[pair_start];
            let right = level.get(pair_start + 1).copied().unwrap_or(left);
            next.push(merkle_parent(left, right));
        }
        level = next;
        index >>= 1;
    }
    if level[0] != block.header.merkle_root.to_raw_hash().to_byte_array() {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    }
    Ok(BoundedMerkleBranchV1 { siblings, position })
}

fn merkle_parent(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    bitcoin::hashes::sha256d::Hash::hash(&bytes).to_byte_array()
}

fn validate_evidence(evidence: &CanonicalBitcoinRpcEvidenceV1) -> Result<(), LiveBitcoinError> {
    if evidence.genesis_hash == [0; 32]
        || evidence.raw_transaction.is_empty()
        || evidence.raw_transaction.len() > MAX_TRANSACTION_BYTES
        || evidence.canonical_block.is_empty()
        || evidence.canonical_block.len() > MAX_BLOCK_BYTES
        || evidence.merkle_branch.siblings.len() > BoundedMerkleBranchV1::MAX_DEPTH
        || usize::try_from(evidence.block_height).ok() != Some(evidence.ancestry_headers.len())
        || evidence.ancestry_headers.len() > MAX_CHAIN_HEADERS
        || evidence.confirmation_headers.len() > MAX_CHAIN_HEADERS
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    if canonical_genesis_hash(evidence.network) != evidence.genesis_hash {
        return Err(LiveBitcoinError::IdentityMismatch);
    }
    let configured_challenge = match evidence.network {
        BitcoinCoreNetworkV1::CustomSignet => evidence.signet_challenge.clone(),
        BitcoinCoreNetworkV1::Regtest | BitcoinCoreNetworkV1::PublicSignet => None,
    };
    let expected_challenge = expected_signet_challenge(evidence.network, configured_challenge)
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if expected_challenge != evidence.signet_challenge {
        return Err(LiveBitcoinError::IdentityMismatch);
    }
    let transaction: Transaction =
        deserialize(&evidence.raw_transaction).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if serialize(&transaction) != evidence.raw_transaction
        || transaction.compute_txid().to_raw_hash().to_byte_array() != evidence.txid
        || transaction.compute_wtxid().to_raw_hash().to_byte_array() != evidence.wtxid
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let block: Block =
        deserialize(&evidence.canonical_block).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if serialize(&block) != evidence.canonical_block
        || !block.check_merkle_root()
        || block.block_hash().to_raw_hash().to_byte_array() != evidence.block_hash
        || serialize(&block.header) != evidence.block_header
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let positions: Vec<usize> = block
        .txdata
        .iter()
        .enumerate()
        .filter_map(|(position, candidate)| {
            (candidate.compute_txid().to_raw_hash().to_byte_array() == evidence.txid)
                .then_some(position)
        })
        .collect();
    if positions.len() != 1
        || serialize(&block.txdata[positions[0]]) != evidence.raw_transaction
        || merkle_branch(&block, positions[0])? != evidence.merkle_branch
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut previous = None;
    for (height, raw) in evidence.ancestry_headers.iter().enumerate() {
        let header = validated_header(raw)?;
        let hash = header.block_hash().to_raw_hash().to_byte_array();
        if height == 0 {
            if hash != evidence.genesis_hash {
                return Err(LiveBitcoinError::IdentityMismatch);
            }
        } else if header.prev_blockhash.to_raw_hash().to_byte_array()
            != previous.ok_or(LiveBitcoinError::CorruptRecord)?
        {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        previous = Some(hash);
    }
    let funding_header = validated_header(&evidence.block_header)?;
    if funding_header.block_hash().to_raw_hash().to_byte_array() != evidence.block_hash
        || (evidence.block_height == 0 && evidence.block_hash != evidence.genesis_hash)
        || (evidence.block_height > 0
            && funding_header.prev_blockhash.to_raw_hash().to_byte_array()
                != previous.ok_or(LiveBitcoinError::CorruptRecord)?)
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    previous = Some(evidence.block_hash);
    for raw in &evidence.confirmation_headers {
        let header = validated_header(raw)?;
        if header.prev_blockhash.to_raw_hash().to_byte_array()
            != previous.ok_or(LiveBitcoinError::CorruptRecord)?
        {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        previous = Some(header.block_hash().to_raw_hash().to_byte_array());
    }
    let expected_tip_height = evidence
        .block_height
        .checked_add(
            u64::try_from(evidence.confirmation_headers.len())
                .map_err(|_| LiveBitcoinError::BoundsExceeded)?,
        )
        .ok_or(LiveBitcoinError::BoundsExceeded)?;
    if evidence.tip_height != expected_tip_height
        || evidence.tip_hash != previous.ok_or(LiveBitcoinError::CorruptRecord)?
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn validated_header(raw: &[u8; 80]) -> Result<Header, LiveBitcoinError> {
    let header: Header = deserialize(raw).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    header
        .validate_pow(header.target())
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    Ok(header)
}

fn encode_network(network: BitcoinCoreNetworkV1) -> u8 {
    match network {
        BitcoinCoreNetworkV1::Regtest => 1,
        BitcoinCoreNetworkV1::PublicSignet => 2,
        BitcoinCoreNetworkV1::CustomSignet => 3,
    }
}

fn decode_network(value: u8) -> Result<BitcoinCoreNetworkV1, LiveBitcoinError> {
    match value {
        1 => Ok(BitcoinCoreNetworkV1::Regtest),
        2 => Ok(BitcoinCoreNetworkV1::PublicSignet),
        3 => Ok(BitcoinCoreNetworkV1::CustomSignet),
        _ => Err(LiveBitcoinError::CorruptRecord),
    }
}

fn put_len(output: &mut Vec<u8>, length: usize) -> Result<(), LiveBitcoinError> {
    output.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| LiveBitcoinError::BoundsExceeded)?
            .to_be_bytes(),
    );
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), LiveBitcoinError> {
    put_len(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_headers(output: &mut Vec<u8>, headers: &[[u8; 80]]) -> Result<(), LiveBitcoinError> {
    put_len(output, headers.len())?;
    for header in headers {
        output.extend_from_slice(header);
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn require_magic(&mut self, expected: &[u8; 8]) -> Result<(), LiveBitcoinError> {
        if self.take(8)? != expected {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], LiveBitcoinError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(LiveBitcoinError::BoundsExceeded)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(LiveBitcoinError::CorruptRecord)?;
        self.position = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, LiveBitcoinError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(LiveBitcoinError::CorruptRecord)
    }

    fn take_u16(&mut self) -> Result<u16, LiveBitcoinError> {
        self.take(2)?
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_u32(&mut self) -> Result<u32, LiveBitcoinError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_u64(&mut self) -> Result<u64, LiveBitcoinError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], LiveBitcoinError> {
        self.take(N)?
            .try_into()
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_len(&mut self, maximum: usize) -> Result<usize, LiveBitcoinError> {
        let length =
            usize::try_from(self.take_u32()?).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
        if length > maximum {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        Ok(length)
    }

    fn take_bytes(&mut self, maximum: usize) -> Result<Vec<u8>, LiveBitcoinError> {
        let length = self.take_len(maximum)?;
        self.take(length).map(ToOwned::to_owned)
    }

    fn take_headers(&mut self) -> Result<Vec<[u8; 80]>, LiveBitcoinError> {
        let count = self.take_len(MAX_CHAIN_HEADERS)?;
        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            headers.push(self.take_array()?);
        }
        Ok(headers)
    }

    fn finish(self) -> Result<(), LiveBitcoinError> {
        if self.position != self.bytes.len() {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::Network;

    use super::*;

    fn genesis_evidence() -> Result<CanonicalBitcoinRpcEvidenceV1, LiveBitcoinError> {
        genesis_evidence_for(BitcoinCoreNetworkV1::Regtest, Network::Regtest, None)
    }

    fn genesis_evidence_for(
        network: BitcoinCoreNetworkV1,
        bitcoin_network: Network,
        signet_challenge: Option<Vec<u8>>,
    ) -> Result<CanonicalBitcoinRpcEvidenceV1, LiveBitcoinError> {
        let block = genesis_block(bitcoin_network);
        let transaction = &block.txdata[0];
        let block_hash = block.block_hash().to_raw_hash().to_byte_array();
        Ok(CanonicalBitcoinRpcEvidenceV1 {
            network,
            genesis_hash: block_hash,
            signet_challenge,
            raw_transaction: serialize(transaction),
            txid: transaction.compute_txid().to_raw_hash().to_byte_array(),
            wtxid: transaction.compute_wtxid().to_raw_hash().to_byte_array(),
            canonical_block: serialize(&block),
            block_header: serialize(&block.header)
                .try_into()
                .map_err(|_| LiveBitcoinError::CorruptRecord)?,
            block_hash,
            block_height: 0,
            merkle_branch: BoundedMerkleBranchV1 {
                siblings: Vec::new(),
                position: 0,
            },
            ancestry_headers: Vec::new(),
            confirmation_headers: Vec::new(),
            tip_height: 0,
            tip_hash: block_hash,
        })
    }

    #[test]
    fn canonical_evidence_codec_roundtrips_real_regtest_genesis() -> Result<(), LiveBitcoinError> {
        let evidence = genesis_evidence()?;
        let encoded = evidence.encode_canonical()?;
        let decoded = CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &encoded,
            BitcoinCoreNetworkV1::Regtest,
            evidence.genesis_hash,
            None,
        )?;
        assert_eq!(decoded.txid(), evidence.txid());
        assert_eq!(decoded.block_hash(), evidence.block_hash());
        assert_eq!(decoded.encode_canonical()?, encoded);
        Ok(())
    }

    #[test]
    fn canonical_evidence_rejects_tamper_and_trailing_bytes() -> Result<(), LiveBitcoinError> {
        let evidence = genesis_evidence()?;
        let encoded = evidence.encode_canonical()?;
        let mut tampered = encoded.clone();
        let raw_transaction_offset = 8 + 2 + 1 + 32 + 4 + 4;
        tampered[raw_transaction_offset] ^= 1;
        assert!(CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &tampered,
            BitcoinCoreNetworkV1::Regtest,
            evidence.genesis_hash,
            None,
        )
        .is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &trailing,
            BitcoinCoreNetworkV1::Regtest,
            evidence.genesis_hash,
            None,
        )
        .is_err());

        let encoded = evidence.encode_canonical()?;
        let mut wrong_network = encoded.clone();
        wrong_network[10] = 2;
        assert!(CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &wrong_network,
            BitcoinCoreNetworkV1::Regtest,
            evidence.genesis_hash,
            None,
        )
        .is_err());
        let mut wrong_tip = encoded;
        let last = wrong_tip
            .last_mut()
            .ok_or(LiveBitcoinError::CorruptRecord)?;
        *last ^= 1;
        assert!(CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &wrong_tip,
            BitcoinCoreNetworkV1::Regtest,
            evidence.genesis_hash,
            None,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn custom_signet_codec_requires_an_external_exact_challenge() -> Result<(), LiveBitcoinError> {
        let evidence = genesis_evidence_for(
            BitcoinCoreNetworkV1::CustomSignet,
            Network::Signet,
            Some(vec![0x51]),
        )?;
        let encoded = evidence.encode_canonical()?;
        let decoded = CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &encoded,
            BitcoinCoreNetworkV1::CustomSignet,
            evidence.genesis_hash,
            Some(&[0x51]),
        )?;
        assert_eq!(decoded.signet_challenge(), Some([0x51].as_slice()));
        assert!(CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &encoded,
            BitcoinCoreNetworkV1::CustomSignet,
            evidence.genesis_hash,
            Some(&[0x52]),
        )
        .is_err());
        assert!(CanonicalBitcoinRpcEvidenceV1::decode_canonical(
            &encoded,
            BitcoinCoreNetworkV1::CustomSignet,
            evidence.genesis_hash,
            None,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn merkle_branch_is_derived_from_real_block_not_caller_input() -> Result<(), LiveBitcoinError> {
        let block = genesis_block(Network::Regtest);
        let branch = merkle_branch(&block, 0)?;
        assert_eq!(branch.position, 0);
        assert!(branch.siblings.is_empty());
        assert!(merkle_branch(&block, 1).is_err());
        Ok(())
    }
}

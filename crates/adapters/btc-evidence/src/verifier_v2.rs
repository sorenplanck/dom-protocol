//! Full-block Bitcoin evidence V2 verification and header-authentication gate.

mod regtest;

pub use regtest::{
    RegtestHeaderAuthorityErrorV2, RegtestHeaderAuthorityV2, RegtestHeaderCheckpointV2,
    RegtestHeaderPolicyV2,
};

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::{block::Header, Block, Network};

use crate::evidence_v2::{BitcoinEvidenceNetworkV2, BitcoinOutcomeV2, KeystoneBitcoinEvidenceV2};
use crate::merkle_v2::{verify_full_block_merkle_v2, MerkleProofErrorV2};

/// An opaque attestation produced by the concrete genesis-rooted Regtest
/// header authority.
///
/// There is deliberately no public constructor or decoder. Parsing a block,
/// checking its own target, or linking caller-provided headers is insufficient
/// to construct this type. It also commits to the exact canonical V2 evidence,
/// so one header result cannot be replayed with another route, outpoint,
/// position, outcome or reorg fork. Regtest construction validates the fixed
/// expected bits, genesis-rooted checkpoint, linkage, proof of work, rolling
/// MTP, heights and cumulative chain work inside this crate. Signet has no V2
/// construction authority in this version.
pub struct AuthenticatedBlockV2 {
    _authority_seal: regtest::RegtestAuthenticationSealV2,
    network: BitcoinEvidenceNetworkV2,
    network_genesis_hash: [u8; 32],
    block_hash: [u8; 32],
    block_height: u64,
    confirmation_tip_hash: [u8; 32],
    confirmation_tip_height: u64,
    confirmation_depth: u32,
    confirmation_chain_digest: [u8; 32],
    minimum_confirmation_depth: u32,
    policy_digest: [u8; 32],
    checkpoint_digest: [u8; 32],
    evidence_digest: [u8; 32],
    genesis_rooted_chain_digest: [u8; 32],
    confirmation_tip_chain_work: [u8; 32],
    confirmation_tip_median_time_past: u32,
    header_authority_digest: [u8; 32],
}

impl AuthenticatedBlockV2 {
    /// Network authenticated by the external header authority.
    #[must_use]
    pub const fn network(&self) -> BitcoinEvidenceNetworkV2 {
        self.network
    }

    /// Exact authenticated containing block hash in internal byte order.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Exact authenticated containing block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Authenticated depth including the containing block.
    #[must_use]
    pub const fn confirmation_depth(&self) -> u32 {
        self.confirmation_depth
    }

    /// Exact authenticated confirmation-tip hash in internal byte order.
    #[must_use]
    pub const fn confirmation_tip_hash(&self) -> [u8; 32] {
        self.confirmation_tip_hash
    }

    /// Exact authenticated confirmation-tip height.
    #[must_use]
    pub const fn confirmation_tip_height(&self) -> u64 {
        self.confirmation_tip_height
    }

    /// Canonical V2 evidence digest bound by the authority.
    #[must_use]
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    /// Digest of the exact genesis-rooted Regtest header chain through the
    /// authenticated confirmation tip.
    #[must_use]
    pub const fn genesis_rooted_chain_digest(&self) -> [u8; 32] {
        self.genesis_rooted_chain_digest
    }

    /// Cumulative proof of work from the canonical Regtest genesis through
    /// the authenticated confirmation tip, encoded big-endian.
    #[must_use]
    pub const fn confirmation_tip_chain_work(&self) -> [u8; 32] {
        self.confirmation_tip_chain_work
    }

    /// Bitcoin Core rolling median-time-past at the authenticated
    /// confirmation tip.
    #[must_use]
    pub const fn confirmation_tip_median_time_past(&self) -> u32 {
        self.confirmation_tip_median_time_past
    }

    /// Digest identifying the external header authority result.
    #[must_use]
    pub const fn header_authority_digest(&self) -> [u8; 32] {
        self.header_authority_digest
    }
}

/// Verification failures for Bitcoin evidence V2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceVerificationErrorV2 {
    /// Regtest or public-Signet evidence carried a foreign genesis hash.
    #[error("V2 network genesis mismatch")]
    NetworkGenesisMismatch,
    /// The mandatory complete block failed consensus decoding.
    #[error("V2 complete block parse failed")]
    BlockParseFailed,
    /// Re-encoding the complete block did not reproduce its exact bytes.
    #[error("V2 complete block encoding is non-canonical")]
    NonCanonicalBlockEncoding,
    /// A containing or successor header failed even its stated target.
    #[error("V2 header proof-of-work is invalid")]
    InvalidHeaderWork,
    /// Successor headers do not link from the containing block.
    #[error("V2 confirmation header chain is broken")]
    BrokenHeaderChain,
    /// The supplied successor list is below the explicit minimum depth.
    #[error("V2 confirmation depth is insufficient")]
    InsufficientConfirmations,
    /// Height arithmetic overflowed.
    #[error("V2 confirmation height overflow")]
    HeightOverflow,
    /// The complete transaction tree contains Bitcoin Core's mutation pattern.
    #[error("V2 full block has a mutated merkle tree")]
    MutationDetected,
    /// At least one full-block transaction has exactly 64 stripped bytes.
    #[error("V2 full block contains an ambiguous 64-byte transaction")]
    AmbiguousTransactionSize,
    /// The complete block transaction tree does not match its header root.
    #[error("V2 full block merkle root mismatch")]
    MerkleRootMismatch,
    /// The exact witnesses in the complete block are not committed by the
    /// coinbase witness commitment.
    #[error("V2 full block witness commitment mismatch")]
    WitnessCommitmentMismatch,
    /// The canonical evidence container could not be re-encoded for authority
    /// binding. This is unreachable for a valid public constructor result and
    /// therefore indicates an invalid internal state.
    #[error("V2 canonical evidence binding failed")]
    CanonicalEvidenceBindingFailed,
    /// The position or full transaction tree is otherwise structurally invalid.
    #[error("V2 full block merkle structure is invalid")]
    InvalidMerkleStructure,
    /// The explicit transaction count differs from the mandatory full block.
    #[error("V2 explicit transaction count mismatch")]
    TransactionCountMismatch,
    /// The transaction at the explicit position has another txid.
    #[error("V2 transaction id mismatch")]
    TxidMismatch,
    /// The transaction at the explicit position has another wtxid.
    #[error("V2 witness transaction id mismatch")]
    WtxidMismatch,
    /// The transaction does not spend the exact contractual outpoint.
    #[error("V2 expected outpoint is not spent")]
    OutpointNotSpent,
    /// The witness shape contradicts the claimed terminal path.
    #[error("V2 witness shape contradicts outcome")]
    WitnessShapeInvalid,
    /// Full-block/header/confirmation facts do not match the opaque external
    /// authority result exactly.
    #[error("V2 authenticated header binding mismatch")]
    AuthenticatedHeaderMismatch,
    /// The opaque authority result belongs to another canonical V2 evidence
    /// object, even if that object reused the same block header.
    #[error("V2 authenticated evidence binding mismatch")]
    AuthenticatedEvidenceMismatch,
}

/// Operational, externally header-authenticated Bitcoin outcome V2.
///
/// This type cannot be produced by structural Merkle/header linkage alone:
/// [`verify_evidence_v2`] requires an [`AuthenticatedBlockV2`], which has no
/// public constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBitcoinOutcomeV2 {
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    outcome: BitcoinOutcomeV2,
    txid: [u8; 32],
    wtxid: [u8; 32],
    block_hash: [u8; 32],
    block_height: u64,
    confirmation_depth: u32,
    total_transactions: u32,
    transaction_position: u32,
    policy_digest: [u8; 32],
    checkpoint_digest: [u8; 32],
    evidence_digest: [u8; 32],
    genesis_rooted_chain_digest: [u8; 32],
    confirmation_tip_chain_work: [u8; 32],
    confirmation_tip_median_time_past: u32,
    header_authority_digest: [u8; 32],
}

impl VerifiedBitcoinOutcomeV2 {
    /// Exact settlement identifier.
    #[must_use]
    pub const fn settlement_id(&self) -> [u8; 32] {
        self.settlement_id
    }

    /// Exact frozen terms digest.
    #[must_use]
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms_hash
    }

    /// Verified terminal path with V2 provenance.
    #[must_use]
    pub const fn outcome(&self) -> BitcoinOutcomeV2 {
        self.outcome
    }

    /// Verified transaction id in internal byte order.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Verified witness transaction id in internal byte order.
    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }

    /// Authenticated containing block hash in internal byte order.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Authenticated containing block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Authenticated depth including the containing block.
    #[must_use]
    pub const fn confirmation_depth(&self) -> u32 {
        self.confirmation_depth
    }

    /// Exact number of transactions inspected in the complete block.
    #[must_use]
    pub const fn total_transactions(&self) -> u32 {
        self.total_transactions
    }

    /// Exact zero-based transaction position.
    #[must_use]
    pub const fn transaction_position(&self) -> u32 {
        self.transaction_position
    }

    /// Authenticated header-policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// Authenticated external-checkpoint digest.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> [u8; 32] {
        self.checkpoint_digest
    }

    /// Canonical evidence digest matched by the opaque authority.
    #[must_use]
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    /// Digest of the exact genesis-rooted Regtest header chain through the
    /// authenticated confirmation tip.
    #[must_use]
    pub const fn genesis_rooted_chain_digest(&self) -> [u8; 32] {
        self.genesis_rooted_chain_digest
    }

    /// Cumulative proof of work from genesis through the confirmation tip,
    /// encoded big-endian.
    #[must_use]
    pub const fn confirmation_tip_chain_work(&self) -> [u8; 32] {
        self.confirmation_tip_chain_work
    }

    /// Rolling median-time-past at the authenticated confirmation tip.
    #[must_use]
    pub const fn confirmation_tip_median_time_past(&self) -> u32 {
        self.confirmation_tip_median_time_past
    }

    /// Digest identifying the opaque header authority result.
    #[must_use]
    pub const fn header_authority_digest(&self) -> [u8; 32] {
        self.header_authority_digest
    }
}

/// Verifies V2 evidence against a separately authenticated block/checkpoint.
///
/// Before producing an operational outcome this function parses the mandatory
/// full block, rejects non-canonical bytes, checks every transaction for the
/// stripped 64-byte ambiguity, applies Bitcoin Core's mutation scan globally,
/// authenticates the exact witnesses through the coinbase commitment, checks
/// the explicit transaction position, and matches every chain/policy fact to
/// the opaque authority result.
pub fn verify_evidence_v2(
    evidence: &KeystoneBitcoinEvidenceV2,
    authenticated_block: &AuthenticatedBlockV2,
) -> Result<VerifiedBitcoinOutcomeV2, EvidenceVerificationErrorV2> {
    validate_canonical_network_identity(evidence)?;
    let evidence_digest = canonical_evidence_digest_v2(evidence)?;
    if authenticated_block.evidence_digest != evidence_digest {
        return Err(EvidenceVerificationErrorV2::AuthenticatedEvidenceMismatch);
    }
    let announced_transactions =
        preflight_full_block_transaction_count_v2(evidence.full_block_bytes())?;
    if announced_transactions != evidence.transaction().total_transactions() {
        return Err(EvidenceVerificationErrorV2::TransactionCountMismatch);
    }

    let block: Block = deserialize(evidence.full_block_bytes())
        .map_err(|_| EvidenceVerificationErrorV2::BlockParseFailed)?;
    if serialize(&block) != evidence.full_block_bytes() {
        return Err(EvidenceVerificationErrorV2::NonCanonicalBlockEncoding);
    }
    block
        .header
        .validate_pow(block.header.target())
        .map_err(|_| EvidenceVerificationErrorV2::InvalidHeaderWork)?;

    let position = usize::try_from(evidence.transaction().transaction_position())
        .map_err(|_| EvidenceVerificationErrorV2::InvalidMerkleStructure)?;
    let full_merkle = verify_full_block_merkle_v2(&block, position).map_err(map_merkle_error)?;
    if full_merkle.total_transactions != evidence.transaction().total_transactions() {
        return Err(EvidenceVerificationErrorV2::TransactionCountMismatch);
    }
    // The header Merkle root commits only non-witness transaction ids. Without
    // this consensus check, an attacker could replace the claimed witness,
    // update the caller-provided wtxid and retain the same authenticated
    // header. A canonical SegWit block commits every exact witness through the
    // coinbase output and reserved value.
    if !block.check_witness_commitment() {
        return Err(EvidenceVerificationErrorV2::WitnessCommitmentMismatch);
    }
    let transaction = block
        .txdata
        .get(position)
        .ok_or(EvidenceVerificationErrorV2::InvalidMerkleStructure)?;
    if transaction.compute_txid().to_raw_hash().to_byte_array() != evidence.transaction().txid() {
        return Err(EvidenceVerificationErrorV2::TxidMismatch);
    }
    if transaction.compute_wtxid().to_raw_hash().to_byte_array() != evidence.transaction().wtxid() {
        return Err(EvidenceVerificationErrorV2::WtxidMismatch);
    }

    let expected_outpoint = evidence.transaction().expected_outpoint();
    let input = transaction
        .input
        .iter()
        .find(|input| {
            input.previous_output.txid.to_raw_hash().to_byte_array() == expected_outpoint.txid()
                && input.previous_output.vout == expected_outpoint.vout()
        })
        .ok_or(EvidenceVerificationErrorV2::OutpointNotSpent)?;
    verify_witness_shape_v2(&input.witness, evidence.transaction().outcome())?;

    let block_hash = block.header.block_hash().to_raw_hash().to_byte_array();
    let mut previous = block.header.block_hash();
    for raw_header in evidence.confirmation_headers() {
        let header: Header =
            deserialize(raw_header).map_err(|_| EvidenceVerificationErrorV2::BrokenHeaderChain)?;
        header
            .validate_pow(header.target())
            .map_err(|_| EvidenceVerificationErrorV2::InvalidHeaderWork)?;
        if header.prev_blockhash != previous {
            return Err(EvidenceVerificationErrorV2::BrokenHeaderChain);
        }
        previous = header.block_hash();
    }

    let confirmation_depth = evidence.confirmation_depth();
    if confirmation_depth < evidence.header_policy().minimum_confirmation_depth() {
        return Err(EvidenceVerificationErrorV2::InsufficientConfirmations);
    }
    let confirmation_tip_height = evidence
        .header_policy()
        .block_height()
        .checked_add(
            u64::try_from(evidence.confirmation_headers().len())
                .map_err(|_| EvidenceVerificationErrorV2::HeightOverflow)?,
        )
        .ok_or(EvidenceVerificationErrorV2::HeightOverflow)?;
    let confirmation_chain_digest =
        confirmation_chain_digest_v2(&block.header, evidence.confirmation_headers());

    let policy = evidence.header_policy();
    if authenticated_block.network != policy.network()
        || authenticated_block.network_genesis_hash != policy.network_genesis_hash()
        || authenticated_block.block_hash != block_hash
        || authenticated_block.block_height != policy.block_height()
        || authenticated_block.confirmation_tip_hash != previous.to_raw_hash().to_byte_array()
        || authenticated_block.confirmation_tip_height != confirmation_tip_height
        || authenticated_block.confirmation_depth != confirmation_depth
        || authenticated_block.confirmation_chain_digest != confirmation_chain_digest
        || authenticated_block.minimum_confirmation_depth != policy.minimum_confirmation_depth()
        || authenticated_block.policy_digest != policy.policy_digest()
        || authenticated_block.checkpoint_digest != policy.checkpoint_digest()
        || authenticated_block.header_authority_digest == [0; 32]
        || full_merkle.merkle_root != block.header.merkle_root.to_raw_hash().to_byte_array()
        || full_merkle.transaction_position != evidence.transaction().transaction_position()
    {
        return Err(EvidenceVerificationErrorV2::AuthenticatedHeaderMismatch);
    }

    Ok(VerifiedBitcoinOutcomeV2 {
        settlement_id: evidence.route().settlement_id(),
        terms_hash: evidence.route().terms_hash(),
        outcome: evidence.transaction().outcome(),
        txid: evidence.transaction().txid(),
        wtxid: evidence.transaction().wtxid(),
        block_hash,
        block_height: policy.block_height(),
        confirmation_depth,
        total_transactions: full_merkle.total_transactions,
        transaction_position: full_merkle.transaction_position,
        policy_digest: policy.policy_digest(),
        checkpoint_digest: policy.checkpoint_digest(),
        evidence_digest,
        genesis_rooted_chain_digest: authenticated_block.genesis_rooted_chain_digest,
        confirmation_tip_chain_work: authenticated_block.confirmation_tip_chain_work,
        confirmation_tip_median_time_past: authenticated_block.confirmation_tip_median_time_past,
        header_authority_digest: authenticated_block.header_authority_digest,
    })
}

/// Reads only the fixed header and canonical CompactSize transaction count.
/// This runs before `bitcoin` is allowed to allocate or decode the block's
/// transaction vector.
fn preflight_full_block_transaction_count_v2(
    bytes: &[u8],
) -> Result<u32, EvidenceVerificationErrorV2> {
    const HEADER_BYTES: usize = 80;
    let discriminant = *bytes
        .get(HEADER_BYTES)
        .ok_or(EvidenceVerificationErrorV2::BlockParseFailed)?;
    let (value, noncanonical) = match discriminant {
        value @ 0x00..=0xfc => (u64::from(value), false),
        0xfd => {
            let raw: [u8; 2] = bytes
                .get(HEADER_BYTES + 1..HEADER_BYTES + 3)
                .ok_or(EvidenceVerificationErrorV2::BlockParseFailed)?
                .try_into()
                .map_err(|_| EvidenceVerificationErrorV2::BlockParseFailed)?;
            let value = u64::from(u16::from_le_bytes(raw));
            (value, value < 0xfd)
        }
        0xfe => {
            let raw: [u8; 4] = bytes
                .get(HEADER_BYTES + 1..HEADER_BYTES + 5)
                .ok_or(EvidenceVerificationErrorV2::BlockParseFailed)?
                .try_into()
                .map_err(|_| EvidenceVerificationErrorV2::BlockParseFailed)?;
            let value = u64::from(u32::from_le_bytes(raw));
            (value, value <= u64::from(u16::MAX))
        }
        0xff => {
            let raw: [u8; 8] = bytes
                .get(HEADER_BYTES + 1..HEADER_BYTES + 9)
                .ok_or(EvidenceVerificationErrorV2::BlockParseFailed)?
                .try_into()
                .map_err(|_| EvidenceVerificationErrorV2::BlockParseFailed)?;
            let value = u64::from_le_bytes(raw);
            (value, value <= u64::from(u32::MAX))
        }
    };
    if noncanonical {
        return Err(EvidenceVerificationErrorV2::NonCanonicalBlockEncoding);
    }
    let count =
        u32::try_from(value).map_err(|_| EvidenceVerificationErrorV2::InvalidMerkleStructure)?;
    if count == 0 || count > KeystoneBitcoinEvidenceV2::MAX_TRANSACTIONS {
        return Err(EvidenceVerificationErrorV2::InvalidMerkleStructure);
    }
    Ok(count)
}

fn validate_canonical_network_identity(
    evidence: &KeystoneBitcoinEvidenceV2,
) -> Result<(), EvidenceVerificationErrorV2> {
    let canonical_network = match evidence.header_policy().network() {
        BitcoinEvidenceNetworkV2::Regtest => Some(Network::Regtest),
        BitcoinEvidenceNetworkV2::PublicSignet => Some(Network::Signet),
        BitcoinEvidenceNetworkV2::CustomSignet => None,
    };
    if let Some(network) = canonical_network {
        let expected = genesis_block(network)
            .block_hash()
            .to_raw_hash()
            .to_byte_array();
        if evidence.header_policy().network_genesis_hash() != expected {
            return Err(EvidenceVerificationErrorV2::NetworkGenesisMismatch);
        }
    }
    Ok(())
}

fn map_merkle_error(error: MerkleProofErrorV2) -> EvidenceVerificationErrorV2 {
    match error {
        MerkleProofErrorV2::MutationDetected => EvidenceVerificationErrorV2::MutationDetected,
        MerkleProofErrorV2::AmbiguousTransactionSize => {
            EvidenceVerificationErrorV2::AmbiguousTransactionSize
        }
        MerkleProofErrorV2::MerkleRootMismatch => EvidenceVerificationErrorV2::MerkleRootMismatch,
        MerkleProofErrorV2::EmptyTransactionSet
        | MerkleProofErrorV2::TransactionCountBoundExceeded
        | MerkleProofErrorV2::PositionOutOfRange
        | MerkleProofErrorV2::BranchTooDeep
        | MerkleProofErrorV2::BranchLengthMismatch
        | MerkleProofErrorV2::NonCanonicalOddDuplication => {
            EvidenceVerificationErrorV2::InvalidMerkleStructure
        }
    }
}

fn verify_witness_shape_v2(
    witness: &bitcoin::Witness,
    outcome: BitcoinOutcomeV2,
) -> Result<(), EvidenceVerificationErrorV2> {
    let items: Vec<&[u8]> = witness.iter().collect();
    if items.len() >= 2 && items.last().and_then(|last| last.first()) == Some(&0x50) {
        return Err(EvidenceVerificationErrorV2::WitnessShapeInvalid);
    }
    match outcome {
        BitcoinOutcomeV2::KeyPathClaim if items.len() == 1 && items[0].len() == 64 => Ok(()),
        BitcoinOutcomeV2::CsvScriptPathRefund if items.len() == 3 => Ok(()),
        BitcoinOutcomeV2::KeyPathClaim | BitcoinOutcomeV2::CsvScriptPathRefund => {
            Err(EvidenceVerificationErrorV2::WitnessShapeInvalid)
        }
    }
}

fn confirmation_chain_digest_v2(
    containing_header: &Header,
    confirmation_headers: &[[u8; 80]],
) -> [u8; 32] {
    const DOMAIN: &[u8] = b"DOM/BTC-EVIDENCE/V2/CONFIRMATION-CHAIN\0";
    let mut bytes = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(80usize.saturating_mul(confirmation_headers.len().saturating_add(1))),
    );
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&serialize(containing_header));
    for header in confirmation_headers {
        bytes.extend_from_slice(header);
    }
    bitcoin::hashes::sha256d::Hash::hash(&bytes).to_byte_array()
}

fn canonical_evidence_digest_v2(
    evidence: &KeystoneBitcoinEvidenceV2,
) -> Result<[u8; 32], EvidenceVerificationErrorV2> {
    const DOMAIN: &[u8] = b"DOM/BTC-EVIDENCE/V2/AUTHORITY-BINDING\0";
    let encoded = evidence
        .encode()
        .map_err(|_| EvidenceVerificationErrorV2::CanonicalEvidenceBindingFailed)?;
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(DOMAIN);
    engine.input(&encoded);
    Ok(bitcoin::hashes::sha256d::Hash::from_engine(engine).to_byte_array())
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::blockdata::block::Version;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
        Txid, Witness,
    };

    use crate::evidence_v2::{
        BitcoinEvidenceRouteBindingV2, BitcoinHeaderPolicyBindingV2, BitcoinOutPointV2,
        BitcoinTransactionClaimV2,
    };

    use super::*;

    fn transaction(tag: u8, script_bytes: usize) -> Transaction {
        let mut witness = Witness::new();
        witness.push([0x11; 64]);
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
                script_pubkey: ScriptBuf::from_bytes(vec![tag; script_bytes]),
            }],
        }
    }

    fn merkle_root(transactions: &[Transaction]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = transactions
            .iter()
            .map(|transaction| transaction.compute_txid().to_raw_hash().to_byte_array())
            .collect();
        while level.len() > 1 {
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                let mut bytes = [0u8; 64];
                bytes[..32].copy_from_slice(&left);
                bytes[32..].copy_from_slice(&right);
                next.push(bitcoin::hashes::sha256d::Hash::hash(&bytes).to_byte_array());
            }
            level = next;
        }
        level[0]
    }

    fn mine_header(header: &mut Header) {
        let target = header.target();
        while header.validate_pow(target).is_err() {
            header.nonce = header.nonce.checked_add(1).expect("easy regtest target");
        }
    }

    fn with_coinbase_witness_commitment(mut transactions: Vec<Transaction>) -> Vec<Transaction> {
        let witness_reserved_value = [0u8; 32];
        let mut coinbase_witness = Witness::new();
        coinbase_witness.push(witness_reserved_value);
        let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_script.extend_from_slice(&[0u8; 32]);
        let coinbase = Transaction {
            version: TxVersion(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: coinbase_witness,
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commitment_script),
            }],
        };
        transactions.insert(0, coinbase);

        let provisional = Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: transactions,
        };
        let witness_root = provisional
            .witness_root()
            .expect("coinbase and test transactions have a witness root");
        let commitment =
            Block::compute_witness_commitment(&witness_root, witness_reserved_value.as_slice());
        let mut transactions = provisional.txdata;
        transactions[0].output[0].script_pubkey.as_mut_bytes()[6..38]
            .copy_from_slice(commitment.as_byte_array());
        transactions
    }

    struct EvidenceAuthorityFixtureV2 {
        evidence: KeystoneBitcoinEvidenceV2,
        authority: RegtestHeaderAuthorityV2,
        continuation: Vec<[u8; 80]>,
    }

    impl EvidenceAuthorityFixtureV2 {
        fn authenticate(&self, evidence: &KeystoneBitcoinEvidenceV2) -> AuthenticatedBlockV2 {
            self.authority
                .authenticate(evidence, &self.continuation)
                .expect("genesis-rooted Regtest authority authenticates fixture")
        }
    }

    fn evidence_and_authority(
        transactions: Vec<Transaction>,
        position: usize,
    ) -> EvidenceAuthorityFixtureV2 {
        let transactions = with_coinbase_witness_commitment(transactions);
        let position = position
            .checked_add(1)
            .expect("test position accounts for the coinbase");
        let root = merkle_root(&transactions);
        let genesis = genesis_block(Network::Regtest);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::from_raw_hash(Hash::from_byte_array(root)),
                time: genesis.header.time.saturating_add(1),
                bits: CompactTarget::from_consensus(RegtestHeaderPolicyV2::EXPECTED_BITS),
                nonce: 0,
            },
            txdata: transactions,
        };
        assert!(
            block.check_witness_commitment(),
            "test block authenticates every exact witness"
        );
        mine_header(&mut block.header);
        let block_hash = block.header.block_hash();
        let mut successor = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: block_hash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: block.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(RegtestHeaderPolicyV2::EXPECTED_BITS),
            nonce: 0,
        };
        mine_header(&mut successor);
        let successor_raw: [u8; 80] = serialize(&successor)
            .try_into()
            .expect("header is exactly 80 bytes");
        let transaction = &block.txdata[position];
        let expected_outpoint = BitcoinOutPointV2::new(
            transaction.input[0]
                .previous_output
                .txid
                .to_raw_hash()
                .to_byte_array(),
            transaction.input[0].previous_output.vout,
        )
        .expect("valid V2 outpoint");
        let route =
            BitcoinEvidenceRouteBindingV2::new([1; 32], [2; 32]).expect("valid route binding");
        let authority_policy = RegtestHeaderPolicyV2::new(2).expect("valid fixed Regtest policy");
        let checkpoint =
            RegtestHeaderCheckpointV2::genesis().expect("canonical Regtest genesis checkpoint");
        let policy_binding = BitcoinHeaderPolicyBindingV2::new(
            BitcoinEvidenceNetworkV2::Regtest,
            genesis.block_hash().to_raw_hash().to_byte_array(),
            1,
            authority_policy.digest(),
            checkpoint.digest(),
            2,
        )
        .expect("valid policy binding");
        let claim = BitcoinTransactionClaimV2::new(
            transaction.compute_txid().to_raw_hash().to_byte_array(),
            transaction.compute_wtxid().to_raw_hash().to_byte_array(),
            expected_outpoint,
            u32::try_from(block.txdata.len()).expect("test transaction count fits u32"),
            u32::try_from(position).expect("test position fits u32"),
            BitcoinOutcomeV2::KeyPathClaim,
        )
        .expect("valid transaction claim");
        let evidence = KeystoneBitcoinEvidenceV2::new(
            route,
            policy_binding,
            claim,
            serialize(&block),
            vec![successor_raw],
        )
        .expect("valid evidence container");
        let block_header: [u8; 80] = serialize(&block.header)
            .try_into()
            .expect("header is exactly 80 bytes");
        EvidenceAuthorityFixtureV2 {
            evidence,
            authority: RegtestHeaderAuthorityV2::new(authority_policy, checkpoint),
            continuation: vec![block_header],
        }
    }

    #[test]
    fn operational_outcome_requires_exact_opaque_header_binding() {
        let fixture = evidence_and_authority(vec![transaction(1, 3), transaction(2, 3)], 1);
        let authenticated = fixture.authenticate(&fixture.evidence);
        let evidence = &fixture.evidence;
        let verified = verify_evidence_v2(evidence, &authenticated).expect("fully bound V2");
        assert_eq!(verified.confirmation_depth(), 2);
        assert_eq!(verified.total_transactions(), 3);
        assert_eq!(verified.transaction_position(), 2);
        assert_ne!(verified.header_authority_digest(), [0; 32]);
        assert_eq!(verified.evidence_digest(), authenticated.evidence_digest());
        assert_eq!(
            verified.genesis_rooted_chain_digest(),
            authenticated.genesis_rooted_chain_digest()
        );
        assert_eq!(
            verified.confirmation_tip_chain_work(),
            authenticated.confirmation_tip_chain_work()
        );
        assert_eq!(
            verified.confirmation_tip_median_time_past(),
            authenticated.confirmation_tip_median_time_past()
        );
        assert_eq!(verified.outcome(), BitcoinOutcomeV2::KeyPathClaim);
        assert_eq!(verified.terms_hash(), [2; 32]);
        match crate::bridge::verified_v2_outcome_to_uspe_event(&verified) {
            uspe::AssuranceEvent::CompensationClaimed { terms_hash } => {
                assert_eq!(terms_hash, [2; 32]);
            }
            _ => panic!("unexpected V2 USPE event"),
        }
    }

    #[test]
    fn opaque_header_result_cannot_be_replayed_with_other_route_provenance() {
        let fixture = evidence_and_authority(vec![transaction(1, 3), transaction(2, 3)], 1);
        let authenticated = fixture.authenticate(&fixture.evidence);
        let evidence = &fixture.evidence;
        let changed_route = BitcoinEvidenceRouteBindingV2::new([9; 32], [8; 32])
            .expect("different non-zero route binding");
        let rerouted = KeystoneBitcoinEvidenceV2::new(
            changed_route,
            *evidence.header_policy(),
            *evidence.transaction(),
            evidence.full_block_bytes().to_vec(),
            evidence.confirmation_headers().to_vec(),
        )
        .expect("rerouted object remains structurally bounded");

        assert_eq!(
            verify_evidence_v2(&rerouted, &authenticated).unwrap_err(),
            EvidenceVerificationErrorV2::AuthenticatedEvidenceMismatch
        );
    }

    #[test]
    fn full_v2_verifier_rejects_off_path_mutation_and_any_64_byte_transaction() {
        let mut mutated: Vec<Transaction> = (1..=6).map(|tag| transaction(tag, 3)).collect();
        mutated.push(mutated[5].clone());
        let mutated_fixture = evidence_and_authority(mutated, 0);
        let mutated_authentication = mutated_fixture.authenticate(&mutated_fixture.evidence);
        assert_eq!(
            verify_evidence_v2(&mutated_fixture.evidence, &mutated_authentication).unwrap_err(),
            EvidenceVerificationErrorV2::MutationDetected
        );

        let ambiguous_fixture =
            evidence_and_authority(vec![transaction(1, 3), transaction(2, 4)], 0);
        let ambiguous_authentication = ambiguous_fixture.authenticate(&ambiguous_fixture.evidence);
        assert_eq!(
            verify_evidence_v2(&ambiguous_fixture.evidence, &ambiguous_authentication).unwrap_err(),
            EvidenceVerificationErrorV2::AmbiguousTransactionSize
        );
    }

    #[test]
    fn exact_witnesses_must_match_the_coinbase_commitment() {
        let fixture = evidence_and_authority(vec![transaction(1, 3), transaction(2, 3)], 1);
        let evidence = &fixture.evidence;
        let mut block: Block =
            deserialize(evidence.full_block_bytes()).expect("valid full-block fixture");
        let position = usize::try_from(evidence.transaction().transaction_position())
            .expect("test position fits usize");
        let original_txid = block.txdata[position].compute_txid();
        let mut replacement_witness = Witness::new();
        replacement_witness.push([0x22; 64]);
        block.txdata[position].input[0].witness = replacement_witness;
        assert_eq!(block.txdata[position].compute_txid(), original_txid);
        assert_ne!(
            block.txdata[position]
                .compute_wtxid()
                .to_raw_hash()
                .to_byte_array(),
            evidence.transaction().wtxid()
        );

        let altered_claim = BitcoinTransactionClaimV2::new(
            evidence.transaction().txid(),
            block.txdata[position]
                .compute_wtxid()
                .to_raw_hash()
                .to_byte_array(),
            evidence.transaction().expected_outpoint(),
            evidence.transaction().total_transactions(),
            evidence.transaction().transaction_position(),
            evidence.transaction().outcome(),
        )
        .expect("altered witness remains a structurally valid claim");
        let altered_evidence = KeystoneBitcoinEvidenceV2::new(
            *evidence.route(),
            *evidence.header_policy(),
            altered_claim,
            serialize(&block),
            evidence.confirmation_headers().to_vec(),
        )
        .expect("altered witness remains a bounded container");
        let authenticated = fixture.authenticate(&altered_evidence);

        assert_eq!(
            verify_evidence_v2(&altered_evidence, &authenticated).unwrap_err(),
            EvidenceVerificationErrorV2::WitnessCommitmentMismatch
        );
    }

    #[test]
    fn explicit_transaction_count_must_match_the_complete_block() {
        let fixture = evidence_and_authority(vec![transaction(1, 3), transaction(2, 3)], 0);
        let evidence = &fixture.evidence;
        let claim = BitcoinTransactionClaimV2::new(
            evidence.transaction().txid(),
            evidence.transaction().wtxid(),
            evidence.transaction().expected_outpoint(),
            4,
            evidence.transaction().transaction_position(),
            evidence.transaction().outcome(),
        )
        .expect("structurally valid but false explicit count");
        let mismatched = KeystoneBitcoinEvidenceV2::new(
            *evidence.route(),
            *evidence.header_policy(),
            claim,
            evidence.full_block_bytes().to_vec(),
            evidence.confirmation_headers().to_vec(),
        )
        .expect("bounded mismatched evidence");
        let authenticated = fixture.authenticate(&mismatched);

        assert_eq!(
            verify_evidence_v2(&mismatched, &authenticated).unwrap_err(),
            EvidenceVerificationErrorV2::TransactionCountMismatch
        );
    }

    #[test]
    fn full_block_count_is_bounded_and_canonical_before_transaction_decode() {
        let mut excessive = vec![0u8; 89];
        excessive[80] = 0xfe;
        excessive[81..85].copy_from_slice(
            &KeystoneBitcoinEvidenceV2::MAX_TRANSACTIONS
                .saturating_add(1)
                .to_le_bytes(),
        );
        assert_eq!(
            preflight_full_block_transaction_count_v2(&excessive).unwrap_err(),
            EvidenceVerificationErrorV2::InvalidMerkleStructure
        );

        let mut noncanonical = vec![0u8; 83];
        noncanonical[80] = 0xfd;
        noncanonical[81..83].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            preflight_full_block_transaction_count_v2(&noncanonical).unwrap_err(),
            EvidenceVerificationErrorV2::NonCanonicalBlockEncoding
        );
    }
}

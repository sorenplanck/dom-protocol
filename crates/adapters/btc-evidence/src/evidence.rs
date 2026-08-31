//! Evidence and verified-outcome types (Annex M M.9.3, M.9.5).

/// The F5 networks (evidence from a different network identity is invalid
/// even if the txid matches — M.13.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinEvidenceNetworkV1 {
    /// Deterministic local network.
    Regtest,
    /// Persistent controlled signet.
    CustomSignet,
    /// The public signet.
    PublicSignet,
}

/// A previous output (M.9.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinOutPointV1 {
    /// Transaction id (internal byte order).
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

/// The terminal Bitcoin outcome (M.9.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinOutcomeV1 {
    /// A cooperative key-path MuSig2/adaptor claim.
    KeyPathClaim,
    /// A unilateral CSV script-path refund.
    CsvScriptPathRefund,
}

/// A bounded Merkle inclusion branch (M.9.3). Capped so an adversarial
/// proof cannot force unbounded allocation (M.10.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoundedMerkleBranchV1 {
    /// The sibling hashes, leaf-to-root, at most [`Self::MAX_DEPTH`].
    pub siblings: Vec<[u8; 32]>,
    /// The 0-based index of the transaction in the block.
    pub position: u32,
}

impl BoundedMerkleBranchV1 {
    /// The maximum branch depth (a block cannot hold more than 2^32 txs;
    /// 32 levels is a generous, DoS-safe cap).
    pub const MAX_DEPTH: usize = 32;
}

/// The evidence a verifier consumes (M.9.3). `raw_transaction` and the
/// witness are parsed by the audited `bitcoin` crate; caps are enforced
/// before allocation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeystoneBitcoinEvidenceV1 {
    /// Codec version.
    pub codec_version: u16,
    /// The network's genesis hash (identity check).
    pub network: BitcoinEvidenceNetworkV1,
    /// Genesis hash bytes of the network identity.
    pub network_genesis_hash: [u8; 32],
    /// The settlement this evidence belongs to.
    pub settlement_id: [u8; 32],
    /// A3 authority hash of the terms.
    pub terms_hash: [u8; 32],
    /// The contractual outpoint being spent.
    pub expected_outpoint: BitcoinOutPointV1,
    /// The raw spending transaction bytes.
    pub raw_transaction: Vec<u8>,
    /// Its txid (double-SHA256 of the non-witness serialization).
    pub txid: [u8; 32],
    /// Its wtxid (double-SHA256 of the witness serialization).
    pub wtxid: [u8; 32],
    /// The 80-byte block header containing it.
    pub block_header: [u8; 80],
    /// The block height.
    pub block_height: u64,
    /// The Merkle branch proving txid inclusion in the header's root.
    pub txid_merkle_branch: BoundedMerkleBranchV1,
    /// Headers confirming the block (chain of `confirmations`).
    pub confirmation_headers: Vec<[u8; 80]>,
    /// The claimed outcome, cross-checked against the witness shape.
    pub outcome: BitcoinOutcomeV1,
}

impl KeystoneBitcoinEvidenceV1 {
    /// The only codec version accepted by the frozen V1 verifier.
    pub const CODEC_VERSION: u16 = 1;
}

/// Legacy V1 structurally verified facts.
///
/// V1 does not authenticate expected difficulty, retarget, MTP, chain work or
/// an external checkpoint and therefore is not accepted by the operational
/// USPE bridge. The type remains byte/source compatible for explicit migration
/// and historical evidence handling.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifiedBitcoinOutcomeV1 {
    /// The settlement this outcome settles.
    pub settlement_id: [u8; 32],
    /// A3 authority hash of the terms.
    pub terms_hash: [u8; 32],
    /// The verified outcome.
    pub outcome: BitcoinOutcomeV1,
    /// The verified txid.
    pub txid: [u8; 32],
    /// The verified wtxid.
    pub wtxid: [u8; 32],
    /// The containing block hash.
    pub block_hash: [u8; 32],
    /// The block height.
    pub block_height: u64,
    /// The confirmation depth achieved.
    pub confirmation_depth: u32,
}

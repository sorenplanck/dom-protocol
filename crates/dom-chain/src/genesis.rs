//! Canonical fully rooted genesis construction for DOM Protocol.
//!
//! This module is the sole genesis authority used by node startup and vectors.
//! Testnet and Regtest retain the legacy canonical `Block` representation.
//! Mainnet uses a versioned identity envelope because its genesis body is
//! economically empty and its inscription is consensus metadata, not a
//! transaction, output, kernel, proof, or recovery capsule.

use dom_consensus::block::ProofOfWork;
use dom_consensus::{
    compute_block_pmmr_roots, Block, BlockHeader, CoinbaseKernel, CoinbaseTransaction,
    TransactionOutput,
};
use dom_core::{
    BlockHeight, DomError, Hash256, GENESIS_MESSAGE, GENESIS_NONCE_MAINNET, GENESIS_NONCE_REGTEST,
    GENESIS_POW_DIGEST_MAINNET, GENESIS_POW_DIGEST_REGTEST, KERNEL_FEAT_COINBASE,
    NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET, PROTOCOL_VERSION,
    TAG_GENESIS_BLINDING, TAG_GENESIS_INSCRIPTION, TAG_KERNEL_MSG_COINBASE,
    TAG_MAINNET_GENESIS_IDENTITY,
};
use dom_crypto::hash::{blake2b_256, blake2b_256_tagged};
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::{genesis_anchor, target_to_compact, target_to_difficulty, CompactTarget};
use dom_serialization::{DomDeserialize, DomSerialize};
use primitive_types::U256;

/// Canonical version byte for `GenesisInscriptionV1`.
pub const GENESIS_INSCRIPTION_VERSION: u8 = 0x01;
/// Maximum UTF-8 payload accepted by a genesis inscription.
pub const MAX_GENESIS_INSCRIPTION_BYTES: usize = 256;
/// Canonical version byte for `MainnetGenesisIdentityV1`.
pub const MAINNET_GENESIS_IDENTITY_VERSION: u8 = 0x01;

const BLOCK_HEADER_BYTES: usize = BlockHeader::MIN_SERIALIZED_SIZE;
const EMPTY_BODY_BYTES: [u8; 16] = [0u8; 16];
const MAINNET_INSCRIPTION_COUNT: u8 = 1;
// Derived once from `TAG_CHAIN_ID`, Regtest magic, and the pre-finalization
// all-zero configured hash. Pinning this historical signing context preserves
// the deterministic Regtest fixture while removing the hash/chain-ID cycle.
const REGTEST_GENESIS_SIGNING_CONTEXT: [u8; 32] = [
    0x47, 0x3d, 0x3b, 0xe0, 0xc7, 0x97, 0x55, 0x6b, 0xee, 0x04, 0xa1, 0xdd, 0xc7, 0x7f, 0x13, 0xbb,
    0xd4, 0x3e, 0x92, 0xda, 0xec, 0xca, 0xdc, 0x34, 0xd4, 0xa5, 0xa9, 0xf2, 0xd3, 0xe6, 0x1b, 0xeb,
];

/// Return whether a candidate Mainnet economic-body encoding contains exactly
/// four zero big-endian counts: inputs, outputs, kernels, and transactions.
pub(crate) fn is_empty_mainnet_economic_body(body: &[u8]) -> bool {
    body == EMPTY_BODY_BYTES
}

/// Versioned, length-bounded UTF-8 genesis inscription.
///
/// Canonical encoding is `0x01 || u16_be(payload_length) || payload`. No
/// normalization, padding, terminator, or newline is permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisInscriptionV1 {
    bytes: Vec<u8>,
}

impl GenesisInscriptionV1 {
    /// Construct an inscription after enforcing the version-1 payload rules.
    pub fn new(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() > MAX_GENESIS_INSCRIPTION_BYTES {
            return Err(DomError::Invalid(format!(
                "genesis inscription payload exceeds {MAX_GENESIS_INSCRIPTION_BYTES} bytes"
            )));
        }
        std::str::from_utf8(bytes)
            .map_err(|_| DomError::Invalid("genesis inscription is not valid UTF-8".into()))?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Construct the exact inscription required by Mainnet consensus.
    pub fn mainnet() -> Self {
        Self {
            bytes: GENESIS_MESSAGE.as_bytes().to_vec(),
        }
    }

    /// Return the exact unmodified UTF-8 payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }

    /// Decode the payload as UTF-8.
    pub fn text(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("GenesisInscriptionV1 always contains valid UTF-8")
    }

    /// Return the canonical version-1 encoding.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DomError> {
        let length = u16::try_from(self.bytes.len())
            .map_err(|_| DomError::Invalid("genesis inscription length exceeds u16".into()))?;
        let mut encoded = Vec::with_capacity(3 + self.bytes.len());
        encoded.push(GENESIS_INSCRIPTION_VERSION);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&self.bytes);
        Ok(encoded)
    }

    /// Parse one complete canonical version-1 inscription.
    pub fn from_canonical_bytes(encoded: &[u8]) -> Result<Self, DomError> {
        if encoded.len() < 3 {
            return Err(DomError::Malformed(
                "genesis inscription is shorter than its canonical prefix".into(),
            ));
        }
        if encoded[0] != GENESIS_INSCRIPTION_VERSION {
            return Err(DomError::Invalid(format!(
                "unsupported genesis inscription version: {}",
                encoded[0]
            )));
        }
        let declared = usize::from(u16::from_be_bytes([encoded[1], encoded[2]]));
        if declared > MAX_GENESIS_INSCRIPTION_BYTES {
            return Err(DomError::Invalid(format!(
                "genesis inscription payload exceeds {MAX_GENESIS_INSCRIPTION_BYTES} bytes"
            )));
        }
        let actual = encoded.len().saturating_sub(3);
        if actual != declared {
            return Err(DomError::Malformed(format!(
                "genesis inscription length mismatch: declared {declared}, actual {actual}"
            )));
        }
        Self::new(&encoded[3..])
    }

    /// Compute the domain-separated Blake2b-256 inscription commitment.
    pub fn commitment(&self) -> Result<Hash256, DomError> {
        Ok(blake2b_256_tagged(
            TAG_GENESIS_INSCRIPTION,
            &self.to_canonical_bytes()?,
        ))
    }
}

/// Parsed canonical Mainnet genesis identity envelope.
///
/// Encoding, in order:
///
/// `version_u8 || header_len_u16_be || header || body_len_u16_be || body ||`
/// `inscription_count_u8 || inscription_len_u16_be || inscription || commitment`.
///
/// Version 1 requires a 256-byte ordinary canonical header, a 16-byte empty
/// body containing four zero `u32_be` counts (inputs, outputs, kernels, and
/// transactions), exactly one inscription, and its 32-byte tagged commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainnetGenesisIdentityV1 {
    header_bytes: Vec<u8>,
    inscription: GenesisInscriptionV1,
}

impl MainnetGenesisIdentityV1 {
    /// Construct the canonical Mainnet identity using an economically empty body.
    pub fn new(header_bytes: Vec<u8>, inscription: GenesisInscriptionV1) -> Result<Self, DomError> {
        validate_mainnet_header(&header_bytes)?;
        validate_exact_mainnet_inscription(&inscription)?;
        Ok(Self {
            header_bytes,
            inscription,
        })
    }

    /// Return the canonical rooted header bytes committed by this identity.
    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }

    /// Return the inscription decoded from this identity envelope.
    pub fn inscription(&self) -> &GenesisInscriptionV1 {
        &self.inscription
    }

    /// Return the canonical economically empty body encoding.
    pub fn body_bytes(&self) -> &'static [u8] {
        &EMPTY_BODY_BYTES
    }

    /// Serialize the complete canonical Mainnet genesis identity envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DomError> {
        let inscription_bytes = self.inscription.to_canonical_bytes()?;
        let header_length = u16::try_from(self.header_bytes.len())
            .map_err(|_| DomError::Internal("Mainnet genesis header length exceeds u16".into()))?;
        let body_length = u16::try_from(EMPTY_BODY_BYTES.len())
            .map_err(|_| DomError::Internal("Mainnet genesis body length exceeds u16".into()))?;
        let inscription_length = u16::try_from(inscription_bytes.len()).map_err(|_| {
            DomError::Internal("Mainnet genesis inscription length exceeds u16".into())
        })?;
        let commitment = self.inscription.commitment()?;
        let capacity = 1usize
            .saturating_add(2)
            .saturating_add(self.header_bytes.len())
            .saturating_add(2)
            .saturating_add(EMPTY_BODY_BYTES.len())
            .saturating_add(1)
            .saturating_add(2)
            .saturating_add(inscription_bytes.len())
            .saturating_add(32);
        let mut encoded = Vec::with_capacity(capacity);
        encoded.push(MAINNET_GENESIS_IDENTITY_VERSION);
        encoded.extend_from_slice(&header_length.to_be_bytes());
        encoded.extend_from_slice(&self.header_bytes);
        encoded.extend_from_slice(&body_length.to_be_bytes());
        encoded.extend_from_slice(&EMPTY_BODY_BYTES);
        encoded.push(MAINNET_INSCRIPTION_COUNT);
        encoded.extend_from_slice(&inscription_length.to_be_bytes());
        encoded.extend_from_slice(&inscription_bytes);
        encoded.extend_from_slice(commitment.as_bytes());
        Ok(encoded)
    }

    /// Parse and validate one complete canonical Mainnet identity envelope.
    pub fn from_canonical_bytes(encoded: &[u8]) -> Result<Self, DomError> {
        let mut cursor = 0usize;
        let version = take(encoded, &mut cursor, 1)?[0];
        if version != MAINNET_GENESIS_IDENTITY_VERSION {
            return Err(DomError::Invalid(format!(
                "unsupported Mainnet genesis identity version: {version}"
            )));
        }
        let header_length = read_u16_be(encoded, &mut cursor)?;
        if header_length != BLOCK_HEADER_BYTES {
            return Err(DomError::Malformed(format!(
                "Mainnet genesis header length must be {BLOCK_HEADER_BYTES}, got {header_length}"
            )));
        }
        let header_bytes = take(encoded, &mut cursor, header_length)?.to_vec();
        validate_mainnet_header(&header_bytes)?;

        let body_length = read_u16_be(encoded, &mut cursor)?;
        if body_length != EMPTY_BODY_BYTES.len() {
            return Err(DomError::Malformed(format!(
                "Mainnet genesis empty body length must be {}, got {body_length}",
                EMPTY_BODY_BYTES.len()
            )));
        }
        let body = take(encoded, &mut cursor, body_length)?;
        if !is_empty_mainnet_economic_body(body) {
            return Err(DomError::Invalid(
                "Mainnet genesis body must contain zero inputs, outputs, kernels, and transactions"
                    .into(),
            ));
        }

        let inscription_count = take(encoded, &mut cursor, 1)?[0];
        if inscription_count != MAINNET_INSCRIPTION_COUNT {
            return Err(DomError::Invalid(format!(
                "Mainnet genesis requires exactly one inscription, got {inscription_count}"
            )));
        }
        let inscription_length = read_u16_be(encoded, &mut cursor)?;
        let inscription_bytes = take(encoded, &mut cursor, inscription_length)?;
        let inscription = GenesisInscriptionV1::from_canonical_bytes(inscription_bytes)?;
        validate_exact_mainnet_inscription(&inscription)?;

        let stored_commitment = take(encoded, &mut cursor, 32)?;
        let computed_commitment = inscription.commitment()?;
        if stored_commitment != computed_commitment.as_bytes() {
            return Err(DomError::Invalid(
                "Mainnet genesis inscription commitment mismatch".into(),
            ));
        }
        if cursor != encoded.len() {
            return Err(DomError::Malformed(format!(
                "trailing Mainnet genesis identity bytes: {}",
                encoded.len().saturating_sub(cursor)
            )));
        }

        Ok(Self {
            header_bytes,
            inscription,
        })
    }

    /// Compute the Mainnet genesis identity hash over the complete envelope.
    ///
    /// This computes a candidate identity only. The repository intentionally
    /// does not pin it until the later offline timestamp and nonce ceremony.
    pub fn identity_hash(&self) -> Result<Hash256, DomError> {
        Ok(blake2b_256_tagged(
            TAG_MAINNET_GENESIS_IDENTITY,
            &self.to_canonical_bytes()?,
        ))
    }
}

/// Complete deterministic genesis construction result.
#[derive(Debug, Clone)]
pub struct CanonicalGenesis {
    /// Legacy canonical block for Testnet and Regtest; absent for Mainnet V1.
    pub block: Option<Block>,
    /// Canonical rooted header bytes.
    pub header_bytes: Vec<u8>,
    /// Complete canonical genesis representation for the selected network.
    pub block_bytes: Vec<u8>,
    /// Genesis identity hash for the selected network.
    pub hash: Hash256,
}

impl CanonicalGenesis {
    /// Decode the Mainnet inscription from canonical genesis data.
    ///
    /// This accessor parses `block_bytes`; it never reads documentation,
    /// configuration, logs, or an environment variable.
    pub fn inscription(
        &self,
        network_magic: u32,
    ) -> Result<Option<GenesisInscriptionV1>, DomError> {
        canonical_genesis_inscription(network_magic, &self.block_bytes)
    }
}

/// Build the canonical fully rooted genesis representation for a recognized network.
///
/// This is the sole high-level production genesis constructor. Testnet and
/// Regtest retain their existing block bytes and Blake2b-256 header identity.
/// Mainnet uses `MainnetGenesisIdentityV1`, whose tagged hash commits to the
/// rooted header, the explicitly empty body, the literal inscription encoding,
/// and the inscription commitment. Mainnet remains unfinalized and inactive.
pub fn build_canonical_genesis(
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<CanonicalGenesis, DomError> {
    match network_magic {
        NETWORK_MAGIC_MAINNET => construct_mainnet_identity(),
        NETWORK_MAGIC_TESTNET | NETWORK_MAGIC_REGTEST => {
            build_legacy_canonical_genesis(network_magic, chain_id)
        }
        _ => Err(DomError::Invalid(format!(
            "unknown network magic for canonical genesis: 0x{network_magic:08x}"
        ))),
    }
}

/// Decode the canonical inscription only for Mainnet genesis data.
pub fn canonical_genesis_inscription(
    network_magic: u32,
    canonical_bytes: &[u8],
) -> Result<Option<GenesisInscriptionV1>, DomError> {
    match network_magic {
        NETWORK_MAGIC_MAINNET => Ok(Some(
            MainnetGenesisIdentityV1::from_canonical_bytes(canonical_bytes)?.inscription,
        )),
        NETWORK_MAGIC_TESTNET | NETWORK_MAGIC_REGTEST => Ok(None),
        _ => Err(DomError::Invalid(format!(
            "unknown network magic for genesis inscription: 0x{network_magic:08x}"
        ))),
    }
}

/// Validate a complete Mainnet genesis identity and its exact inscription.
pub fn validate_mainnet_genesis_identity(
    canonical_bytes: &[u8],
) -> Result<MainnetGenesisIdentityV1, DomError> {
    MainnetGenesisIdentityV1::from_canonical_bytes(canonical_bytes)
}

/// Compute the canonical identifier for a serialized block header.
///
/// Mainnet height zero is identified by the tagged
/// [`MainnetGenesisIdentityV1`] envelope so its canonical identifier commits to
/// the inscription and empty economic body. Every other header, including the
/// frozen Testnet genesis and all ordinary blocks, retains the existing
/// untagged Blake2b-256 header identifier.
pub fn canonical_header_identifier(
    network_magic: u32,
    header_bytes: &[u8],
) -> Result<Hash256, DomError> {
    let header = BlockHeader::from_bytes(header_bytes)?;
    if network_magic == NETWORK_MAGIC_MAINNET && header.height == BlockHeight::GENESIS {
        return MainnetGenesisIdentityV1::new(
            header_bytes.to_vec(),
            GenesisInscriptionV1::mainnet(),
        )?
        .identity_hash();
    }
    match network_magic {
        NETWORK_MAGIC_MAINNET | NETWORK_MAGIC_TESTNET | NETWORK_MAGIC_REGTEST => {
            Ok(blake2b_256(header_bytes))
        }
        _ => Err(DomError::Invalid(format!(
            "unknown network magic for block identifier: 0x{network_magic:08x}"
        ))),
    }
}

fn construct_mainnet_identity() -> Result<CanonicalGenesis, DomError> {
    let anchor = genesis_anchor(NETWORK_MAGIC_MAINNET)?;
    let empty_root = blake2b_256_tagged(dom_core::TAG_PMMR_EMPTY, &[]);
    let header = canonical_header(
        NETWORK_MAGIC_MAINNET,
        anchor,
        empty_root,
        empty_root,
        empty_root,
    );
    let header_bytes = header
        .to_bytes()
        .map_err(|error| DomError::Internal(format!("genesis header serialization: {error}")))?;
    let identity =
        MainnetGenesisIdentityV1::new(header_bytes.clone(), GenesisInscriptionV1::mainnet())?;
    let block_bytes = identity.to_canonical_bytes()?;
    validate_mainnet_genesis_identity(&block_bytes)?;
    let hash = identity.identity_hash()?;
    Ok(CanonicalGenesis {
        block: None,
        header_bytes,
        block_bytes,
        hash,
    })
}

fn build_legacy_canonical_genesis(
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<CanonicalGenesis, DomError> {
    let anchor = genesis_anchor(network_magic)?;
    // Regtest's deterministic fixture predates its configured nonzero chain
    // identity. Bind it to the pinned pre-finalization signing context so
    // finalizing the configured Regtest hash cannot create a circular
    // hash -> chain ID -> signature -> hash dependency. Frozen Testnet keeps
    // its existing chain-ID-bound signature byte for byte.
    let genesis_signing_context = if network_magic == NETWORK_MAGIC_REGTEST {
        &REGTEST_GENESIS_SIGNING_CONTEXT
    } else {
        chain_id
    };
    let coinbase = build_genesis_coinbase(genesis_signing_context)?;
    let (output_root, kernel_root, rangeproof_root) = compute_block_pmmr_roots(&coinbase, &[])?;
    let header = canonical_header(
        network_magic,
        anchor,
        output_root,
        kernel_root,
        rangeproof_root,
    );
    let block = Block {
        header,
        coinbase,
        transactions: Vec::new(),
    };
    let header_bytes = block
        .header
        .to_bytes()
        .map_err(|error| DomError::Internal(format!("genesis header serialization: {error}")))?;
    let block_bytes = block
        .to_bytes()
        .map_err(|error| DomError::Internal(format!("genesis block serialization: {error}")))?;
    let hash = blake2b_256(&header_bytes);
    Ok(CanonicalGenesis {
        block: Some(block),
        header_bytes,
        block_bytes,
        hash,
    })
}

fn canonical_header(
    network_magic: u32,
    anchor: dom_pow::AsertAnchor,
    output_root: Hash256,
    kernel_root: Hash256,
    rangeproof_root: Hash256,
) -> BlockHeader {
    let (nonce, pow_digest) = match network_magic {
        NETWORK_MAGIC_MAINNET => (GENESIS_NONCE_MAINNET, GENESIS_POW_DIGEST_MAINNET),
        NETWORK_MAGIC_REGTEST => (GENESIS_NONCE_REGTEST, GENESIS_POW_DIGEST_REGTEST),
        _ => (0, [0u8; 32]),
    };
    BlockHeader {
        version: PROTOCOL_VERSION,
        prev_hash: Hash256::ZERO,
        height: BlockHeight::GENESIS,
        timestamp: anchor.timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(target_to_compact(&anchor.target)),
        total_difficulty: U256::from(target_to_difficulty(&anchor.target)),
        pow: ProofOfWork {
            nonce,
            randomx_hash: Hash256::from_bytes(pow_digest),
        },
    }
}

fn validate_mainnet_header(header_bytes: &[u8]) -> Result<(), DomError> {
    if header_bytes.len() != BLOCK_HEADER_BYTES {
        return Err(DomError::Malformed(format!(
            "Mainnet genesis header must be {BLOCK_HEADER_BYTES} bytes"
        )));
    }
    let header = BlockHeader::from_bytes(header_bytes)?;
    if header.height != BlockHeight::GENESIS || header.prev_hash != Hash256::ZERO {
        return Err(DomError::Invalid(
            "Mainnet genesis identity requires a height-zero header with zero previous hash".into(),
        ));
    }
    let empty_root = blake2b_256_tagged(dom_core::TAG_PMMR_EMPTY, &[]);
    if header.output_root != empty_root
        || header.kernel_root != empty_root
        || header.rangeproof_root != empty_root
    {
        return Err(DomError::Invalid(
            "Mainnet genesis identity requires empty output, kernel, and range-proof roots".into(),
        ));
    }
    Ok(())
}

fn validate_exact_mainnet_inscription(inscription: &GenesisInscriptionV1) -> Result<(), DomError> {
    if inscription.payload() != GENESIS_MESSAGE.as_bytes() {
        return Err(DomError::Invalid(
            "Mainnet genesis inscription does not match the configured consensus bytes".into(),
        ));
    }
    Ok(())
}

fn take<'a>(data: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], DomError> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| DomError::Malformed("Mainnet genesis identity length overflow".into()))?;
    if end > data.len() {
        return Err(DomError::Malformed(format!(
            "unexpected end of Mainnet genesis identity at byte {cursor}"
        )));
    }
    let value = &data[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_u16_be(data: &[u8], cursor: &mut usize) -> Result<usize, DomError> {
    let value = take(data, cursor, 2)?;
    Ok(usize::from(u16::from_be_bytes([value[0], value[1]])))
}

fn build_genesis_coinbase(chain_id: &[u8; 32]) -> Result<CoinbaseTransaction, DomError> {
    let blinding_hash = blake2b_256_tagged(TAG_GENESIS_BLINDING, b"");
    let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes())
        .map_err(|error| DomError::Internal(format!("genesis blinding: {error}")))?;
    let nonce = *blake2b_256_tagged(TAG_GENESIS_BLINDING, b"bulletproof-nonce").as_bytes();
    let explicit_value = dom_core::block_reward(BlockHeight::GENESIS).noms();
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, proof_commitment) =
        dom_crypto::range_proof_prove_bytes_with_nonce(explicit_value, &blinding, &nonce)
            .map_err(|error| DomError::Internal(format!("genesis range proof failed: {error}")))?;
    if proof_commitment != *commitment.as_bytes() {
        return Err(DomError::Internal(
            "genesis range proof commitment mismatch".into(),
        ));
    }
    let excess = Commitment::commit(0, &blinding);
    let mut message_data = Vec::with_capacity(9);
    message_data.push(KERNEL_FEAT_COINBASE);
    message_data.extend_from_slice(&explicit_value.to_le_bytes());
    let message = blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &message_data);
    let key = SecretKey::from_bytes(blinding.as_bytes())
        .map_err(|error| DomError::Internal(format!("genesis blinding as key: {error}")))?;
    let signature = schnorr_sign(&key, message.as_bytes(), chain_id)
        .map_err(|error| DomError::Internal(format!("genesis signing failed: {error}")))?;

    Ok(CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: signature.to_bytes(),
        },
        offset: [0u8; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_consensus::derive_chain_id;
    use dom_core::{
        block_reward, configured_genesis_hash_for_network_magic, BlockHeight, GENESIS_HASH_TESTNET,
        INITIAL_BLOCK_REWARD, MAX_SUPPLY_NOMS, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST,
        NETWORK_MAGIC_TESTNET,
    };

    const INSCRIPTION_HEX: &str =
        "4e6f7420612073746f7265206f662076616c75652e2041206d65616e73206f662065786368616e67652e";
    const ENCODING_HEX: &str =
        "01002a4e6f7420612073746f7265206f662076616c75652e2041206d65616e73206f662065786368616e67652e";
    const COMMITMENT_HEX: &str = "5cd1c38c517e4ed92697aa1ff4ebbabee026d0d0112f26c460eb379f1bcf8c28";

    fn configured_chain_id(network_magic: u32) -> [u8; 32] {
        let genesis_hash = configured_genesis_hash_for_network_magic(network_magic).unwrap();
        *derive_chain_id(network_magic, &genesis_hash).as_bytes()
    }

    fn mainnet_identity_bytes() -> Vec<u8> {
        build_canonical_genesis(NETWORK_MAGIC_MAINNET, &[0u8; 32])
            .unwrap()
            .block_bytes
    }

    #[test]
    fn exact_inscription_vector_is_frozen() {
        let inscription = GenesisInscriptionV1::mainnet();
        assert_eq!(inscription.payload().len(), 42);
        assert_eq!(hex::encode(inscription.payload()), INSCRIPTION_HEX);
        assert_eq!(
            hex::encode(inscription.to_canonical_bytes().unwrap()),
            ENCODING_HEX
        );
        assert_eq!(
            hex::encode(inscription.commitment().unwrap().as_bytes()),
            COMMITMENT_HEX
        );
        assert_eq!(inscription.text(), GENESIS_MESSAGE);
    }

    #[test]
    fn canonical_testnet_genesis_matches_frozen_identity() {
        let genesis = build_canonical_genesis(
            NETWORK_MAGIC_TESTNET,
            &configured_chain_id(NETWORK_MAGIC_TESTNET),
        )
        .unwrap();
        let block = genesis.block.as_ref().unwrap();
        assert_eq!(genesis.hash.as_bytes(), &GENESIS_HASH_TESTNET);
        assert_eq!(block.coinbase.output.proof.len(), 739);
        assert_eq!(
            hex::encode(block.header.output_root.as_bytes()),
            "7dcd67abf72846eadd94cee37060ecd58ac26df2a6c1f6e74a43fe9e6aab9f1d"
        );
        assert_eq!(
            hex::encode(block.header.kernel_root.as_bytes()),
            "69a1283a2fd4a90f0df6110caf2f74150365e31ca96cc2485cb022ceae15834b"
        );
        assert_eq!(
            hex::encode(block.header.rangeproof_root.as_bytes()),
            "ac00fb8ccb323f0cfdc2f4da553ad818e289cb2614400cb6d6af4b51d18a872c"
        );
        assert_eq!(block.to_bytes().unwrap(), genesis.block_bytes);
        assert_eq!(genesis.header_bytes.len(), 256);
        assert_eq!(genesis.block_bytes.len(), 1_175);
        assert_eq!(
            blake2b_256(&genesis.block_bytes).to_hex(),
            "42175918270462f833745d1f8cff6b63b4495ca2bf774dee4786314ee72f4a46"
        );
        assert_eq!(
            derive_chain_id(NETWORK_MAGIC_TESTNET, &genesis.hash).to_hex(),
            "de1168ce8fb42618c320390e9a5fada2e5fc6f69ea78a51b4a69b458653ff770"
        );
        assert!(genesis
            .inscription(NETWORK_MAGIC_TESTNET)
            .unwrap()
            .is_none());
    }

    #[test]
    fn canonical_header_identifier_matches_each_genesis_authority() {
        for magic in [
            NETWORK_MAGIC_MAINNET,
            NETWORK_MAGIC_TESTNET,
            NETWORK_MAGIC_REGTEST,
        ] {
            let genesis = build_canonical_genesis(magic, &configured_chain_id(magic)).unwrap();
            assert_eq!(
                canonical_header_identifier(magic, &genesis.header_bytes).unwrap(),
                genesis.hash
            );
        }
    }

    #[test]
    fn finalized_configured_identifiers_and_chain_ids_match_construction() {
        let expected_chain_ids = [
            (
                NETWORK_MAGIC_MAINNET,
                "f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b",
            ),
            (
                NETWORK_MAGIC_TESTNET,
                "de1168ce8fb42618c320390e9a5fada2e5fc6f69ea78a51b4a69b458653ff770",
            ),
            (
                NETWORK_MAGIC_REGTEST,
                "22384b4cbfaae306a7bdb23a822442f7e68fb51f65328697a754a9f3abd698e1",
            ),
        ];
        for (magic, expected_chain_id) in expected_chain_ids {
            let configured = configured_genesis_hash_for_network_magic(magic).unwrap();
            let chain_id = derive_chain_id(magic, &configured);
            let canonical = build_canonical_genesis(magic, chain_id.as_bytes()).unwrap();
            assert_eq!(canonical.hash, configured);
            assert_eq!(chain_id.to_hex(), expected_chain_id);
            assert_eq!(
                canonical_header_identifier(magic, &canonical.header_bytes).unwrap(),
                configured
            );
        }
    }

    #[test]
    fn finalized_pow_digests_match_targets_and_protocol_modes() {
        let mainnet = build_canonical_genesis(
            NETWORK_MAGIC_MAINNET,
            &configured_chain_id(NETWORK_MAGIC_MAINNET),
        )
        .unwrap();
        let mainnet_header = BlockHeader::from_bytes(&mainnet.header_bytes).unwrap();
        let mainnet_target = mainnet_header.target.to_target().unwrap();
        let mainnet_digest =
            dom_pow::randomx_pool::randomx_hash(&[0u8; 32], &mainnet_header.pow_preimage())
                .unwrap();
        assert_eq!(mainnet_digest, *mainnet_header.pow.randomx_hash.as_bytes());
        assert!(dom_pow::hash_meets_target(&mainnet_digest, &mainnet_target));
        assert_ne!(mainnet.hash.as_bytes(), &mainnet_digest);

        let regtest = build_canonical_genesis(
            NETWORK_MAGIC_REGTEST,
            &configured_chain_id(NETWORK_MAGIC_REGTEST),
        )
        .unwrap();
        let regtest_header = BlockHeader::from_bytes(&regtest.header_bytes).unwrap();
        let regtest_target = regtest_header.target.to_target().unwrap();
        let regtest_digest = dom_pow::fast_pow_hash(&[0u8; 32], &regtest_header.pow_preimage());
        assert_eq!(regtest_digest, *regtest_header.pow.randomx_hash.as_bytes());
        assert!(dom_pow::hash_meets_target(&regtest_digest, &regtest_target));
    }

    #[test]
    fn machine_readable_vectors_match_production_bytes() {
        for (magic, vector) in [
            (
                NETWORK_MAGIC_MAINNET,
                include_str!("../../../test-vectors/genesis/mainnet-v1.json"),
            ),
            (
                NETWORK_MAGIC_TESTNET,
                include_str!("../../../test-vectors/genesis/testnet-v1.json"),
            ),
            (
                NETWORK_MAGIC_REGTEST,
                include_str!("../../../test-vectors/genesis/regtest-v1.json"),
            ),
        ] {
            let canonical = build_canonical_genesis(magic, &configured_chain_id(magic)).unwrap();
            assert!(vector.contains(&hex::encode(&canonical.header_bytes)));
            assert!(vector.contains(&hex::encode(&canonical.block_bytes)));
            assert!(vector.contains(&canonical.hash.to_hex()));
            assert!(vector.contains(&derive_chain_id(magic, &canonical.hash).to_hex()));
        }
    }

    #[test]
    fn network_identity_mutations_cannot_preserve_genesis_identifiers() {
        for magic in [NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST] {
            let canonical = build_canonical_genesis(magic, &configured_chain_id(magic)).unwrap();
            let header = BlockHeader::from_bytes(&canonical.header_bytes).unwrap();
            let baseline = canonical.hash;
            for mutate in 0..10 {
                let mut changed = header.clone();
                match mutate {
                    0 => changed.timestamp.0 ^= 1,
                    1 => changed.pow.nonce ^= 1,
                    2 => changed.version ^= 1,
                    3 => changed.prev_hash = Hash256::from_bytes([1u8; 32]),
                    4 => changed.target.0 ^= 1,
                    5 => changed.total_difficulty += U256::one(),
                    6 => changed.output_root = Hash256::from_bytes([2u8; 32]),
                    7 => changed.kernel_root = Hash256::from_bytes([3u8; 32]),
                    8 => changed.rangeproof_root = Hash256::from_bytes([4u8; 32]),
                    _ => changed.pow.randomx_hash = Hash256::from_bytes([5u8; 32]),
                }
                let changed_bytes = changed.to_bytes().unwrap();
                let changed_identifier = if magic == NETWORK_MAGIC_MAINNET {
                    blake2b_256_tagged(
                        TAG_MAINNET_GENESIS_IDENTITY,
                        &MainnetGenesisIdentityV1::new(
                            changed_bytes,
                            GenesisInscriptionV1::mainnet(),
                        )
                        .map(|identity| identity.to_canonical_bytes().unwrap())
                        .unwrap_or_default(),
                    )
                } else {
                    blake2b_256(&changed_bytes)
                };
                assert_ne!(changed_identifier, baseline);
            }
        }
    }

    #[test]
    fn regtest_genesis_has_no_chain_id_hash_cycle() {
        let first = build_canonical_genesis(NETWORK_MAGIC_REGTEST, &[0u8; 32]).unwrap();
        let pre_finalization = derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::ZERO);
        assert_eq!(
            pre_finalization.as_bytes(),
            &REGTEST_GENESIS_SIGNING_CONTEXT
        );
        let derived = derive_chain_id(NETWORK_MAGIC_REGTEST, &first.hash);
        let second = build_canonical_genesis(NETWORK_MAGIC_REGTEST, derived.as_bytes()).unwrap();
        assert_eq!(second.header_bytes, first.header_bytes);
        assert_eq!(second.block_bytes, first.block_bytes);
        assert_eq!(second.hash, first.hash);
    }

    #[test]
    fn mainnet_identity_is_inscribed_and_economically_empty() {
        let genesis = build_canonical_genesis(NETWORK_MAGIC_MAINNET, &[0u8; 32]).unwrap();
        assert!(genesis.block.is_none());
        assert_eq!(genesis.block_bytes.len(), 357);
        let identity = validate_mainnet_genesis_identity(&genesis.block_bytes).unwrap();
        assert_eq!(identity.body_bytes(), &[0u8; 16]);
        assert_eq!(
            u32::from_be_bytes(identity.body_bytes()[0..4].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_be_bytes(identity.body_bytes()[4..8].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_be_bytes(identity.body_bytes()[8..12].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_be_bytes(identity.body_bytes()[12..16].try_into().unwrap()),
            0
        );
        assert_eq!(
            block_reward(BlockHeight::GENESIS).noms(),
            INITIAL_BLOCK_REWARD
        );
        assert_eq!(block_reward(BlockHeight(1)).noms(), INITIAL_BLOCK_REWARD);
        assert_eq!(MAX_SUPPLY_NOMS, 3_299_996_676_900_000);
        assert_eq!(identity.inscription().text(), GENESIS_MESSAGE);
        assert_eq!(
            genesis
                .inscription(NETWORK_MAGIC_MAINNET)
                .unwrap()
                .unwrap()
                .text(),
            GENESIS_MESSAGE
        );
    }

    #[test]
    fn mainnet_validation_rejects_inscription_mutations() {
        let canonical = mainnet_identity_bytes();
        let identity = validate_mainnet_genesis_identity(&canonical).unwrap();
        let phrase_offset = canonical
            .windows(GENESIS_MESSAGE.len())
            .position(|window| window == GENESIS_MESSAGE.as_bytes())
            .unwrap();

        for replacement in *b"nV! " {
            let mut changed = canonical.clone();
            changed[phrase_offset] = replacement;
            assert!(validate_mainnet_genesis_identity(&changed).is_err());
        }

        let mut lookalike = identity.inscription().payload().to_vec();
        lookalike.splice(0..1, "Ν".as_bytes().iter().copied());
        assert!(MainnetGenesisIdentityV1::new(
            identity.header_bytes().to_vec(),
            GenesisInscriptionV1::new(&lookalike).unwrap(),
        )
        .is_err());

        for suffix in [b"\n".as_slice(), b" ".as_slice(), b"\0".as_slice()] {
            let mut changed = identity.inscription().payload().to_vec();
            changed.extend_from_slice(suffix);
            assert!(MainnetGenesisIdentityV1::new(
                identity.header_bytes().to_vec(),
                GenesisInscriptionV1::new(&changed).unwrap(),
            )
            .is_err());
        }
    }

    #[test]
    fn malformed_inscription_and_envelope_encodings_are_rejected() {
        assert!(GenesisInscriptionV1::from_canonical_bytes(&[2, 0, 0]).is_err());
        assert!(GenesisInscriptionV1::from_canonical_bytes(&[1, 0, 2, 0xff, 0xff]).is_err());
        assert!(GenesisInscriptionV1::from_canonical_bytes(&[1, 0, 1]).is_err());
        assert!(GenesisInscriptionV1::new(&vec![b'a'; 257]).is_err());

        let canonical = mainnet_identity_bytes();
        let phrase_offset = canonical
            .windows(GENESIS_MESSAGE.len())
            .position(|window| window == GENESIS_MESSAGE.as_bytes())
            .unwrap();
        let count_offset = phrase_offset - 3 - 3;

        let mut duplicate = canonical.clone();
        duplicate[count_offset] = 2;
        assert!(validate_mainnet_genesis_identity(&duplicate).is_err());

        let mut invalid_version = canonical.clone();
        invalid_version[0] = 2;
        assert!(validate_mainnet_genesis_identity(&invalid_version).is_err());

        let mut invalid_length = canonical.clone();
        invalid_length[phrase_offset - 1] ^= 1;
        assert!(validate_mainnet_genesis_identity(&invalid_length).is_err());

        let mut invalid_commitment = canonical.clone();
        *invalid_commitment.last_mut().unwrap() ^= 1;
        assert!(validate_mainnet_genesis_identity(&invalid_commitment).is_err());

        let mut trailing = canonical;
        trailing.push(0);
        assert!(validate_mainnet_genesis_identity(&trailing).is_err());
    }

    #[test]
    fn inscription_and_mainnet_identity_hash_have_bit_sensitivity() {
        use dom_consensus::derive_chain_id;

        let inscription = GenesisInscriptionV1::mainnet();
        let original_commitment = inscription.commitment().unwrap();
        let mut changed_payload = inscription.payload().to_vec();
        changed_payload[0] ^= 1;
        let changed = GenesisInscriptionV1::new(&changed_payload).unwrap();
        assert_ne!(original_commitment, changed.commitment().unwrap());

        let identity = validate_mainnet_genesis_identity(&mainnet_identity_bytes()).unwrap();
        let original_hash = identity.identity_hash().unwrap();
        let changed_identity = MainnetGenesisIdentityV1 {
            header_bytes: identity.header_bytes().to_vec(),
            inscription: changed,
        };
        let changed_hash = changed_identity.identity_hash().unwrap();
        assert_ne!(original_hash, changed_hash);
        assert_ne!(
            derive_chain_id(NETWORK_MAGIC_MAINNET, &original_hash),
            derive_chain_id(NETWORK_MAGIC_MAINNET, &changed_hash)
        );
    }

    #[test]
    fn independent_encoding_verifier_repeats_one_hundred_times() {
        let vector = include_str!("../../../test-vectors/genesis/mainnet-inscription-v1.json");
        for _ in 0..100 {
            let payload = GENESIS_MESSAGE.as_bytes();
            let mut independent = Vec::with_capacity(3 + payload.len());
            independent.push(1);
            independent.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            independent.extend_from_slice(payload);
            assert_eq!(hex::encode(&independent), ENCODING_HEX);
            assert_eq!(
                hex::encode(blake2b_256_tagged(TAG_GENESIS_INSCRIPTION, &independent).as_bytes()),
                COMMITMENT_HEX
            );
            assert_eq!(
                GenesisInscriptionV1::from_canonical_bytes(&independent)
                    .unwrap()
                    .text(),
                GENESIS_MESSAGE
            );
            assert!(vector.contains(ENCODING_HEX));
            assert!(vector.contains(COMMITMENT_HEX));
            assert!(vector.contains(INSCRIPTION_HEX));
            assert!(vector.contains(GENESIS_MESSAGE));
        }
    }

    #[test]
    fn canonical_genesis_is_deterministic_for_every_configured_network() {
        for magic in [
            NETWORK_MAGIC_MAINNET,
            NETWORK_MAGIC_TESTNET,
            NETWORK_MAGIC_REGTEST,
        ] {
            let chain_id = configured_chain_id(magic);
            let expected = build_canonical_genesis(magic, &chain_id).unwrap();
            for _ in 0..10 {
                let actual = build_canonical_genesis(magic, &chain_id).unwrap();
                assert_eq!(actual.header_bytes, expected.header_bytes);
                assert_eq!(actual.block_bytes, expected.block_bytes);
                assert_eq!(actual.hash, expected.hash);
            }
        }
    }

    #[test]
    fn testnet_and_regtest_do_not_inherit_mainnet_inscription() {
        for magic in [NETWORK_MAGIC_TESTNET, NETWORK_MAGIC_REGTEST] {
            let genesis = build_canonical_genesis(magic, &configured_chain_id(magic)).unwrap();
            assert!(genesis.inscription(magic).unwrap().is_none());
            assert!(!genesis
                .block_bytes
                .windows(GENESIS_MESSAGE.len())
                .any(|window| window == GENESIS_MESSAGE.as_bytes()));
        }
    }

    #[test]
    fn unknown_network_has_no_genesis_authority() {
        let error = build_canonical_genesis(0, &[0u8; 32]).unwrap_err();
        assert!(error.to_string().contains("unknown network magic"));
    }
}

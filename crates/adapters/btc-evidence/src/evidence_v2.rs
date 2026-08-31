//! Canonical, bounded Bitcoin evidence V2 container.
//!
//! V2 is intentionally a new wire format. It requires the complete consensus
//! block and binds the claimed confirmation policy and external checkpoint by
//! digest. Those digests are not self-authenticating: the verifier additionally
//! requires an opaque header-authority result before producing an operational
//! outcome.

const V2_FIXED_BYTES: usize = 300;

/// Hard transaction-count bound shared by V2 decoding and full-block checks.
pub(crate) const MAX_TRANSACTIONS_V2: u32 = 100_000;

/// Canonical decoding and construction errors for Bitcoin evidence V2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceCodecErrorV2 {
    /// The complete encoded container or an announced variable field is too
    /// large for the V2 policy.
    #[error("V2 evidence exceeds a hard bound")]
    BoundsExceeded,
    /// The V2 magic prefix does not match.
    #[error("invalid V2 evidence magic")]
    InvalidMagic,
    /// The codec version is not exactly V2.
    #[error("unsupported V2 evidence codec version")]
    UnsupportedCodecVersion,
    /// A network or outcome discriminant is not defined by V2.
    #[error("unknown V2 evidence discriminant")]
    UnknownDiscriminant,
    /// The byte stream ends before a declared field is complete.
    #[error("truncated V2 evidence")]
    Truncated,
    /// Bytes remain after the one canonical V2 container.
    #[error("trailing bytes after V2 evidence")]
    TrailingBytes,
    /// A required route, transaction, policy, checkpoint, or depth field is
    /// structurally invalid.
    #[error("invalid V2 evidence field")]
    InvalidField,
}

/// Bitcoin network provenance carried only by evidence V2.
///
/// This deliberately does not reuse the V1 discriminant type: an authenticated
/// V2 policy must never be confused with a legacy structural proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinEvidenceNetworkV2 {
    /// Deterministic local network.
    Regtest,
    /// Persistent operator-controlled Signet.
    CustomSignet,
    /// Bitcoin Core public Signet.
    PublicSignet,
}

/// A contractual outpoint carrying explicit V2 provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinOutPointV2 {
    txid: [u8; 32],
    vout: u32,
}

impl BitcoinOutPointV2 {
    /// Creates a non-zero V2 outpoint.
    pub fn new(txid: [u8; 32], vout: u32) -> Result<Self, EvidenceCodecErrorV2> {
        if txid == [0; 32] {
            return Err(EvidenceCodecErrorV2::InvalidField);
        }
        Ok(Self { txid, vout })
    }

    /// Transaction id in Bitcoin's internal byte order.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Output index.
    #[must_use]
    pub const fn vout(&self) -> u32 {
        self.vout
    }
}

/// Terminal Bitcoin outcome carrying explicit V2 provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinOutcomeV2 {
    /// Cooperative key-path MuSig2/adaptor claim.
    KeyPathClaim,
    /// Unilateral CSV script-path refund.
    CsvScriptPathRefund,
}

/// Route facts bound into a Bitcoin evidence V2 container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinEvidenceRouteBindingV2 {
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
}

impl BitcoinEvidenceRouteBindingV2 {
    /// Creates a non-zero route binding.
    pub fn new(
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
    ) -> Result<Self, EvidenceCodecErrorV2> {
        if settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err(EvidenceCodecErrorV2::InvalidField);
        }
        Ok(Self {
            settlement_id,
            terms_hash,
        })
    }

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
}

/// Header-policy and checkpoint facts that must later match an external,
/// authenticated header authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinHeaderPolicyBindingV2 {
    network: BitcoinEvidenceNetworkV2,
    network_genesis_hash: [u8; 32],
    block_height: u64,
    policy_digest: [u8; 32],
    checkpoint_digest: [u8; 32],
    minimum_confirmation_depth: u32,
}

impl BitcoinHeaderPolicyBindingV2 {
    /// Creates explicit V2 chain-policy facts.
    pub fn new(
        network: BitcoinEvidenceNetworkV2,
        network_genesis_hash: [u8; 32],
        block_height: u64,
        policy_digest: [u8; 32],
        checkpoint_digest: [u8; 32],
        minimum_confirmation_depth: u32,
    ) -> Result<Self, EvidenceCodecErrorV2> {
        let maximum_depth = KeystoneBitcoinEvidenceV2::MAX_CONFIRMATION_HEADERS
            .checked_add(1)
            .ok_or(EvidenceCodecErrorV2::BoundsExceeded)?;
        if network_genesis_hash == [0; 32]
            || policy_digest == [0; 32]
            || checkpoint_digest == [0; 32]
            || minimum_confirmation_depth == 0
            || minimum_confirmation_depth > maximum_depth
        {
            return Err(EvidenceCodecErrorV2::InvalidField);
        }
        Ok(Self {
            network,
            network_genesis_hash,
            block_height,
            policy_digest,
            checkpoint_digest,
            minimum_confirmation_depth,
        })
    }

    /// Claimed Bitcoin network family.
    #[must_use]
    pub const fn network(&self) -> BitcoinEvidenceNetworkV2 {
        self.network
    }

    /// Exact network genesis hash in internal byte order.
    #[must_use]
    pub const fn network_genesis_hash(&self) -> [u8; 32] {
        self.network_genesis_hash
    }

    /// Height of the complete containing block.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Digest of the externally authenticated header policy.
    #[must_use]
    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// Digest of the externally authenticated checkpoint.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> [u8; 32] {
        self.checkpoint_digest
    }

    /// Required depth, including the containing block as depth one.
    #[must_use]
    pub const fn minimum_confirmation_depth(&self) -> u32 {
        self.minimum_confirmation_depth
    }
}

/// Exact transaction claim within the mandatory complete block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinTransactionClaimV2 {
    txid: [u8; 32],
    wtxid: [u8; 32],
    expected_outpoint: BitcoinOutPointV2,
    total_transactions: u32,
    transaction_position: u32,
    outcome: BitcoinOutcomeV2,
}

impl BitcoinTransactionClaimV2 {
    /// Creates an exact, non-zero transaction claim.
    pub fn new(
        txid: [u8; 32],
        wtxid: [u8; 32],
        expected_outpoint: BitcoinOutPointV2,
        total_transactions: u32,
        transaction_position: u32,
        outcome: BitcoinOutcomeV2,
    ) -> Result<Self, EvidenceCodecErrorV2> {
        if txid == [0; 32]
            || wtxid == [0; 32]
            || total_transactions == 0
            || total_transactions > MAX_TRANSACTIONS_V2
            || transaction_position >= total_transactions
        {
            return Err(EvidenceCodecErrorV2::InvalidField);
        }
        Ok(Self {
            txid,
            wtxid,
            expected_outpoint,
            total_transactions,
            transaction_position,
            outcome,
        })
    }

    /// Expected transaction id in internal byte order.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Expected witness transaction id in internal byte order.
    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }

    /// Contractual outpoint that the transaction must spend.
    #[must_use]
    pub const fn expected_outpoint(&self) -> BitcoinOutPointV2 {
        self.expected_outpoint
    }

    /// Exact number of transactions claimed for the complete block.
    #[must_use]
    pub const fn total_transactions(&self) -> u32 {
        self.total_transactions
    }

    /// Zero-based position in the complete block transaction vector.
    #[must_use]
    pub const fn transaction_position(&self) -> u32 {
        self.transaction_position
    }

    /// Claimed terminal witness path.
    #[must_use]
    pub const fn outcome(&self) -> BitcoinOutcomeV2 {
        self.outcome
    }
}

/// Canonical V2 Bitcoin evidence.
///
/// The full block is mandatory. The type is still untrusted input and cannot
/// itself authenticate headers, difficulty, chain work, Signet, or the external
/// checkpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct KeystoneBitcoinEvidenceV2 {
    route: BitcoinEvidenceRouteBindingV2,
    header_policy: BitcoinHeaderPolicyBindingV2,
    transaction: BitcoinTransactionClaimV2,
    full_block: Vec<u8>,
    confirmation_headers: Vec<[u8; 80]>,
}

impl KeystoneBitcoinEvidenceV2 {
    /// Distinct V2 wire magic. A V2 decoder never falls back to V1.
    pub const MAGIC: [u8; 8] = *b"DBTCEVV2";
    /// Exact codec version carried after [`Self::MAGIC`].
    pub const CODEC_VERSION: u16 = 2;
    /// Maximum complete consensus block bytes accepted before deserialization.
    pub const MAX_FULL_BLOCK_BYTES: u32 = 4_000_000;
    /// Maximum successor headers retained by one V2 evidence object.
    pub const MAX_CONFIRMATION_HEADERS: u32 = 4_096;
    /// Maximum transaction count accepted from the complete block.
    pub const MAX_TRANSACTIONS: u32 = MAX_TRANSACTIONS_V2;
    /// Maximum complete V2 container bytes accepted before any allocation.
    pub const MAX_ENCODED_BYTES: usize = 4_400_000;

    /// Creates a bounded, still-untrusted V2 container.
    pub fn new(
        route: BitcoinEvidenceRouteBindingV2,
        header_policy: BitcoinHeaderPolicyBindingV2,
        transaction: BitcoinTransactionClaimV2,
        full_block: Vec<u8>,
        confirmation_headers: Vec<[u8; 80]>,
    ) -> Result<Self, EvidenceCodecErrorV2> {
        let evidence = Self {
            route,
            header_policy,
            transaction,
            full_block,
            confirmation_headers,
        };
        evidence.validate_bounds()?;
        Ok(evidence)
    }

    /// Decodes exactly one canonical V2 container.
    ///
    /// The total input, full-block length and confirmation count are checked
    /// before allocating their corresponding vectors.
    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceCodecErrorV2> {
        if bytes.len() > Self::MAX_ENCODED_BYTES {
            return Err(EvidenceCodecErrorV2::BoundsExceeded);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take_array::<8>()? != Self::MAGIC {
            return Err(EvidenceCodecErrorV2::InvalidMagic);
        }
        if cursor.take_u16()? != Self::CODEC_VERSION {
            return Err(EvidenceCodecErrorV2::UnsupportedCodecVersion);
        }

        let network = decode_network(cursor.take_u8()?)?;
        let network_genesis_hash = cursor.take_array()?;
        let settlement_id = cursor.take_array()?;
        let terms_hash = cursor.take_array()?;
        let expected_outpoint = BitcoinOutPointV2::new(cursor.take_array()?, cursor.take_u32()?)?;
        let txid = cursor.take_array()?;
        let wtxid = cursor.take_array()?;
        let block_height = cursor.take_u64()?;
        let total_transactions = cursor.take_u32()?;
        let transaction_position = cursor.take_u32()?;
        let outcome = decode_outcome(cursor.take_u8()?)?;
        let policy_digest = cursor.take_array()?;
        let checkpoint_digest = cursor.take_array()?;
        let minimum_confirmation_depth = cursor.take_u32()?;
        let full_block = cursor.take_vec_bounded(Self::MAX_FULL_BLOCK_BYTES as usize)?;
        let confirmation_headers =
            cursor.take_headers_bounded(Self::MAX_CONFIRMATION_HEADERS as usize)?;
        if !cursor.is_finished() {
            return Err(EvidenceCodecErrorV2::TrailingBytes);
        }

        Self::new(
            BitcoinEvidenceRouteBindingV2::new(settlement_id, terms_hash)?,
            BitcoinHeaderPolicyBindingV2::new(
                network,
                network_genesis_hash,
                block_height,
                policy_digest,
                checkpoint_digest,
                minimum_confirmation_depth,
            )?,
            BitcoinTransactionClaimV2::new(
                txid,
                wtxid,
                expected_outpoint,
                total_transactions,
                transaction_position,
                outcome,
            )?,
            full_block,
            confirmation_headers,
        )
    }

    /// Encodes the one canonical V2 representation.
    pub fn encode(&self) -> Result<Vec<u8>, EvidenceCodecErrorV2> {
        self.validate_bounds()?;
        let header_bytes = self
            .confirmation_headers
            .len()
            .checked_mul(80)
            .ok_or(EvidenceCodecErrorV2::BoundsExceeded)?;
        let capacity = V2_FIXED_BYTES
            .checked_add(self.full_block.len())
            .and_then(|value| value.checked_add(header_bytes))
            .ok_or(EvidenceCodecErrorV2::BoundsExceeded)?;
        if capacity > Self::MAX_ENCODED_BYTES {
            return Err(EvidenceCodecErrorV2::BoundsExceeded);
        }

        let mut output = Vec::with_capacity(capacity);
        output.extend_from_slice(&Self::MAGIC);
        output.extend_from_slice(&Self::CODEC_VERSION.to_be_bytes());
        output.push(encode_network(self.header_policy.network));
        output.extend_from_slice(&self.header_policy.network_genesis_hash);
        output.extend_from_slice(&self.route.settlement_id);
        output.extend_from_slice(&self.route.terms_hash);
        output.extend_from_slice(&self.transaction.expected_outpoint.txid);
        output.extend_from_slice(&self.transaction.expected_outpoint.vout.to_be_bytes());
        output.extend_from_slice(&self.transaction.txid);
        output.extend_from_slice(&self.transaction.wtxid);
        output.extend_from_slice(&self.header_policy.block_height.to_be_bytes());
        output.extend_from_slice(&self.transaction.total_transactions.to_be_bytes());
        output.extend_from_slice(&self.transaction.transaction_position.to_be_bytes());
        output.push(encode_outcome(self.transaction.outcome));
        output.extend_from_slice(&self.header_policy.policy_digest);
        output.extend_from_slice(&self.header_policy.checkpoint_digest);
        output.extend_from_slice(&self.header_policy.minimum_confirmation_depth.to_be_bytes());
        put_bytes(&mut output, &self.full_block)?;
        let header_count = u32::try_from(self.confirmation_headers.len())
            .map_err(|_| EvidenceCodecErrorV2::BoundsExceeded)?;
        output.extend_from_slice(&header_count.to_be_bytes());
        for header in &self.confirmation_headers {
            output.extend_from_slice(header);
        }
        if output.len() != capacity || output.len() > Self::MAX_ENCODED_BYTES {
            return Err(EvidenceCodecErrorV2::BoundsExceeded);
        }
        Ok(output)
    }

    /// Frozen route facts.
    #[must_use]
    pub const fn route(&self) -> &BitcoinEvidenceRouteBindingV2 {
        &self.route
    }

    /// Explicit external policy/checkpoint binding.
    #[must_use]
    pub const fn header_policy(&self) -> &BitcoinHeaderPolicyBindingV2 {
        &self.header_policy
    }

    /// Exact transaction claim.
    #[must_use]
    pub const fn transaction(&self) -> &BitcoinTransactionClaimV2 {
        &self.transaction
    }

    /// Mandatory complete consensus block bytes.
    #[must_use]
    pub fn full_block_bytes(&self) -> &[u8] {
        &self.full_block
    }

    /// Canonical successor headers after the containing block.
    #[must_use]
    pub fn confirmation_headers(&self) -> &[[u8; 80]] {
        &self.confirmation_headers
    }

    /// Confirmation depth including the containing block.
    #[must_use]
    pub fn confirmation_depth(&self) -> u32 {
        u32::try_from(self.confirmation_headers.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .unwrap_or(u32::MAX)
    }

    fn validate_bounds(&self) -> Result<(), EvidenceCodecErrorV2> {
        if self.full_block.is_empty()
            || self.full_block.len() > Self::MAX_FULL_BLOCK_BYTES as usize
            || self.confirmation_headers.len() > Self::MAX_CONFIRMATION_HEADERS as usize
            || self.confirmation_depth() < self.header_policy.minimum_confirmation_depth
        {
            return Err(EvidenceCodecErrorV2::BoundsExceeded);
        }
        let header_bytes = self
            .confirmation_headers
            .len()
            .checked_mul(80)
            .ok_or(EvidenceCodecErrorV2::BoundsExceeded)?;
        let encoded_len = V2_FIXED_BYTES
            .checked_add(self.full_block.len())
            .and_then(|value| value.checked_add(header_bytes))
            .ok_or(EvidenceCodecErrorV2::BoundsExceeded)?;
        if encoded_len > Self::MAX_ENCODED_BYTES {
            return Err(EvidenceCodecErrorV2::BoundsExceeded);
        }
        Ok(())
    }
}

fn encode_network(network: BitcoinEvidenceNetworkV2) -> u8 {
    match network {
        BitcoinEvidenceNetworkV2::Regtest => 0,
        BitcoinEvidenceNetworkV2::CustomSignet => 1,
        BitcoinEvidenceNetworkV2::PublicSignet => 2,
    }
}

fn decode_network(value: u8) -> Result<BitcoinEvidenceNetworkV2, EvidenceCodecErrorV2> {
    match value {
        0 => Ok(BitcoinEvidenceNetworkV2::Regtest),
        1 => Ok(BitcoinEvidenceNetworkV2::CustomSignet),
        2 => Ok(BitcoinEvidenceNetworkV2::PublicSignet),
        _ => Err(EvidenceCodecErrorV2::UnknownDiscriminant),
    }
}

fn encode_outcome(outcome: BitcoinOutcomeV2) -> u8 {
    match outcome {
        BitcoinOutcomeV2::KeyPathClaim => 0,
        BitcoinOutcomeV2::CsvScriptPathRefund => 1,
    }
}

fn decode_outcome(value: u8) -> Result<BitcoinOutcomeV2, EvidenceCodecErrorV2> {
    match value {
        0 => Ok(BitcoinOutcomeV2::KeyPathClaim),
        1 => Ok(BitcoinOutcomeV2::CsvScriptPathRefund),
        _ => Err(EvidenceCodecErrorV2::UnknownDiscriminant),
    }
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), EvidenceCodecErrorV2> {
    let length = u32::try_from(bytes.len()).map_err(|_| EvidenceCodecErrorV2::BoundsExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], EvidenceCodecErrorV2> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(EvidenceCodecErrorV2::BoundsExceeded)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(EvidenceCodecErrorV2::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], EvidenceCodecErrorV2> {
        self.take(N)?
            .try_into()
            .map_err(|_| EvidenceCodecErrorV2::Truncated)
    }

    fn take_u8(&mut self) -> Result<u8, EvidenceCodecErrorV2> {
        Ok(self.take_array::<1>()?[0])
    }

    fn take_u16(&mut self) -> Result<u16, EvidenceCodecErrorV2> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, EvidenceCodecErrorV2> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, EvidenceCodecErrorV2> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_vec_bounded(&mut self, maximum: usize) -> Result<Vec<u8>, EvidenceCodecErrorV2> {
        let length =
            usize::try_from(self.take_u32()?).map_err(|_| EvidenceCodecErrorV2::BoundsExceeded)?;
        if length > maximum {
            return Err(EvidenceCodecErrorV2::BoundsExceeded);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn take_headers_bounded(
        &mut self,
        maximum: usize,
    ) -> Result<Vec<[u8; 80]>, EvidenceCodecErrorV2> {
        let count =
            usize::try_from(self.take_u32()?).map_err(|_| EvidenceCodecErrorV2::BoundsExceeded)?;
        if count > maximum {
            return Err(EvidenceCodecErrorV2::BoundsExceeded);
        }
        let bytes_needed = count
            .checked_mul(80)
            .ok_or(EvidenceCodecErrorV2::BoundsExceeded)?;
        let raw = self.take(bytes_needed)?;
        let mut headers = Vec::with_capacity(count);
        for chunk in raw.chunks_exact(80) {
            headers.push(
                chunk
                    .try_into()
                    .map_err(|_| EvidenceCodecErrorV2::Truncated)?,
            );
        }
        Ok(headers)
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

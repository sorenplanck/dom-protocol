//! Fail-closed HTTP adapter for a real DOM node.
//!
//! This crate consumes the authenticated, full-fidelity F7 scanner exposed by
//! DOM Protocol at `GET /chain/scan/scriptless/v1`.  It validates the frozen
//! network identity, every page anchor, header linkage, canonical transaction
//! bytes, transaction hashes and every transaction projection before returning
//! an observation to the wallet.  Transaction submission uses the existing
//! DOM `POST /tx/submit` admission path.
//!
//! The adapter is deliberately not a consensus implementation.  Canonical
//! decoding and hashing are delegated to the pinned DOM crates, while mempool
//! and consensus admission remain exclusively inside the real node.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::io::Read;
use std::time::Duration;

use dom_consensus::{BlockHeader, Transaction};
use dom_crypto::blake2b_256;
use dom_serialization::{DomDeserialize, DomSerialize};
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Full-fidelity scanner schema accepted by this adapter.
pub const SCRIPTLESS_SCAN_SCHEMA_V1: u16 = 1;
/// Node-side maximum number of blocks in one page.
pub const MAX_SCRIPTLESS_SCAN_BLOCKS_V1: u64 = 64;
/// Maximum HTTP response accepted before JSON allocation.
pub const MAX_SCRIPTLESS_RESPONSE_BYTES_V1: u64 = 64 * 1024 * 1024;
/// Maximum canonical transaction size accepted from the scanner.
pub const MAX_CANONICAL_TRANSACTION_BYTES_V1: usize = 16 * 1024 * 1024;

/// Validates exact canonical DOM transaction bytes and returns their real
/// transaction identifier (`BLAKE2b-256(canonical_bytes)`).
///
/// This is the single local authority used both before submission and when
/// binding durable outbox artifacts; callers never hash an invented DTO.
pub fn canonical_transaction_hash_v1(
    canonical_bytes: &[u8],
) -> Result<[u8; 32], ChainAdapterError> {
    if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_CANONICAL_TRANSACTION_BYTES_V1 {
        return Err(ChainAdapterError::BoundsExceeded);
    }
    let transaction = Transaction::from_bytes(canonical_bytes)
        .map_err(|_| ChainAdapterError::InvalidTransaction)?;
    let reencoded = transaction
        .to_bytes()
        .map_err(|_| ChainAdapterError::InvalidTransaction)?;
    if reencoded != canonical_bytes {
        return Err(ChainAdapterError::InvalidTransaction);
    }
    Ok(*blake2b_256(canonical_bytes).as_bytes())
}

/// Stable failures returned by the real DOM boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainAdapterError {
    /// Endpoint, identity, timeout or bound configuration is invalid.
    #[error("invalid DOM adapter configuration")]
    InvalidConfiguration,
    /// The node did not authenticate the request.
    #[error("DOM RPC authentication failed")]
    AuthenticationFailed,
    /// The required real-node API is not available.
    #[error("required DOM RPC capability is unavailable")]
    CapabilityUnavailable,
    /// The node is temporarily unavailable or overloaded.
    #[error("DOM RPC is temporarily unavailable")]
    TemporarilyUnavailable,
    /// The request or response exceeded a fixed bound.
    #[error("DOM RPC bound exceeded")]
    BoundsExceeded,
    /// The HTTP response was not the closed versioned schema.
    #[error("malformed DOM RPC response")]
    MalformedResponse,
    /// The response does not belong to the frozen network/version identity.
    #[error("DOM network or version identity mismatch")]
    IdentityMismatch,
    /// A saved anchor is no longer canonical.
    #[error("DOM reorganization invalidated the scan cursor")]
    ReorgDetected,
    /// Canonical block linkage or transaction evidence is inconsistent.
    #[error("invalid canonical DOM chain evidence")]
    InvalidEvidence,
    /// The real node rejected the submitted transaction.
    #[error("DOM node rejected the transaction")]
    TransactionRejected,
    /// Local canonical DOM decoding rejected the transaction.
    #[error("invalid canonical DOM transaction")]
    InvalidTransaction,
    /// An unexpected HTTP status was returned.
    #[error("unexpected DOM RPC status {0}")]
    HttpStatus(u16),
}

/// Frozen DOM identity required for every scanner page.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExpectedDomIdentityV1 {
    /// Exact lowercase network label, normally `regtest` in F7.
    pub network: String,
    /// Consensus network magic.
    pub network_magic: u32,
    /// Consensus chain identifier.
    pub chain_id: [u8; 32],
    /// Canonical genesis identifier.
    pub genesis_hash: [u8; 32],
    /// Exact protocol version.
    pub protocol_version: u32,
    /// Exact output proof serialization version.
    pub range_proof_serialization_version: u8,
}

impl ExpectedDomIdentityV1 {
    /// Validates one startup-safe canonical network identity.
    ///
    /// The label selects exactly one magic and one compiled genesis. Mainnet
    /// additionally passes `dom-core`'s explicit finalized-genesis readiness
    /// gate. The derived chain id and both wire-version pins are then checked
    /// against that exact startup-safe genesis; a configured arbitrary genesis
    /// is never accepted, including on testnet and regtest.
    pub fn validate(&self) -> Result<(), ChainAdapterError> {
        let expected_magic = match self.network.as_str() {
            "regtest" => dom_core::NETWORK_MAGIC_REGTEST,
            "testnet" => dom_core::NETWORK_MAGIC_TESTNET,
            "mainnet" => dom_core::NETWORK_MAGIC_MAINNET,
            _ => return Err(ChainAdapterError::InvalidConfiguration),
        };
        let startup_genesis = dom_core::startup_genesis_hash_for_network_magic(expected_magic)
            .map_err(|_| ChainAdapterError::InvalidConfiguration)?;
        if self.network_magic != expected_magic
            || self.chain_id == [0_u8; 32]
            || self.genesis_hash == [0_u8; 32]
            || startup_genesis.as_bytes() != &self.genesis_hash
            || self.protocol_version != dom_core::PROTOCOL_VERSION
            || self.range_proof_serialization_version
                != dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION
            || dom_consensus::derive_chain_id(self.network_magic, &startup_genesis).as_bytes()
                != &self.chain_id
        {
            return Err(ChainAdapterError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Restart-safe cursor for the authenticated scanner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ScriptlessScanCursorV1 {
    /// First height not yet processed.
    pub next_height: u64,
    /// Canonical block immediately before `next_height`; absent only at zero.
    pub anchor_hash: Option<[u8; 32]>,
}

impl ScriptlessScanCursorV1 {
    /// Creates the unique genesis cursor.
    pub const fn genesis() -> Self {
        Self {
            next_height: 0,
            anchor_hash: None,
        }
    }

    fn validate(&self) -> Result<(), ChainAdapterError> {
        match (self.next_height, self.anchor_hash) {
            (0, None) | (1.., Some(_)) => Ok(()),
            _ => Err(ChainAdapterError::InvalidConfiguration),
        }
    }
}

/// Frozen identity and tip returned atomically with a scanner page.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ObservedDomIdentityV1 {
    /// Network label.
    pub network: String,
    /// Consensus network magic.
    pub network_magic: u32,
    /// Consensus chain identifier.
    pub chain_id: [u8; 32],
    /// Canonical genesis identifier.
    pub genesis_hash: [u8; 32],
    /// Protocol version.
    pub protocol_version: u32,
    /// Output proof serialization version.
    pub range_proof_serialization_version: u8,
    /// Consensus coinbase maturity.
    pub coinbase_maturity: u64,
    /// Snapshot tip height.
    pub tip_height: u64,
    /// Snapshot tip identifier.
    pub tip_hash: [u8; 32],
}

/// Canonical location of an observed transaction.
/// Where the authenticated scanner placed one transaction.
///
/// Its fields are private and it has **no public constructor at all**: a value
/// of this type exists only inside a
/// [`CanonicalTransactionEvidenceV1`], and only this module builds one. A
/// caller may read a location; it cannot make one, and it cannot alter one it
/// was given.
///
/// ```compile_fail
/// use dom_scriptless_chain_adapter::TransactionLocationV1;
///
/// let _forged = TransactionLocationV1 {
///     block_height: 9,
///     block_hash: [0x81; 32],
///     transaction_index: 1,
/// };
/// ```
///
/// **What it does not establish.** That the transaction is at that height, in
/// that block, at that index. These three values are the scanner's word,
/// carried faithfully; sealing them stops a third party from substituting
/// them, and stops nothing else. What makes a location trustworthy is the
/// hash-linked walk that proves the block is an ancestor of a reported tip —
/// `RealDomRpcRuntimeV1::transaction_with_proved_tip` in `adapters/dom-real`,
/// not this type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TransactionLocationV1 {
    block_height: u64,
    block_hash: [u8; 32],
    transaction_index: u32,
}

impl TransactionLocationV1 {
    /// Block height the scanner reported.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Canonical block identifier the scanner reported.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Zero-based position of the transaction inside that block.
    #[must_use]
    pub const fn transaction_index(&self) -> u32 {
        self.transaction_index
    }
}

/// Full, locally decoded real-DOM transaction evidence.
///
/// Its fields are private: callers may inspect evidence, but cannot
/// manufacture it. The invariant this buys is exact and worth stating in one
/// sentence: **it is impossible to build an evidence whose `tx_hash`
/// disagrees with its `canonical_bytes`**, because no constructor accepts an
/// identity — every route derives it from the bytes through
/// [`canonical_transaction_hash_v1`], which decodes with the pinned decoder,
/// requires the re-encoding to round-trip, and only then hashes.
///
/// All four fields are private, and that is what makes a forged literal
/// impossible. It is asserted as four reads rather than as one literal, and
/// deliberately: a literal would have to name `dom_consensus::Transaction` for
/// the last field, and a `compile_fail` block that fails because an `extern`
/// did not resolve passes while testing nothing. Every block below names the
/// crate under test and nothing else, so the only error each of them can
/// produce is the one it is there to produce.
///
/// ```compile_fail
/// fn read_location(e: &dom_scriptless_chain_adapter::CanonicalTransactionEvidenceV1) {
///     let _ = e.location;
/// }
/// ```
///
/// ```compile_fail
/// fn read_identity(e: &dom_scriptless_chain_adapter::CanonicalTransactionEvidenceV1) {
///     let _ = e.tx_hash;
/// }
/// ```
///
/// ```compile_fail
/// fn read_bytes(e: &dom_scriptless_chain_adapter::CanonicalTransactionEvidenceV1) {
///     let _ = &e.canonical_bytes;
/// }
/// ```
///
/// ```compile_fail
/// fn read_transaction(e: &dom_scriptless_chain_adapter::CanonicalTransactionEvidenceV1) {
///     let _ = &e.transaction;
/// }
/// ```
///
/// Two negatives used to live in `adapters/dom-real`'s test module and are
/// promoted here, because the compiler now says what they used to assert.
/// Both set an identity that contradicted the bytes — one an arbitrary
/// `[0x9a; 32]`, one the funding transaction's identity on a claim — and both
/// existed to prove that the verifier recomputes the identity from the bytes
/// and refuses a mislabelled transaction. That state is no longer refuted; it
/// is unrepresentable, and these two lines are the whole of what remains
/// necessary:
///
/// ```compile_fail
/// fn mislabel(mut evidence: dom_scriptless_chain_adapter::CanonicalTransactionEvidenceV1) {
///     evidence.tx_hash = [0x9a; 32];
/// }
/// ```
///
/// **What it does not establish.** That this transaction is on any chain, at
/// the location it carries, or at all. It establishes that these bytes decode,
/// round-trip, and hash to this identity. Inclusion is the scanner's claim and
/// the ancestry walk's proof; see [`TransactionLocationV1`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CanonicalTransactionEvidenceV1 {
    location: TransactionLocationV1,
    tx_hash: [u8; 32],
    canonical_bytes: Vec<u8>,
    transaction: Transaction,
}

impl CanonicalTransactionEvidenceV1 {
    /// Builds evidence from exact canonical bytes and the location they were
    /// found at, deriving the identity rather than accepting one.
    ///
    /// The only public route into this type. It runs
    /// [`canonical_transaction_hash_v1`] — pinned decoder, re-encoding
    /// round-trip, then hash — so the identity is a function of the bytes and
    /// a caller has nothing to lie about there. It adds no cryptographic
    /// surface: that discipline was already public and already the one the
    /// scanner path uses.
    ///
    /// The transaction is decoded a second time to be retained. That decode
    /// cannot fail once the first has succeeded, and it is written as a
    /// fallible call anyway rather than assumed, because "cannot fail" is the
    /// kind of claim this codebase has learned to check.
    ///
    /// **What the caller still chooses**, and it is deliberate: the three
    /// location values. That is honest rather than lax — the location is the
    /// scanner's word however this value is built, and what makes it
    /// trustworthy is the ancestry walk in `adapters/dom-real`, not a
    /// constructor here. A zero block identity is refused because it can
    /// describe no block, and that is the whole of what is checked.
    pub fn from_canonical_bytes_at(
        block_height: u64,
        block_hash: [u8; 32],
        transaction_index: u32,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, ChainAdapterError> {
        if block_hash == [0_u8; 32] {
            return Err(ChainAdapterError::InvalidEvidence);
        }
        let tx_hash = canonical_transaction_hash_v1(&canonical_bytes)?;
        let transaction = Transaction::from_bytes(&canonical_bytes)
            .map_err(|_| ChainAdapterError::InvalidTransaction)?;
        Ok(Self {
            location: TransactionLocationV1 {
                block_height,
                block_hash,
                transaction_index,
            },
            tx_hash,
            canonical_bytes,
            transaction,
        })
    }

    /// Canonical inclusion location the scanner reported.
    #[must_use]
    pub const fn location(&self) -> TransactionLocationV1 {
        self.location
    }

    /// BLAKE2b-256 identity, always derived from [`Self::canonical_bytes`].
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }

    /// Exact bytes the authenticated scanner returned.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Transaction decoded by the pinned DOM canonical decoder.
    #[must_use]
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Computes the signature-omitting template hash through the pinned DOM
    /// adaptor authority. This is the comparison used for an observed claim,
    /// whose final adaptor signature is not known when terms are frozen.
    pub fn template_hash(&self) -> Result<[u8; 32], ChainAdapterError> {
        dom_adaptor::canonical_template_v1(&self.transaction)
            .map(|(_, digest)| digest)
            .map_err(|_| ChainAdapterError::InvalidEvidence)
    }

    /// Whether this transaction spends the exact confidential commitment.
    #[must_use]
    pub fn spends_commitment(&self, commitment: &[u8; 33]) -> bool {
        self.transaction
            .inputs
            .iter()
            .any(|input| input.commitment.as_bytes() == commitment)
    }

    /// Whether this transaction creates the exact confidential commitment.
    #[must_use]
    pub fn creates_commitment(&self, commitment: &[u8; 33]) -> bool {
        self.transaction
            .outputs
            .iter()
            .any(|output| output.commitment.as_bytes() == commitment)
    }

    /// Returns one canonical final kernel signature by index.
    pub fn kernel_signature(&self, index: usize) -> Result<&[u8; 65], ChainAdapterError> {
        self.transaction
            .kernels
            .get(index)
            .map(|kernel| &kernel.excess_signature)
            .ok_or(ChainAdapterError::InvalidEvidence)
    }
}

/// One canonical block and its complete non-coinbase transactions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CanonicalBlockEvidenceV1 {
    /// Block height.
    pub height: u64,
    /// Canonical block identifier.
    pub block_hash: [u8; 32],
    /// Previous canonical block identifier.
    pub previous_block_hash: [u8; 32],
    /// Exact serialized header bytes.
    pub canonical_header_bytes: Vec<u8>,
    /// Header timestamp.
    pub timestamp: u64,
    /// Non-coinbase transactions preserving block order.
    pub transactions: Vec<CanonicalTransactionEvidenceV1>,
}

/// Validated scanner page.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScriptlessScanPageV1 {
    /// Identity and snapshot tip observed under the node's chain lock.
    pub identity: ObservedDomIdentityV1,
    /// Contiguous canonical blocks.
    pub blocks: Vec<CanonicalBlockEvidenceV1>,
    /// Cursor to persist only after all returned blocks are durably applied.
    pub next_cursor: ScriptlessScanCursorV1,
    /// Whether the snapshot tip was reached.
    pub reached_snapshot_tip: bool,
}

/// Successful economic admission of an exact transaction by a real DOM node.
///
/// Its fields are intentionally private: callers may inspect a receipt, but
/// cannot manufacture one.  Values are created only after the closed node
/// response has been validated against the locally recomputed transaction
/// identifier and the economic predicate (`confirmed || relayed`).
///
/// ```compile_fail
/// use dom_scriptless_chain_adapter::{SubmissionReceiptV1, SubmissionStateV1};
///
/// let _forged = SubmissionReceiptV1 {
///     tx_hash: [1_u8; 32],
///     relayed: true,
///     state: SubmissionStateV1::New,
/// };
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use = "a validated submission receipt must be durably acted upon"]
pub struct SubmissionReceiptV1 {
    tx_hash: [u8; 32],
    relayed: bool,
    state: SubmissionStateV1,
}

impl SubmissionReceiptV1 {
    /// Locally recomputed canonical transaction identifier.
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }

    /// Whether at least one relay subscriber accepted the exact transaction.
    #[must_use]
    pub const fn was_relayed(&self) -> bool {
        self.relayed
    }

    /// Canonical node knowledge state for this exact transaction.
    #[must_use]
    pub const fn state(&self) -> SubmissionStateV1 {
        self.state
    }

    /// Whether this validated receipt establishes economic admission.
    ///
    /// This is always true for values returned by the production adapter.  It
    /// remains public so durable consumers can defensively recheck the
    /// invariant without reconstructing the receipt.
    #[must_use]
    pub const fn is_economically_admitted(&self) -> bool {
        self.state.is_confirmed() || self.relayed
    }

    /// Canonical commitment to the exact validated receipt facts.
    #[must_use]
    pub fn receipt_digest_v1(&self) -> [u8; 32] {
        submission_receipt_digest_v1(self.tx_hash, self.state, self.relayed)
    }
}

/// Exact transaction state returned by idempotent real-node submission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SubmissionStateV1 {
    /// Newly admitted into this node's mempool.
    New,
    /// Exact bytes were already in the mempool and were retransmitted.
    Mempool,
    /// Exact bytes are already present in the canonical chain.
    Confirmed,
}

impl SubmissionStateV1 {
    /// Stable tag used by the canonical receipt commitment and durable stores.
    #[must_use]
    pub const fn tag_v1(self) -> u8 {
        match self {
            Self::New => 1,
            Self::Mempool => 2,
            Self::Confirmed => 3,
        }
    }

    /// Whether the exact transaction is already in the canonical chain.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

/// Revalidates public receipt facts loaded from a durable owner-only store.
///
/// This function does not mint a [`SubmissionReceiptV1`]. It only checks the
/// economic predicate and the domain-separated commitment, allowing a durable
/// consumer to detect local corruption without creating a caller-forgeable
/// node receipt.
pub fn validate_submission_receipt_facts_v1(
    tx_hash: [u8; 32],
    state: SubmissionStateV1,
    relayed: bool,
    receipt_digest: [u8; 32],
) -> Result<(), ChainAdapterError> {
    if !(state.is_confirmed() || relayed)
        || submission_receipt_digest_v1(tx_hash, state, relayed) != receipt_digest
    {
        return Err(ChainAdapterError::InvalidEvidence);
    }
    Ok(())
}

fn submission_receipt_digest_v1(
    tx_hash: [u8; 32],
    state: SubmissionStateV1,
    relayed: bool,
) -> [u8; 32] {
    let mut material = [0_u8; 34];
    material[..32].copy_from_slice(&tx_hash);
    material[32] = state.tag_v1();
    material[33] = u8::from(relayed);
    let mut input = Vec::with_capacity(31 + material.len());
    input.extend_from_slice(b"DOM:submission-receipt:v1");
    input.extend_from_slice(&material);
    *blake2b_256(&input).as_bytes()
}

/// Bearer token kept zeroizing and always redacted from formatting.
pub struct BearerTokenV1(Zeroizing<String>);

impl BearerTokenV1 {
    /// Retains a nonempty token. Tokens larger than 4 KiB are rejected before
    /// entering the HTTP client.
    ///
    /// The token is moved into its zeroizing wrapper **before** validation, so
    /// every exit path of *this constructor* wipes it. A rejected token is
    /// secret material exactly like an accepted one — it was typed, sealed or
    /// read from a manifest by the same operator — and failing validation is no
    /// reason to hand it back to the allocator in the clear.
    ///
    /// Known limit, stated rather than implied: this covers **retention**, not
    /// transmission. Every request re-materializes the credential through
    /// `bearer_auth` (`:556`, `:579`), which builds a `String` and a
    /// `HeaderValue` that this crate does not own and cannot zeroize. `reqwest`
    /// marks the resulting header sensitive, so it is kept out of logs and
    /// debug output, but the bytes still reach the allocator uncleared once per
    /// request. Closing that would require an owned header path through the
    /// HTTP client, which is out of this boundary's control.
    pub fn new(token: String) -> Result<Self, ChainAdapterError> {
        let token = Zeroizing::new(token);
        if token.is_empty()
            || token.len() > 4_096
            || token.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ChainAdapterError::InvalidConfiguration);
        }
        Ok(Self(token))
    }
}

impl core::fmt::Debug for BearerTokenV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BearerTokenV1(<redacted>)")
    }
}

/// Strict client for the authenticated DOM Scriptless scanner and mempool.
pub struct DomHttpChainAdapterV1 {
    endpoint: reqwest::Url,
    client: Client,
    expected: ExpectedDomIdentityV1,
    bearer_token: BearerTokenV1,
}

impl DomHttpChainAdapterV1 {
    /// Constructs a client with fixed timeouts, no redirects and a frozen
    /// expected identity. Plain HTTP is accepted only for a loopback host.
    pub fn new(
        endpoint: &str,
        expected: ExpectedDomIdentityV1,
        bearer_token: BearerTokenV1,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ChainAdapterError> {
        expected.validate()?;
        // Endpoint length bound. The daemon repeats this number as
        // `MAX_DOM_NODE_ENDPOINT_BYTES_V1`
        // (`dom-interopd/src/production_node.rs:77`) because the dependency runs
        // daemon -> adapter and a shared constant would invert it. The two must
        // move together, and the daemon side already proves they agree in
        // `endpoint_prefilter_and_client_agree_on_the_canonical_table`
        // (`production_node.rs:959`); this comment is the link from the adapter
        // side, which has no way to reference that test.
        if endpoint.len() > 2_048
            || connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > request_timeout
        {
            return Err(ChainAdapterError::InvalidConfiguration);
        }
        let mut url =
            reqwest::Url::parse(endpoint).map_err(|_| ChainAdapterError::InvalidConfiguration)?;
        if url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ChainAdapterError::InvalidConfiguration);
        }
        let host = url
            .host_str()
            .ok_or(ChainAdapterError::InvalidConfiguration)?;
        // `Url::host_str` returns an IPv6 literal in its bracketed form
        // (`[::1]`), which `IpAddr` does not parse. Strip exactly that wrapper
        // and nothing else, so an IPv6 loopback is recognised as the loopback it
        // is. Without this, `http://[::1]/` was refused while `https://[::1]/`
        // was accepted — an accidental asymmetry of URL syntax, never a rule.
        let bare_host = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host);
        let loopback = bare_host.eq_ignore_ascii_case("localhost")
            || bare_host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(ChainAdapterError::InvalidConfiguration);
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ChainAdapterError::InvalidConfiguration);
        }
        let normalized_path = url.path().trim_end_matches('/').to_owned();
        url.set_path(if normalized_path.is_empty() {
            "/"
        } else {
            &normalized_path
        });
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ChainAdapterError::InvalidConfiguration)?;
        Ok(Self {
            endpoint: url,
            client,
            expected,
            bearer_token,
        })
    }

    /// Frozen identity supplied by the composition root.
    pub const fn expected_identity(&self) -> &ExpectedDomIdentityV1 {
        &self.expected
    }

    /// Reads and validates one bounded scanner page.
    pub fn scan_page(
        &self,
        cursor: ScriptlessScanCursorV1,
        max_blocks: u64,
    ) -> Result<ScriptlessScanPageV1, ChainAdapterError> {
        cursor.validate()?;
        if max_blocks == 0 || max_blocks > MAX_SCRIPTLESS_SCAN_BLOCKS_V1 {
            return Err(ChainAdapterError::BoundsExceeded);
        }
        let requested_to = cursor
            .next_height
            .checked_add(max_blocks - 1)
            .ok_or(ChainAdapterError::BoundsExceeded)?;
        let mut url = self.endpoint_for("chain/scan/scriptless/v1")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("from", &cursor.next_height.to_string());
            query.append_pair("to", &requested_to.to_string());
            query.append_pair(
                "expected_network_magic",
                &self.expected.network_magic.to_string(),
            );
            query.append_pair("expected_chain_id", &hex::encode(self.expected.chain_id));
            if let Some(anchor) = cursor.anchor_hash {
                query.append_pair("anchor_hash", &hex::encode(anchor));
            }
        }
        let response = self
            .client
            .get(url)
            .bearer_auth(self.bearer_token.0.as_str())
            .send()
            .map_err(map_transport_error)?;
        let dto: ScanResponseDto =
            decode_json_response(response, ChainAdapterError::ReorgDetected)?;
        validate_scan_response(&self.expected, cursor, requested_to, dto)
    }

    /// Submits exact canonical transaction bytes to the real DOM mempool.
    /// Local parsing is a preflight only; the node remains the authority.
    /// A receipt is returned only after the node proves canonical confirmation
    /// or at least one relay subscriber accepted the exact transaction.
    pub fn submit_canonical_transaction(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<SubmissionReceiptV1, ChainAdapterError> {
        let expected_hash = canonical_transaction_hash_v1(canonical_bytes)?;
        let body = SubmitRequestDto {
            tx_hex: hex::encode(canonical_bytes),
        };
        let response = self
            .client
            .post(self.endpoint_for("tx/submit")?)
            .bearer_auth(self.bearer_token.0.as_str())
            .json(&body)
            .send()
            .map_err(map_transport_error)?;
        let dto: SubmitResponseDto =
            decode_json_response(response, ChainAdapterError::TransactionRejected)?;
        validate_submission_response(dto, expected_hash)
    }

    fn endpoint_for(&self, suffix: &str) -> Result<reqwest::Url, ChainAdapterError> {
        let base = self.endpoint.as_str().trim_end_matches('/');
        reqwest::Url::parse(&format!("{base}/{suffix}"))
            .map_err(|_| ChainAdapterError::InvalidConfiguration)
    }
}

fn validate_submission_response(
    dto: SubmitResponseDto,
    expected_hash: [u8; 32],
) -> Result<SubmissionReceiptV1, ChainAdapterError> {
    if !dto.accepted || dto.error.is_some() {
        return Err(ChainAdapterError::TransactionRejected);
    }
    let state = match dto.state.as_str() {
        "new" if !dto.already_known && !dto.confirmed => SubmissionStateV1::New,
        "mempool" if dto.already_known && !dto.confirmed => SubmissionStateV1::Mempool,
        "confirmed" if dto.already_known && dto.confirmed => SubmissionStateV1::Confirmed,
        _ => return Err(ChainAdapterError::MalformedResponse),
    };
    let observed_hash = dto
        .tx_hash
        .as_deref()
        .ok_or(ChainAdapterError::MalformedResponse)
        .and_then(parse_hex_32)?;
    if observed_hash != expected_hash {
        return Err(ChainAdapterError::InvalidEvidence);
    }
    let receipt = SubmissionReceiptV1 {
        tx_hash: expected_hash,
        relayed: dto.relayed,
        state,
    };
    if !receipt.is_economically_admitted() {
        // The node accepted the bytes locally, but they remain volatile.  The
        // caller must retry the exact transaction until it is relayed or
        // observed canonical; no admission authority is emitted yet.
        return Err(ChainAdapterError::TemporarilyUnavailable);
    }
    Ok(receipt)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDto {
    network: String,
    network_magic: u32,
    chain_id: String,
    genesis_hash: String,
    protocol_version: u32,
    range_proof_serialization_version: u8,
    coinbase_maturity: u64,
    tip_height: u64,
    tip_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorDto {
    height: u64,
    block_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDto {
    spent_commitment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputDto {
    commitment: String,
    range_proof: String,
    recovery_capsule: String,
    recovery_version: u16,
    is_coinbase: bool,
    block_height: u64,
    block_hash: String,
    output_position: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelDto {
    excess: String,
    features: u8,
    fee: u64,
    lock_height: u64,
    excess_signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionDto {
    block_height: u64,
    block_hash: String,
    transaction_index: u32,
    tx_hash: String,
    canonical_bytes: String,
    inputs: Vec<InputDto>,
    outputs: Vec<OutputDto>,
    kernels: Vec<KernelDto>,
    offset: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoinbaseDto {
    output_commitment: String,
    explicit_value: u64,
    kernel_excess: String,
    kernel_features: u8,
    kernel_excess_signature: String,
    offset: String,
    output_proof_envelope: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockDto {
    height: u64,
    block_hash: String,
    previous_block_hash: String,
    canonical_header_bytes: String,
    timestamp: u64,
    canonical_marker: String,
    transactions: Vec<TransactionDto>,
    coinbase: CoinbaseDto,
    total_fees_noms: u64,
    protocol_version: u32,
    range_proof_serialization_version: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContinuationDto {
    next_height: u64,
    anchor: AnchorDto,
    snapshot_tip_height: u64,
    snapshot_tip_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanResponseDto {
    schema_version: u16,
    status: String,
    canonical: bool,
    identity: IdentityDto,
    requested_from: u64,
    requested_to: u64,
    served_from: u64,
    served_to: Option<u64>,
    request_anchor: Option<AnchorDto>,
    blocks: Vec<BlockDto>,
    continuation: Option<ContinuationDto>,
}

#[derive(Serialize)]
struct SubmitRequestDto {
    tx_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitResponseDto {
    accepted: bool,
    relayed: bool,
    tx_hash: Option<String>,
    state: String,
    already_known: bool,
    confirmed: bool,
    #[serde(rename = "warning")]
    _warning: Option<String>,
    error: Option<String>,
}

fn validate_scan_response(
    expected: &ExpectedDomIdentityV1,
    cursor: ScriptlessScanCursorV1,
    requested_to: u64,
    dto: ScanResponseDto,
) -> Result<ScriptlessScanPageV1, ChainAdapterError> {
    if dto.schema_version != SCRIPTLESS_SCAN_SCHEMA_V1
        || dto.status != "ok"
        || !dto.canonical
        || dto.requested_from != cursor.next_height
        || dto.requested_to != requested_to
        || dto.served_from != cursor.next_height
        || dto.blocks.len() > MAX_SCRIPTLESS_SCAN_BLOCKS_V1 as usize
    {
        return Err(ChainAdapterError::MalformedResponse);
    }
    let identity = parse_and_validate_identity(expected, dto.identity)?;
    validate_request_anchor(cursor, dto.request_anchor)?;

    let mut blocks = Vec::with_capacity(dto.blocks.len());
    let mut expected_height = cursor.next_height;
    let mut expected_previous = cursor.anchor_hash;
    for block in dto.blocks {
        if block.height != expected_height {
            return Err(ChainAdapterError::InvalidEvidence);
        }
        let block_hash = parse_hex_32(&block.block_hash)?;
        let previous_block_hash = parse_hex_32(&block.previous_block_hash)?;
        if expected_previous.is_some_and(|previous| previous != previous_block_hash)
            || parse_hex_32(&block.canonical_marker)? != block_hash
            || block.range_proof_serialization_version != identity.range_proof_serialization_version
        {
            return Err(ChainAdapterError::InvalidEvidence);
        }
        let header_bytes = parse_hex_bounded(
            &block.canonical_header_bytes,
            BlockHeader::MIN_SERIALIZED_SIZE.saturating_mul(4),
        )?;
        let header = BlockHeader::from_bytes(&header_bytes)
            .map_err(|_| ChainAdapterError::InvalidEvidence)?;
        let header_hash = *blake2b_256(&header_bytes).as_bytes();
        validate_consensus_header_version(block.protocol_version, header.version)?;
        if header_hash != block_hash
            || header.height.0 != block.height
            || header.timestamp.0 != block.timestamp
            || header.prev_hash.as_bytes() != &previous_block_hash
        {
            return Err(ChainAdapterError::InvalidEvidence);
        }
        validate_coinbase(&block.coinbase)?;
        let mut transactions = Vec::with_capacity(block.transactions.len());
        let mut total_fees = 0_u64;
        let mut next_output_position = 1_u32;
        for (position, transaction) in block.transactions.into_iter().enumerate() {
            let index = u32::try_from(position).map_err(|_| ChainAdapterError::BoundsExceeded)?;
            if transaction.block_height != block.height
                || transaction.block_hash != block.block_hash
                || transaction.transaction_index != index
            {
                return Err(ChainAdapterError::InvalidEvidence);
            }
            let evidence =
                validate_transaction(transaction, block.height, block_hash, next_output_position)?;
            let output_count = u32::try_from(evidence.transaction.outputs.len())
                .map_err(|_| ChainAdapterError::BoundsExceeded)?;
            next_output_position = next_output_position
                .checked_add(output_count)
                .ok_or(ChainAdapterError::BoundsExceeded)?;
            for kernel in &evidence.transaction.kernels {
                total_fees = total_fees
                    .checked_add(kernel.fee.noms())
                    .ok_or(ChainAdapterError::InvalidEvidence)?;
            }
            transactions.push(evidence);
        }
        if total_fees != block.total_fees_noms {
            return Err(ChainAdapterError::InvalidEvidence);
        }
        blocks.push(CanonicalBlockEvidenceV1 {
            height: block.height,
            block_hash,
            previous_block_hash,
            canonical_header_bytes: header_bytes,
            timestamp: block.timestamp,
            transactions,
        });
        expected_previous = Some(block_hash);
        expected_height = expected_height
            .checked_add(1)
            .ok_or(ChainAdapterError::BoundsExceeded)?;
    }

    let observed_served_to = blocks.last().map(|block| block.height);
    if dto.served_to != observed_served_to {
        return Err(ChainAdapterError::MalformedResponse);
    }
    let (next_cursor, reached_snapshot_tip) = match dto.continuation {
        Some(continuation) => {
            let last = blocks.last().ok_or(ChainAdapterError::MalformedResponse)?;
            let anchor = parse_anchor(continuation.anchor)?;
            if anchor != (last.height, last.block_hash)
                || continuation.next_height != last.height.saturating_add(1)
                || continuation.snapshot_tip_height != identity.tip_height
                || parse_hex_32(&continuation.snapshot_tip_hash)? != identity.tip_hash
            {
                return Err(ChainAdapterError::InvalidEvidence);
            }
            (
                ScriptlessScanCursorV1 {
                    next_height: continuation.next_height,
                    anchor_hash: Some(last.block_hash),
                },
                false,
            )
        }
        None => {
            if let Some(last) = blocks.last() {
                if last.height != identity.tip_height || last.block_hash != identity.tip_hash {
                    return Err(ChainAdapterError::InvalidEvidence);
                }
                (
                    ScriptlessScanCursorV1 {
                        next_height: last
                            .height
                            .checked_add(1)
                            .ok_or(ChainAdapterError::BoundsExceeded)?,
                        anchor_hash: Some(last.block_hash),
                    },
                    true,
                )
            } else {
                if cursor.next_height <= identity.tip_height {
                    return Err(ChainAdapterError::InvalidEvidence);
                }
                (cursor, true)
            }
        }
    };
    Ok(ScriptlessScanPageV1 {
        identity,
        blocks,
        next_cursor,
        reached_snapshot_tip,
    })
}

fn validate_consensus_header_version(
    projected_version: u32,
    decoded_version: u32,
) -> Result<(), ChainAdapterError> {
    if projected_version == decoded_version {
        Ok(())
    } else {
        Err(ChainAdapterError::InvalidEvidence)
    }
}

fn parse_and_validate_identity(
    expected: &ExpectedDomIdentityV1,
    dto: IdentityDto,
) -> Result<ObservedDomIdentityV1, ChainAdapterError> {
    let observed = ObservedDomIdentityV1 {
        network: dto.network,
        network_magic: dto.network_magic,
        chain_id: parse_hex_32(&dto.chain_id)?,
        genesis_hash: parse_hex_32(&dto.genesis_hash)?,
        protocol_version: dto.protocol_version,
        range_proof_serialization_version: dto.range_proof_serialization_version,
        coinbase_maturity: dto.coinbase_maturity,
        tip_height: dto.tip_height,
        tip_hash: parse_hex_32(&dto.tip_hash)?,
    };
    if observed.network != expected.network
        || observed.network_magic != expected.network_magic
        || observed.chain_id != expected.chain_id
        || observed.genesis_hash != expected.genesis_hash
        || observed.protocol_version != expected.protocol_version
        || observed.range_proof_serialization_version != expected.range_proof_serialization_version
        || observed.coinbase_maturity == 0
        || observed.tip_hash == [0_u8; 32]
    {
        return Err(ChainAdapterError::IdentityMismatch);
    }
    Ok(observed)
}

fn validate_request_anchor(
    cursor: ScriptlessScanCursorV1,
    anchor: Option<AnchorDto>,
) -> Result<(), ChainAdapterError> {
    match (cursor.next_height, cursor.anchor_hash, anchor) {
        (0, None, None) => Ok(()),
        (height, Some(expected), Some(observed)) if height > 0 => {
            let observed = parse_anchor(observed)?;
            if observed == (height - 1, expected) {
                Ok(())
            } else {
                Err(ChainAdapterError::InvalidEvidence)
            }
        }
        _ => Err(ChainAdapterError::MalformedResponse),
    }
}

fn parse_anchor(anchor: AnchorDto) -> Result<(u64, [u8; 32]), ChainAdapterError> {
    Ok((anchor.height, parse_hex_32(&anchor.block_hash)?))
}

fn validate_transaction(
    dto: TransactionDto,
    block_height: u64,
    block_hash: [u8; 32],
    first_output_position: u32,
) -> Result<CanonicalTransactionEvidenceV1, ChainAdapterError> {
    let canonical_bytes =
        parse_hex_bounded(&dto.canonical_bytes, MAX_CANONICAL_TRANSACTION_BYTES_V1)?;
    let transaction = Transaction::from_bytes(&canonical_bytes)
        .map_err(|_| ChainAdapterError::InvalidEvidence)?;
    if transaction
        .to_bytes()
        .map_err(|_| ChainAdapterError::InvalidEvidence)?
        != canonical_bytes
    {
        return Err(ChainAdapterError::InvalidEvidence);
    }
    let tx_hash = *blake2b_256(&canonical_bytes).as_bytes();
    if parse_hex_32(&dto.tx_hash)? != tx_hash
        || parse_hex_32(&dto.offset)? != transaction.offset
        || dto.inputs.len() != transaction.inputs.len()
        || dto.outputs.len() != transaction.outputs.len()
        || dto.kernels.len() != transaction.kernels.len()
    {
        return Err(ChainAdapterError::InvalidEvidence);
    }
    for (projected, canonical) in dto.inputs.iter().zip(&transaction.inputs) {
        if parse_hex_33(&projected.spent_commitment)? != *canonical.commitment.as_bytes() {
            return Err(ChainAdapterError::InvalidEvidence);
        }
    }
    for (position, (projected, canonical)) in
        dto.outputs.iter().zip(&transaction.outputs).enumerate()
    {
        let position = u32::try_from(position).map_err(|_| ChainAdapterError::BoundsExceeded)?;
        let expected_position = first_output_position
            .checked_add(position)
            .ok_or(ChainAdapterError::BoundsExceeded)?;
        let capsule = canonical
            .recovery_capsule()
            .map_err(|_| ChainAdapterError::InvalidEvidence)?;
        let capsule_bytes: &[u8] = match capsule.as_ref() {
            Some(value) => value.as_bytes().as_slice(),
            None => &[],
        };
        let capsule_version = capsule.as_ref().map_or(0, |value| value.version());
        if parse_hex_33(&projected.commitment)? != *canonical.commitment.as_bytes()
            || parse_hex_bounded(&projected.range_proof, dom_crypto::RANGE_PROOF_SIZE)?
                != canonical
                    .range_proof_bytes()
                    .map_err(|_| ChainAdapterError::InvalidEvidence)?
            || parse_hex_bounded(&projected.recovery_capsule, 96)? != capsule_bytes
            || projected.recovery_version != capsule_version
            || projected.is_coinbase
            || projected.block_height != block_height
            || parse_hex_32(&projected.block_hash)? != block_hash
            || projected.output_position != expected_position
        {
            return Err(ChainAdapterError::InvalidEvidence);
        }
    }
    for (projected, canonical) in dto.kernels.iter().zip(&transaction.kernels) {
        if parse_hex_33(&projected.excess)? != *canonical.excess.as_bytes()
            || projected.features != canonical.features
            || projected.fee != canonical.fee.noms()
            || projected.lock_height != canonical.lock_height
            || parse_hex_65(&projected.excess_signature)? != canonical.excess_signature
        {
            return Err(ChainAdapterError::InvalidEvidence);
        }
    }
    Ok(CanonicalTransactionEvidenceV1 {
        location: TransactionLocationV1 {
            block_height,
            block_hash,
            transaction_index: dto.transaction_index,
        },
        tx_hash,
        canonical_bytes,
        transaction,
    })
}

fn validate_coinbase(dto: &CoinbaseDto) -> Result<(), ChainAdapterError> {
    let _ = parse_hex_33(&dto.output_commitment)?;
    let _ = parse_hex_33(&dto.kernel_excess)?;
    let _ = parse_hex_65(&dto.kernel_excess_signature)?;
    let _ = parse_hex_32(&dto.offset)?;
    let _ = parse_hex_bounded(
        &dto.output_proof_envelope,
        dom_crypto::RANGE_PROOF_SIZE.saturating_add(96),
    )?;
    if dto.explicit_value == 0 || dto.kernel_features == 0 {
        return Err(ChainAdapterError::InvalidEvidence);
    }
    Ok(())
}

fn decode_json_response<T: for<'de> Deserialize<'de>>(
    response: Response,
    conflict_error: ChainAdapterError,
) -> Result<T, ChainAdapterError> {
    let status = response.status().as_u16();
    match status {
        200..=299 => {}
        400 => return Err(ChainAdapterError::MalformedResponse),
        401 | 403 => return Err(ChainAdapterError::AuthenticationFailed),
        404 => return Err(ChainAdapterError::CapabilityUnavailable),
        409 => return Err(conflict_error),
        429 | 503 => return Err(ChainAdapterError::TemporarilyUnavailable),
        other => return Err(ChainAdapterError::HttpStatus(other)),
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SCRIPTLESS_RESPONSE_BYTES_V1)
    {
        return Err(ChainAdapterError::BoundsExceeded);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_SCRIPTLESS_RESPONSE_BYTES_V1 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ChainAdapterError::TemporarilyUnavailable)?;
    if bytes.len() as u64 > MAX_SCRIPTLESS_RESPONSE_BYTES_V1 {
        return Err(ChainAdapterError::BoundsExceeded);
    }
    serde_json::from_slice(&bytes).map_err(|_| ChainAdapterError::MalformedResponse)
}

fn map_transport_error(error: reqwest::Error) -> ChainAdapterError {
    if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body() {
        ChainAdapterError::TemporarilyUnavailable
    } else {
        ChainAdapterError::MalformedResponse
    }
}

fn parse_hex_bounded(value: &str, maximum: usize) -> Result<Vec<u8>, ChainAdapterError> {
    if value.len() % 2 != 0 || value.len() / 2 > maximum {
        return Err(ChainAdapterError::BoundsExceeded);
    }
    hex::decode(value).map_err(|_| ChainAdapterError::MalformedResponse)
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N], ChainAdapterError> {
    if value.len() != N.saturating_mul(2) {
        return Err(ChainAdapterError::MalformedResponse);
    }
    let bytes = hex::decode(value).map_err(|_| ChainAdapterError::MalformedResponse)?;
    bytes
        .try_into()
        .map_err(|_| ChainAdapterError::MalformedResponse)
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], ChainAdapterError> {
    parse_hex_array(value)
}

fn parse_hex_33(value: &str) -> Result<[u8; 33], ChainAdapterError> {
    parse_hex_array(value)
}

fn parse_hex_65(value: &str) -> Result<[u8; 65], ChainAdapterError> {
    parse_hex_array(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Result<ExpectedDomIdentityV1, ChainAdapterError> {
        identity_for("regtest", dom_core::NETWORK_MAGIC_REGTEST)
    }

    fn identity_for(
        network: &str,
        network_magic: u32,
    ) -> Result<ExpectedDomIdentityV1, ChainAdapterError> {
        let genesis = dom_core::startup_genesis_hash_for_network_magic(network_magic)
            .map_err(|_| ChainAdapterError::InvalidConfiguration)?;
        Ok(ExpectedDomIdentityV1 {
            network: network.to_owned(),
            network_magic,
            chain_id: *dom_consensus::derive_chain_id(network_magic, &genesis).as_bytes(),
            genesis_hash: *genesis.as_bytes(),
            protocol_version: dom_core::PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        })
    }

    #[test]
    fn bearer_tokens_reject_ascii_control_and_out_of_range_material(
    ) -> Result<(), ChainAdapterError> {
        // A trailing newline is the realistic accident: a token read from a file
        // or pasted into a manifest. `BearerTokenV1` has no `PartialEq`, and the
        // workspace lints deny `unwrap_err`, so the error is bound by let-else
        // and then compared by its exact variant.
        for rejected in [
            "tok\n".to_owned(),
            "tok\u{0}".to_owned(),
            "tok\t".to_owned(),
            String::new(),
            "x".repeat(4_097),
        ] {
            let Err(error) = BearerTokenV1::new(rejected) else {
                return Err(ChainAdapterError::InvalidConfiguration);
            };
            assert_eq!(error, ChainAdapterError::InvalidConfiguration);
        }
        BearerTokenV1::new("valid-token".to_owned())?;
        BearerTokenV1::new("x".repeat(4_096))?;
        Ok(())
    }

    #[test]
    fn plain_http_is_accepted_only_for_loopback_hosts() -> Result<(), ChainAdapterError> {
        // IPv6 loopback must behave exactly like IPv4 loopback. The bracketed
        // host form is a URL syntax detail, never a policy difference.
        for (endpoint, accepted) in [
            ("http://127.0.0.1:8080/", true),
            ("http://[::1]:8080/", true),
            ("http://localhost:8080/", true),
            ("http://10.0.0.1:8080/", false),
            ("http://[2001:db8::1]:8080/", false),
            ("http://node.example:8080/", false),
            // An IPv4-mapped IPv6 address is deliberately NOT unwrapped:
            // `Ipv6Addr::is_loopback` is true only for `::1`, and widening that
            // here would be policy, not syntax.
            ("http://[::ffff:127.0.0.1]:8080/", false),
            // A malformed IPv6 literal fails at URL parsing, before any
            // loopback question is asked.
            ("http://[::1:8080/", false),
            ("https://127.0.0.1:8080/", true),
            ("https://[::1]:8080/", true),
            ("https://10.0.0.1:8080/", true),
            ("https://[2001:db8::1]:8080/", true),
            ("https://node.example:8080/", true),
        ] {
            let outcome = DomHttpChainAdapterV1::new(
                endpoint,
                identity()?,
                BearerTokenV1::new("table-driven-token".to_owned())?,
                Duration::from_millis(50),
                Duration::from_millis(50),
            );
            match outcome {
                Ok(_) => assert!(accepted, "endpoint {endpoint} must be refused"),
                Err(error) => {
                    assert!(!accepted, "endpoint {endpoint} must be accepted");
                    assert_eq!(error, ChainAdapterError::InvalidConfiguration);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn identity_accepts_only_exact_startup_safe_network_tuple() -> Result<(), ChainAdapterError> {
        let identity = identity()?;
        assert_eq!(identity.validate(), Ok(()));
        let mainnet = identity_for("mainnet", dom_core::NETWORK_MAGIC_MAINNET)?;
        assert_eq!(mainnet.validate(), Ok(()));
        assert_eq!(
            identity_for("testnet", dom_core::NETWORK_MAGIC_TESTNET)?.validate(),
            Ok(())
        );

        let mut wrong_magic = mainnet.clone();
        wrong_magic.network_magic = dom_core::NETWORK_MAGIC_REGTEST;
        assert_eq!(
            wrong_magic.validate(),
            Err(ChainAdapterError::InvalidConfiguration)
        );

        let mut wrong_protocol = mainnet.clone();
        wrong_protocol.protocol_version = wrong_protocol.protocol_version.saturating_add(1);
        assert_eq!(
            wrong_protocol.validate(),
            Err(ChainAdapterError::InvalidConfiguration)
        );

        let mut wrong_rangeproof = mainnet.clone();
        wrong_rangeproof.range_proof_serialization_version = wrong_rangeproof
            .range_proof_serialization_version
            .saturating_add(1);
        let mut wrong_genesis = mainnet.clone();
        wrong_genesis.genesis_hash[0] ^= 1;
        let mut wrong_chain = mainnet;
        wrong_chain.chain_id[0] ^= 1;
        for invalid in [wrong_rangeproof, wrong_genesis, wrong_chain] {
            assert_eq!(
                invalid.validate(),
                Err(ChainAdapterError::InvalidConfiguration)
            );
        }
        Ok(())
    }

    #[test]
    fn configuration_rejects_remote_plaintext_and_secrets_in_url() -> Result<(), ChainAdapterError>
    {
        let token = || BearerTokenV1::new("laboratory-token".to_owned());
        assert!(DomHttpChainAdapterV1::new(
            "http://example.com:43374",
            identity()?,
            token()?,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .is_err());
        assert!(DomHttpChainAdapterV1::new(
            "http://user:secret@127.0.0.1:43374",
            identity()?,
            token()?,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .is_err());
        assert!(DomHttpChainAdapterV1::new(
            "http://127.0.0.1:43374",
            identity()?,
            token()?,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .is_ok());
        Ok(())
    }

    #[test]
    fn token_and_secret_material_are_redacted() -> Result<(), ChainAdapterError> {
        let token = BearerTokenV1::new("do-not-print-this".to_owned())?;
        let rendered = format!("{token:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("do-not-print-this"));
        Ok(())
    }

    #[test]
    fn cursor_and_hex_parsing_fail_closed() {
        assert!(ScriptlessScanCursorV1::genesis().validate().is_ok());
        assert!(ScriptlessScanCursorV1 {
            next_height: 1,
            anchor_hash: None,
        }
        .validate()
        .is_err());
        assert!(parse_hex_32(&"11".repeat(32)).is_ok());
        assert!(parse_hex_32(&"11".repeat(31)).is_err());
        assert!(parse_hex_32(&"zz".repeat(32)).is_err());
        assert!(parse_hex_bounded(&"11".repeat(9), 8).is_err());
    }

    #[test]
    fn scanner_schema_rejects_unknown_fields() {
        let response = serde_json::from_str::<ScanResponseDto>(
            r#"{"schema_version":1,"status":"ok","canonical":true,"unknown":1}"#,
        );
        assert!(response.is_err());
    }

    #[test]
    fn rpc_wire_version_is_not_a_consensus_header_version() {
        let rpc_wire_version = 2;
        let consensus_header_version = 3;
        assert_ne!(rpc_wire_version, consensus_header_version);
        assert_eq!(
            validate_consensus_header_version(consensus_header_version, consensus_header_version,),
            Ok(())
        );
        assert_eq!(
            validate_consensus_header_version(consensus_header_version, rpc_wire_version),
            Err(ChainAdapterError::InvalidEvidence)
        );
    }

    fn empty_past_tip_response(
        expected: &ExpectedDomIdentityV1,
        cursor: ScriptlessScanCursorV1,
    ) -> ScanResponseDto {
        ScanResponseDto {
            schema_version: SCRIPTLESS_SCAN_SCHEMA_V1,
            status: "ok".to_owned(),
            canonical: true,
            identity: IdentityDto {
                network: expected.network.clone(),
                network_magic: expected.network_magic,
                chain_id: hex::encode(expected.chain_id),
                genesis_hash: hex::encode(expected.genesis_hash),
                protocol_version: expected.protocol_version,
                range_proof_serialization_version: expected.range_proof_serialization_version,
                coinbase_maturity: 60,
                tip_height: 0,
                tip_hash: hex::encode(expected.genesis_hash),
            },
            requested_from: cursor.next_height,
            requested_to: cursor.next_height,
            served_from: cursor.next_height,
            served_to: None,
            request_anchor: cursor.anchor_hash.map(|block_hash| AnchorDto {
                height: cursor.next_height - 1,
                block_hash: hex::encode(block_hash),
            }),
            blocks: Vec::new(),
            continuation: None,
        }
    }

    #[test]
    fn page_validation_binds_identity_and_anchor() -> Result<(), ChainAdapterError> {
        let expected = identity()?;
        let cursor = ScriptlessScanCursorV1 {
            next_height: 1,
            anchor_hash: Some(expected.genesis_hash),
        };
        let page = validate_scan_response(
            &expected,
            cursor,
            cursor.next_height,
            empty_past_tip_response(&expected, cursor),
        )?;
        assert!(page.reached_snapshot_tip);
        assert_eq!(page.next_cursor, cursor);

        let mut wrong_identity = empty_past_tip_response(&expected, cursor);
        wrong_identity.identity.chain_id = hex::encode([0x99_u8; 32]);
        assert_eq!(
            validate_scan_response(&expected, cursor, cursor.next_height, wrong_identity),
            Err(ChainAdapterError::IdentityMismatch)
        );

        let mut wrong_anchor = empty_past_tip_response(&expected, cursor);
        wrong_anchor.request_anchor = Some(AnchorDto {
            height: 0,
            block_hash: hex::encode([0x88_u8; 32]),
        });
        assert_eq!(
            validate_scan_response(&expected, cursor, cursor.next_height, wrong_anchor),
            Err(ChainAdapterError::InvalidEvidence)
        );
        Ok(())
    }

    #[test]
    fn submit_state_is_closed_and_internally_consistent() -> Result<(), ChainAdapterError> {
        let hash = [0x51_u8; 32];
        let response = |state: &str, already_known, confirmed, relayed| SubmitResponseDto {
            accepted: true,
            relayed,
            tx_hash: Some(hex::encode(hash)),
            state: state.to_owned(),
            already_known,
            confirmed,
            _warning: None,
            error: None,
        };
        assert_eq!(
            validate_submission_response(response("new", false, false, true), hash)?.state(),
            SubmissionStateV1::New
        );
        assert_eq!(
            validate_submission_response(response("mempool", true, false, true), hash)?.state(),
            SubmissionStateV1::Mempool
        );
        let confirmed =
            validate_submission_response(response("confirmed", true, true, false), hash)?;
        assert_eq!(confirmed.state(), SubmissionStateV1::Confirmed);
        assert_eq!(confirmed.tx_hash(), hash);
        assert!(!confirmed.was_relayed());
        assert!(confirmed.is_economically_admitted());
        let receipt_digest = confirmed.receipt_digest_v1();
        validate_submission_receipt_facts_v1(
            hash,
            SubmissionStateV1::Confirmed,
            false,
            receipt_digest,
        )?;
        assert_eq!(
            validate_submission_receipt_facts_v1(
                hash,
                SubmissionStateV1::Confirmed,
                false,
                [0x81; 32],
            ),
            Err(ChainAdapterError::InvalidEvidence)
        );
        assert_eq!(
            validate_submission_response(response("new", false, false, false), hash),
            Err(ChainAdapterError::TemporarilyUnavailable)
        );
        assert_eq!(
            validate_submission_response(response("mempool", true, false, false), hash),
            Err(ChainAdapterError::TemporarilyUnavailable)
        );
        let confirmed_and_relayed =
            validate_submission_response(response("confirmed", true, true, true), hash)?;
        assert_eq!(confirmed_and_relayed.state(), SubmissionStateV1::Confirmed);
        assert!(confirmed_and_relayed.was_relayed());
        assert_eq!(
            validate_submission_response(response("unknown", false, false, false), hash),
            Err(ChainAdapterError::MalformedResponse)
        );
        Ok(())
    }
}

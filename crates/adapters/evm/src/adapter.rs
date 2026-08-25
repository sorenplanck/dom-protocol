//! The adapter itself: configuration, unsigned artifacts, observation.
//!
//! # Custody: there is none (I1)
//!
//! [`EvmAdapter::prepare_lock`] returns a **deterministic unsigned** call —
//! `to`, `value`, calldata, chain id and a gas hint. It contains no nonce, no
//! gas price, no signature and no key reference, and the adapter has no code
//! path that could add one: it never calls `eth_sendRawTransaction`,
//! `eth_sendTransaction`, `eth_sign` or `personal_*`, and no type in this crate
//! can hold a private key. Authorisation happens elsewhere, locally, by whoever
//! owns the funds.
//!
//! Determinism matters for I7: the same terms and the same adaptor point
//! produce byte-identical artifact bytes, so a retransmission after a crash is
//! byte-identical by construction rather than by bookkeeping.
//!
//! # Which logs belong to this settlement
//!
//! A `ConditionLockV2` deployment is shared. The adapter is configured for one
//! settlement (`session_id`, `terms_hash`, roster, asset, parties), so it must
//! decide which of the contract's logs are its own. It does that
//! cryptographically, never by heuristics:
//!
//! - a `LockOpened` log carries every term the event does not fix; the adapter
//!   reconstructs the full [`LockTerms`] from its configuration plus the event,
//!   re-derives `binding`, and accepts the lock **only if the derived binding
//!   equals the one the contract emitted**. A lock belonging to another session
//!   cannot match, because `session_id` and `terms_hash` are inside the
//!   preimage. Matching locks are remembered;
//! - a `Claimed` / `Refunded` log is accepted only for a remembered lock, and
//!   only if its `binding` topic equals the remembered one.
//!
//! Locks opened before the configured `start_block` (or before a restart) are
//! not discoverable this way, so [`EvmAdapter::track_lock`] exists to
//! re-register a known lock explicitly. [`EvmAdapter::prepare_lock`] registers
//! the lock it prepares automatically.
//!
//! # Finality and reorg
//!
//! Nothing is surfaced above the `finalized` height ([`crate::finality`]), and
//! a broken anchor produces [`ObservedEvent::Reorged`] plus a rewound cursor
//! ([`crate::reorg`]) instead of events. A reorg never erases a revealed scalar
//! ([`crate::revealed`]).

use std::collections::BTreeMap;
use std::sync::Mutex;

use counterparty_api::{
    AdapterError, AdaptorPointBytes, ChainCapabilities, ChainCursor, CounterpartyAdapter,
    CounterpartyChainId, FinalityPolicy, LockMechanism, NeutralTerms, ObservedEvent,
    OpaqueArtifact, RevealedSecretBytes, TimelockDomain, VerifiedOutcome, MAX_EVENTS_PER_OBSERVE,
};

use crate::abi::{concat_words, keccak256, selector, word_u128, MAX_CALLDATA_BYTES, SIG_OPEN};
use crate::attest::{
    attest_settlement_log_cached, extend_verified_chain, VerifiedChain, MAX_ANCESTRY_TOTAL,
};
use crate::binding::{
    adaptor_address, adaptor_address_of_scalar, derive_binding, derive_lock_id, Cut, Direction,
    LockTerms,
};
use crate::cursor::EvmCursor;
use crate::error::{RejectReason, Result};
use crate::evidence::{
    decode_settlement_log, terms_from_opened, EvidenceKind, EvmEvidence, SettlementLog,
    EVIDENCE_VERSION,
};
use crate::finality::{
    fetch_finalized, fetch_finalized_checked, FinalizedHead, REPORTED_MIN_CONFIRMATIONS,
};
use crate::reorg::{
    apply_rewind, detect, KnownHeaders, ReorgOutcome, RpcHeaders, MAX_REORG_DEPTH_CEILING,
};
use crate::revealed::RevealedRegistry;
use crate::rpc::{EthClient, JsonRpc, RpcLog};

/// Adapter version, bound into every artifact it produces (I10).
pub const ADAPTER_VERSION: u32 = 1;

/// Version of the unsigned-call artifact encoding.
pub const UNSIGNED_CALL_VERSION: u16 = 1;

/// Domain string for the neutral chain identifier.
pub const CHAIN_ID_DOMAIN: &str = "DOM-Interop/CounterpartyChainId/evm/v1";

/// Largest `eth_getLogs` window this adapter will request.
pub const MAX_PAGE_SIZE: u64 = 1024;

/// Ethereum mainnet chain id, rejected outright — see
/// [`EvmAdapterConfig::validate`].
pub const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;

/// Neutral chain identifier for an EVM chain.
///
/// `keccak256(CHAIN_ID_DOMAIN ‖ chain_id_be)`. Deliberately independent of the
/// contract address: it names the *chain*, and two deployments on the same
/// chain are the same chain.
pub fn evm_counterparty_chain_id(chain_id: u64) -> CounterpartyChainId {
    let mut pre = Vec::with_capacity(CHAIN_ID_DOMAIN.len() + 8);
    pre.extend_from_slice(CHAIN_ID_DOMAIN.as_bytes());
    pre.extend_from_slice(&chain_id.to_be_bytes());
    CounterpartyChainId(keccak256(&pre))
}

/// Everything the adapter needs to know before it touches a network.
///
/// The settlement-specific half (`session_id`, `terms_hash`, roster, parties)
/// is here rather than being taken from each call so that there is exactly one
/// source of truth; [`EvmAdapter::prepare_lock`] cross-checks the neutral terms
/// it is handed against it and fails closed on any disagreement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvmAdapterConfig {
    /// EVM chain id. Mainnet is rejected.
    pub chain_id: u64,
    /// `ConditionLockV2` / `ConditionLockERC20V2` address.
    pub contract: [u8; 20],
    /// keccak256 of the bytecode expected at `contract`.
    pub expected_code_hash: [u8; 32],
    /// DOM `TrustedChainIdV1`.
    pub dom_chain_id: [u8; 32],
    /// Settlement direction.
    pub direction: Direction,
    /// DOM `session_id`.
    pub session_id: [u8; 32],
    /// DOM `terms_hash`.
    pub terms_hash: [u8; 32],
    /// keccak256 over the ordered roster encoding.
    pub participants_hash: [u8; 32],
    /// `address(0)` for the native contract, the token for the ERC-20 one.
    pub asset: [u8; 20],
    /// The only address allowed to `claim`.
    pub beneficiary: [u8; 20],
    /// The address that will call `open` (`msg.sender`, bound into `lockId`).
    pub funder: [u8; 20],
    /// Lowest block that can contain this deployment's logs.
    pub start_block: u64,
    /// `eth_getLogs` window size.
    pub page_size: u64,
    /// Reorg tolerance; deeper reorgs fail closed.
    pub max_reorg_depth: u32,
    /// Gas limit hint carried in the unsigned artifact. Not a gas price and not
    /// a promise: the local signer decides.
    pub gas_limit_hint: u64,
}

impl EvmAdapterConfig {
    /// Rejects a configuration that could not possibly be safe.
    ///
    /// Judgement call, recorded here so it is visible: **mainnet is refused**.
    /// The project's ground rules forbid mainnet for this phase, and a
    /// configuration check is the only place that rule can be enforced
    /// mechanically rather than by discipline.
    pub fn validate(&self) -> Result<()> {
        if self.chain_id == 0 || self.chain_id == ETHEREUM_MAINNET_CHAIN_ID {
            return Err(AdapterError::InvalidState);
        }
        if self.contract == [0u8; 20] || self.expected_code_hash == [0u8; 32] {
            return Err(AdapterError::InvalidState);
        }
        if self.beneficiary == [0u8; 20] || self.funder == [0u8; 20] {
            return Err(AdapterError::InvalidState);
        }
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(AdapterError::InvalidState);
        }
        if self.max_reorg_depth == 0 || self.max_reorg_depth > MAX_REORG_DEPTH_CEILING {
            return Err(AdapterError::InvalidState);
        }
        Ok(())
    }

    /// **The** list of [`LockTerms`] fields this configuration names, and the
    /// only place that list is written down.
    ///
    /// Round 3 of the audit found this list existing twice — once in
    /// `EvmAdapter::check_terms_against_config` and once, inline and two rows
    /// shorter, in [`crate::evidence::EvmEvidence::verify_static`] — and the
    /// two copies had drifted by exactly `session_id` and `terms_hash`, the two
    /// fields that make a settlement *this* settlement. A record of another DOM
    /// session on the same deployment therefore verified. There is now one
    /// list, and both call sites consume it, so the copies cannot disagree
    /// because there are no copies.
    ///
    /// The `LockTerms` is destructured exhaustively on purpose: adding a field
    /// to [`LockTerms`] does not compile until that field is either compared
    /// here or explicitly named as per-lock, so the list cannot silently fall
    /// behind the struct either.
    ///
    /// Returns `false` on any disagreement. The two call sites report it with
    /// their own error — [`AdapterError::PreconditionUnsatisfied`] when a
    /// caller offers terms, [`AdapterError::EvidenceInvalid`] when a blob
    /// claims to be a fact about this settlement — so this predicate is
    /// deliberately not a `Result`.
    pub fn binds_terms(&self, terms: &LockTerms) -> bool {
        let LockTerms {
            dom_chain_id,
            direction,
            session_id,
            terms_hash,
            participants_hash,
            asset,
            // Per-lock, not per-configuration: a configuration names no amount,
            // no adaptor point and no deadline, so there is nothing here to
            // compare them against. `amount` and `deadline` come from the
            // neutral terms of one lock, and `adaptor_address` from one adaptor
            // point; all three are bound by `binding` and, for a claim, by the
            // `address(t·G)` re-derivation.
            amount: _,
            beneficiary,
            adaptor_address: _,
            deadline: _,
        } = terms;
        *dom_chain_id == self.dom_chain_id
            && *direction == self.direction.as_u8()
            && *session_id == self.session_id
            && *terms_hash == self.terms_hash
            && *participants_hash == self.participants_hash
            && *asset == self.asset
            && *beneficiary == self.beneficiary
    }

    /// Capabilities this adapter declares (I10).
    ///
    /// `min_confirmations` is reported as `0` on purpose: this adapter does not
    /// count confirmations, it reads the `finalized` tag. See
    /// [`crate::finality`].
    pub fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            supports_condition_lock: true,
            // ECDSA/Schnorr adaptor on the EVM leg is explicitly out of v1.
            supports_schnorr_adaptor: false,
            // No hashlock fallback here: it would link the two legs publicly.
            supports_hashlock_fallback: false,
            timelock_domain: TimelockDomain::Timestamp,
            finality: FinalityPolicy {
                min_confirmations: REPORTED_MIN_CONFIRMATIONS,
                max_reorg_depth: self.max_reorg_depth,
            },
        }
    }
}

/// A deterministic, unsigned EVM call.
///
/// Contains no nonce, no gas price, no signature. Two runs with the same inputs
/// produce identical bytes (I7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedEvmCall {
    /// Encoding version.
    pub version: u16,
    /// Chain the call is valid on.
    pub chain_id: u64,
    /// Destination contract.
    pub to: [u8; 20],
    /// `msg.value`, big-endian `uint256`. Zero for the ERC-20 contract.
    pub value: [u8; 32],
    /// Non-binding gas limit hint.
    pub gas_limit_hint: u64,
    /// `lockId` the call will create — supplied so the caller can correlate
    /// without decoding calldata.
    pub lock_id: [u8; 32],
    /// `binding` the call will create.
    pub binding: [u8; 32],
    /// ABI calldata.
    pub calldata: Vec<u8>,
}

impl UnsignedEvmCall {
    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(2 + 8 + 20 + 32 + 8 + 32 + 32 + 4 + self.calldata.len());
        o.extend_from_slice(&self.version.to_be_bytes());
        o.extend_from_slice(&self.chain_id.to_be_bytes());
        o.extend_from_slice(&self.to);
        o.extend_from_slice(&self.value);
        o.extend_from_slice(&self.gas_limit_hint.to_be_bytes());
        o.extend_from_slice(&self.lock_id);
        o.extend_from_slice(&self.binding);
        o.extend_from_slice(&(self.calldata.len() as u32).to_be_bytes());
        o.extend_from_slice(&self.calldata);
        o
    }

    /// Strict decode. The calldata length is validated against
    /// [`MAX_CALLDATA_BYTES`] before the buffer is allocated (I14), and
    /// trailing bytes are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let head = 2 + 8 + 20 + 32 + 8 + 32 + 32 + 4;
        if bytes.len() < head {
            return Err(AdapterError::EvidenceInvalid);
        }
        let mut c = Cut { b: bytes, at: 0 };
        let version = c.take_u16()?;
        if version != UNSIGNED_CALL_VERSION {
            return Err(AdapterError::VersionMismatch);
        }
        let chain_id = c.take_u64()?;
        let to = c.take20()?;
        let value = c.take32()?;
        let gas_limit_hint = c.take_u64()?;
        let lock_id = c.take32()?;
        let binding = c.take32()?;
        let len = c.take_u32()? as usize;
        crate::error::check_cap(len, MAX_CALLDATA_BYTES)?;
        if bytes.len() != head + len {
            return Err(AdapterError::EvidenceInvalid);
        }
        let calldata = c.take(len)?.to_vec();
        Ok(Self {
            version,
            chain_id,
            to,
            value,
            gas_limit_hint,
            lock_id,
            binding,
            calldata,
        })
    }
}

/// Calldata for `open(LockTerms)`.
///
/// `LockTerms` is a static tuple, so it is encoded inline: the payload is
/// exactly `selector ‖ 10 words`.
pub fn encode_open_calldata(terms: &LockTerms) -> Result<Vec<u8>> {
    let sel = selector(SIG_OPEN);
    let body = concat_words(&terms.abi_words())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&sel);
    out.extend_from_slice(&body);
    Ok(out)
}

/// What the adapter remembers about a lock it recognises as its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct TrackedLock {
    binding: [u8; 32],
    adaptor_address: [u8; 20],
    terms: LockTerms,
}

#[derive(Default)]
struct ObserverState {
    known: KnownHeaders,
    revealed: RevealedRegistry,
    tracked: BTreeMap<[u8; 32], TrackedLock>,
    /// Blocks proved, by following parent hashes, to be on the finalized chain.
    ///
    /// Shared across `observe` and `collect_evidence` so a live observer pays
    /// for each link once rather than once per log. Never a shortcut around a
    /// proof — only a memory of proofs already made. See [`crate::attest`].
    verified: VerifiedChain,
}

/// What a decoded log means for *this* settlement, decided without any I/O.
///
/// Separating this from the mutating step is what keeps a stranger's logs
/// cheap: a `ConditionLockV2` deployment is shared, anyone may open a lock on
/// it, and every such log arrives in this adapter's `eth_getLogs` page. Deciding
/// ownership is pure — a binding derivation and a map lookup — so it happens
/// *before* the attestation spends round trips. A third party can therefore
/// fill blocks with `LockOpened` logs without costing this observer a single
/// extra RPC call.
enum Resolved {
    /// Another session's log on the same deployment. Skip it, silently.
    Foreign,
    /// A `LockOpened` for this settlement. Boxed because `LockTerms` dwarfs
    /// every other variant and this enum is returned by value per log.
    Opened(Box<OpenedLock>),
    /// A `Claimed` for a lock this observer tracks.
    Claimed {
        lock_id: [u8; 32],
        t: [u8; 32],
        adaptor_address: [u8; 20],
    },
    /// A `Refunded` for a lock this observer tracks.
    Refunded { lock_id: [u8; 32] },
}

/// The payload of [`Resolved::Opened`].
struct OpenedLock {
    lock_id: [u8; 32],
    binding: [u8; 32],
    terms: LockTerms,
}

/// EVM counterparty adapter.
pub struct EvmAdapter<R: JsonRpc> {
    cfg: EvmAdapterConfig,
    rpc: R,
    state: Mutex<ObserverState>,
}

impl<R: JsonRpc> EvmAdapter<R> {
    /// Builds an adapter over a transport. The configuration is validated
    /// eagerly, before any I/O is possible.
    pub fn new(cfg: EvmAdapterConfig, rpc: R) -> Result<Self> {
        cfg.validate()?;
        let state = ObserverState {
            known: KnownHeaders::with_capacity(cfg.max_reorg_depth as usize),
            revealed: RevealedRegistry::new(),
            tracked: BTreeMap::new(),
            verified: VerifiedChain::new(),
        };
        Ok(Self {
            cfg,
            rpc,
            state: Mutex::new(state),
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &EvmAdapterConfig {
        &self.cfg
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ObserverState>> {
        self.state
            .lock()
            .map_err(|_| AdapterError::AdapterUnavailable)
    }

    /// Re-registers a lock this adapter should recognise.
    ///
    /// Needed after a restart, or when the `LockOpened` log sits below
    /// `start_block`. The terms are re-derived into a binding and `lockId`
    /// locally, so a caller cannot register a lock that does not exist under
    /// this configuration.
    pub fn track_lock(&self, terms: &LockTerms) -> Result<([u8; 32], [u8; 32])> {
        self.check_terms_against_config(terms)?;
        let binding = derive_binding(self.cfg.chain_id, &self.cfg.contract, terms)?;
        let lock_id = derive_lock_id(&binding, &self.cfg.funder)?;
        let mut st = self.lock_state()?;
        st.tracked.insert(
            lock_id,
            TrackedLock {
                binding,
                adaptor_address: terms.adaptor_address,
                terms: *terms,
            },
        );
        Ok((binding, lock_id))
    }

    /// The configured-terms comparison, in the caller-facing dialect: terms a
    /// caller offers must be this settlement's.
    ///
    /// The list itself lives in [`EvmAdapterConfig::binds_terms`], which
    /// [`crate::evidence::EvmEvidence::verify_static`] also consumes — see
    /// there for why it is one list and not two.
    fn check_terms_against_config(&self, terms: &LockTerms) -> Result<()> {
        if !self.cfg.binds_terms(terms) {
            return Err(AdapterError::PreconditionUnsatisfied);
        }
        Ok(())
    }

    /// The scalar published for `lock_id`, if this observer ever saw it.
    ///
    /// Survives reorgs; see [`crate::revealed`].
    pub fn revealed_secret(&self, lock_id: &[u8; 32]) -> Result<Option<RevealedSecretBytes>> {
        Ok(self.lock_state()?.revealed.get(lock_id))
    }

    /// Whether `lock_id`'s scalar is public knowledge as far as this observer
    /// is concerned. Never becomes `false` again.
    pub fn is_revealed(&self, lock_id: &[u8; 32]) -> Result<bool> {
        Ok(self.lock_state()?.revealed.is_revealed(lock_id))
    }

    /// The finalized head, with the precise reason when it cannot be had.
    ///
    /// [`CounterpartyAdapter::observe`] collapses every "cannot answer" onto
    /// [`AdapterError::AdapterUnavailable`], which is right for the core but
    /// useless to an operator. This accessor keeps the distinction:
    /// [`RejectReason::FinalizedTagUnavailable`] means *the endpoint does not
    /// serve the `finalized` tag at all*, which is a `BLOCKED_EXTERNAL`
    /// condition — a provider to replace, not a settlement to doubt — and is
    /// distinct from a transport failure or a malformed answer.
    ///
    /// There is still no fallback: this reports the reason, it does not soften
    /// the rule (A4-EVM).
    pub fn finalized_head_checked(&self) -> core::result::Result<FinalizedHead, RejectReason> {
        fetch_finalized_checked(&self.rpc)
    }

    /// Extends the observer's verified chain one bounded batch further down,
    /// towards `target_height`. Returns the lowest height now proved.
    ///
    /// The escape hatch behind [`RejectReason::AncestryProofTooDeep`]. Ancestry
    /// here is always a followed chain of parent hashes, so a cold process
    /// asked to verify something far below the finalized head cannot be served
    /// in one call. Rather than answering a weaker question — which is exactly
    /// the defect this design replaced — the adapter refuses and offers this:
    /// call it until the returned height reaches `target_height`, then retry.
    /// Work per call is bounded by
    /// [`crate::attest::MAX_ANCESTRY_WALK`]; every link it records was followed.
    ///
    /// A live observer never needs it: the blocks it walks past while catching
    /// up are recorded as it goes.
    pub fn extend_verified_ancestry(&self, target_height: u64) -> Result<u64> {
        let head = fetch_finalized(&self.rpc)?;
        let mut st = self.lock_state()?;
        extend_verified_chain(&self.rpc, target_height, &head, &mut st.verified)
            .map_err(AdapterError::from)
    }

    /// Number of links currently proved to be on the finalized chain.
    ///
    /// Exposed for tests and for an operator asking how much of the chain this
    /// observer has actually verified, rather than assumed.
    pub fn verified_links(&self) -> Result<usize> {
        Ok(self.lock_state()?.verified.len())
    }

    /// Chain-side preflight, run before any observation is surfaced:
    /// the endpoint serves the configured chain, and the configured address
    /// carries the configured bytecode.
    pub fn preflight(&self) -> Result<()> {
        let client = EthClient::new(&self.rpc);
        if client.chain_id()? != self.cfg.chain_id {
            return Err(AdapterError::EvidenceInvalid);
        }
        if client.code_hash(&self.cfg.contract)? != self.cfg.expected_code_hash {
            return Err(AdapterError::EvidenceInvalid);
        }
        Ok(())
    }

    /// Synchronous core of `prepare_lock`. Performs no I/O, so it is fully
    /// deterministic.
    pub fn prepare_lock_blocking(
        &self,
        terms: &NeutralTerms,
        adaptor_point: &AdaptorPointBytes,
    ) -> Result<OpaqueArtifact> {
        self.cfg
            .capabilities()
            .require(LockMechanism::ConditionLock)?;
        // One source of truth: the neutral terms must agree with what this
        // adapter was configured for.
        if terms.terms_hash != self.cfg.terms_hash || terms.settlement_id != self.cfg.session_id {
            return Err(AdapterError::PreconditionUnsatisfied);
        }
        if terms.amount == 0 {
            return Err(AdapterError::PreconditionUnsatisfied);
        }
        let adaptor = adaptor_address(&adaptor_point.0)?;
        if adaptor == [0u8; 20] {
            return Err(AdapterError::PreconditionUnsatisfied);
        }
        let lock_terms = LockTerms {
            dom_chain_id: self.cfg.dom_chain_id,
            direction: self.cfg.direction.as_u8(),
            session_id: self.cfg.session_id,
            terms_hash: self.cfg.terms_hash,
            participants_hash: self.cfg.participants_hash,
            asset: self.cfg.asset,
            amount: word_u128(terms.amount),
            beneficiary: self.cfg.beneficiary,
            adaptor_address: adaptor,
            deadline: terms.deadline,
        };
        let (binding, lock_id) = self.track_lock(&lock_terms)?;
        // Native contract: the value is the amount. ERC-20 contract: the value
        // must be zero, and the token is moved by `transferFrom`.
        let value = if self.cfg.asset == [0u8; 20] {
            word_u128(terms.amount)
        } else {
            [0u8; 32]
        };
        let call = UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: self.cfg.chain_id,
            to: self.cfg.contract,
            value,
            gas_limit_hint: self.cfg.gas_limit_hint,
            lock_id,
            binding,
            calldata: encode_open_calldata(&lock_terms)?,
        };
        Ok(OpaqueArtifact {
            chain: evm_counterparty_chain_id(self.cfg.chain_id),
            adapter_version: ADAPTER_VERSION,
            bytes: call.encode(),
        })
    }

    /// Synchronous core of `observe`.
    pub fn observe_blocking(
        &self,
        cursor: &ChainCursor,
        max: usize,
    ) -> Result<(Vec<ObservedEvent>, ChainCursor)> {
        // `max` is a caller hint; `MAX_EVENTS_PER_OBSERVE` is the hard ceiling
        // and is applied first (I14).
        let max = max.min(MAX_EVENTS_PER_OBSERVE);
        let cur = EvmCursor::decode(
            cursor,
            self.cfg.chain_id,
            &self.cfg.contract,
            self.cfg.start_block,
        )?;
        if max == 0 {
            return Ok((Vec::new(), cur.encode()));
        }
        self.preflight()?;
        let head = fetch_finalized(&self.rpc)?;

        // An endpoint whose finalized checkpoint sits below our anchor is behind
        // (or was swapped for a lagging one). That is unavailability, not a
        // reorg: reporting a reorg here would invalidate settled state because
        // a proxy hiccuped.
        if cur.last_seen_height().is_some_and(|h| h > head.height) {
            return Err(AdapterError::AdapterUnavailable);
        }

        let mut st = self.lock_state()?;

        // Continuity first: never scan on top of an orphaned anchor.
        let headers = RpcHeaders::new(&self.rpc);
        match detect(
            &headers,
            &st.known,
            &cur,
            self.cfg.start_block,
            self.cfg.max_reorg_depth,
        )? {
            ReorgOutcome::Continuous => {}
            ReorgOutcome::Reorg {
                from_height,
                anchor,
            } => {
                let rewound = apply_rewind(&cur, &mut st.known, from_height, anchor);
                // Only the reorg is reported: the caller must revalidate before
                // acting on anything from `from_height` upwards. Revealed
                // scalars are untouched — see `crate::revealed`.
                return Ok((
                    vec![ObservedEvent::Reorged { from_height }],
                    rewound.encode(),
                ));
            }
        }

        if cur.next_from_block > head.height {
            // Nothing final to look at yet.
            let mut c = cur;
            c.finalized_height = head.height;
            return Ok((Vec::new(), c.encode()));
        }

        self.scan(&mut st, cur, &head, max)
    }

    fn scan(
        &self,
        st: &mut ObserverState,
        cur: EvmCursor,
        head: &FinalizedHead,
        max: usize,
    ) -> Result<(Vec<ObservedEvent>, ChainCursor)> {
        let client = EthClient::new(&self.rpc);
        let topics = [
            EvidenceKind::Funded.topic0(),
            EvidenceKind::Claimed.topic0(),
            EvidenceKind::Refunded.topic0(),
        ];

        let mut events: Vec<ObservedEvent> = Vec::new();
        let mut from = cur.next_from_block;
        let mut scanned_through = from.saturating_sub(1);
        let mut anchor = cur.last_seen_block_hash;
        let mut emitted_through = 0u64;

        'pages: while from <= head.height {
            let to = from.saturating_add(self.cfg.page_size - 1).min(head.height);
            let page = client.logs(from, to, &self.cfg.contract, &topics)?;

            // Order and deduplicate before anything is interpreted: an endpoint
            // may legally answer out of order, and a proxy may answer twice.
            let mut ordered = page;
            ordered.sort_by_key(|l| (l.block_number, l.log_index));
            ordered.dedup_by_key(|l| l.dedupe_key());

            // Group by block so the cursor only ever advances past whole blocks.
            let mut idx = 0usize;
            while idx < ordered.len() {
                let height = ordered[idx].block_number;
                let mut block_logs: Vec<&RpcLog> = Vec::new();
                while idx < ordered.len() && ordered[idx].block_number == height {
                    block_logs.push(&ordered[idx]);
                    idx += 1;
                }
                if height < from || height > to {
                    return Err(AdapterError::EvidenceInvalid);
                }
                // Finality gate: this is the last line of defence, on top of
                // clamping the scan window to the finalized height.
                crate::finality::require_final(height, head)?;

                let block = client
                    .block_by_number(height)?
                    .ok_or(AdapterError::AdapterUnavailable)?;
                // The budget is decided inside, *before* any attestation is
                // paid for, and a block that does not fit is left whole for the
                // next call — the cursor advances past whole blocks, so half a
                // block's events would be lost rather than deferred.
                let Some(block_events) =
                    self.decode_block(st, head, &block_logs, events.len(), max)?
                else {
                    break 'pages;
                };

                st.known.record(height, block.hash);
                if !block_events.is_empty() {
                    emitted_through = emitted_through.max(height);
                }
                events.extend(block_events);
                scanned_through = height;
                anchor = block.hash;

                if events.len() >= max {
                    break 'pages;
                }
            }

            // The page held no further usable block; the whole window is done.
            let tip = client
                .block_by_number(to)?
                .ok_or(AdapterError::AdapterUnavailable)?;
            st.known.record(to, tip.hash);
            scanned_through = to;
            anchor = tip.hash;
            from = to.saturating_add(1);
        }

        if scanned_through < cur.next_from_block {
            // Nothing was consumed; keep the cursor exactly where it was.
            let mut c = cur;
            c.finalized_height = head.height;
            return Ok((events, c.encode()));
        }
        let next = cur.advance_to(scanned_through, anchor, head.height, emitted_through);
        Ok((events, next.encode()))
    }

    /// Turns the logs of one block into neutral events.
    ///
    /// **A log that only exists in an `eth_getLogs` answer is never enough.**
    /// Every log here is put through [`attest_settlement_log`], which
    /// independently fetches the receipt, the transaction and the block, checks
    /// that the log is present in its own receipt at the expected `logIndex`,
    /// that the transaction was sent to this contract, that the canonical chain
    /// at that height carries that block, and that the block descends from the
    /// finalized head. Only then is the log decoded and interpreted.
    /// Turns one block's logs into neutral events, or reports that the block
    /// does not fit in what the caller asked for.
    ///
    /// `Ok(None)` means "this whole block is for the next call": blocks are
    /// atomic, because the cursor advances past whole blocks and half a block's
    /// events would be lost when it did.
    ///
    /// Order matters here, and it is the cheap work first:
    ///
    /// 1. decode and resolve every log — **pure**, no I/O. A stranger's lock on
    ///    the same deployment is discarded at this step, having cost nothing;
    /// 2. decide whether what remains fits the budget. If not, nothing in this
    ///    block is attested at all;
    /// 3. only then pay for the attestations.
    ///
    /// Doing (3) before (1) is what let a third party make this observer spend
    /// a receipt, a transaction, a block and an ancestry walk on every lock
    /// they opened, without ever producing an event the budget could restrain.
    fn decode_block(
        &self,
        st: &mut ObserverState,
        head: &FinalizedHead,
        logs: &[&RpcLog],
        already: usize,
        max: usize,
    ) -> Result<Option<Vec<ObservedEvent>>> {
        // 1. Pure.
        let mut ours: Vec<(&RpcLog, Resolved)> = Vec::new();
        for log in logs {
            let decoded = decode_settlement_log(log, &self.cfg.contract)?;
            match self.resolve(st, &decoded)? {
                Resolved::Foreign => continue,
                resolved => ours.push((log, resolved)),
            }
        }

        // 2. Budget, before a single round trip.
        let total = already.saturating_add(ours.len());
        if total > MAX_EVENTS_PER_OBSERVE {
            if already == 0 {
                // A single block cannot be delivered within the hard ceiling:
                // fail closed rather than truncate a block.
                return Err(AdapterError::BoundsExceeded);
            }
            return Ok(None);
        }
        if already > 0 && total > max {
            return Ok(None);
        }

        // 3. Pay.
        let mut out = Vec::new();
        for (log, resolved) in ours {
            // The block the scan grouped by is re-fetched inside the
            // attestation and compared against `log.blockHash` there, so that
            // a disagreement is reported as what it is — the log's block is not
            // the canonical block at that height — rather than as a generic
            // "invalid evidence".
            attest_settlement_log_cached(
                &self.rpc,
                &self.cfg.contract,
                log,
                head,
                &mut st.verified,
            )
            .map_err(AdapterError::from)?;

            let Some(event) = self.commit(st, resolved, log.block_number)? else {
                continue;
            };
            out.push(event);
        }
        Ok(Some(out))
    }

    /// Decides whether a decoded log belongs to this settlement. **Pure**: no
    /// I/O and no mutation, so it can run before an attestation is paid for.
    fn resolve(&self, st: &ObserverState, decoded: &SettlementLog) -> Result<Resolved> {
        match decoded {
            SettlementLog::Opened {
                lock_id, binding, ..
            } => {
                let terms = terms_from_opened(&self.cfg, decoded)?;
                let derived = derive_binding(self.cfg.chain_id, &self.cfg.contract, &terms)?;
                if &derived != binding {
                    // Belongs to a different session on the same deployment.
                    return Ok(Resolved::Foreign);
                }
                let derived_lock = derive_lock_id(&derived, &self.cfg.funder)?;
                if &derived_lock != lock_id {
                    // Same terms but a different funder: not our lock.
                    return Ok(Resolved::Foreign);
                }
                Ok(Resolved::Opened(Box::new(OpenedLock {
                    lock_id: *lock_id,
                    binding: *binding,
                    terms,
                })))
            }
            SettlementLog::Claimed {
                lock_id,
                binding,
                t,
                ..
            } => {
                let Some(tracked) = st.tracked.get(lock_id).copied() else {
                    return Ok(Resolved::Foreign);
                };
                if &tracked.binding != binding {
                    return Ok(Resolved::Foreign);
                }
                Ok(Resolved::Claimed {
                    lock_id: *lock_id,
                    t: *t,
                    adaptor_address: tracked.adaptor_address,
                })
            }
            SettlementLog::Refunded {
                lock_id, binding, ..
            } => {
                let Some(tracked) = st.tracked.get(lock_id).copied() else {
                    return Ok(Resolved::Foreign);
                };
                if &tracked.binding != binding {
                    return Ok(Resolved::Foreign);
                }
                Ok(Resolved::Refunded { lock_id: *lock_id })
            }
        }
    }

    /// Turns a resolved log into a neutral event, recording what the observer
    /// must remember. Runs only **after** the log has been attested.
    fn commit(
        &self,
        st: &mut ObserverState,
        resolved: Resolved,
        height: u64,
    ) -> Result<Option<ObservedEvent>> {
        match resolved {
            Resolved::Foreign => Ok(None),
            Resolved::Opened(opened) => {
                let OpenedLock {
                    lock_id,
                    binding,
                    terms,
                } = *opened;
                st.tracked.insert(
                    lock_id,
                    TrackedLock {
                        binding,
                        adaptor_address: terms.adaptor_address,
                        terms,
                    },
                );
                Ok(Some(ObservedEvent::LockOpened { lock_id, height }))
            }
            Resolved::Claimed {
                lock_id,
                t,
                adaptor_address,
            } => {
                // `t` must be canonical and must actually open the adaptor
                // point the lock committed to. Anything else is a lying
                // endpoint, and is fatal rather than filtered.
                let addr =
                    adaptor_address_of_scalar(&t).map_err(|_| AdapterError::EvidenceInvalid)?;
                if addr != adaptor_address {
                    return Err(AdapterError::EvidenceInvalid);
                }
                // Append-only: this survives every later reorg.
                st.revealed.record(lock_id, RevealedSecretBytes(t));
                Ok(Some(ObservedEvent::LockClaimed {
                    lock_id,
                    revealed: RevealedSecretBytes(t),
                    height,
                }))
            }
            Resolved::Refunded { lock_id } => {
                Ok(Some(ObservedEvent::LockRefunded { lock_id, height }))
            }
        }
    }

    /// Builds canonical evidence for the first finalized log of `kind` that
    /// concerns `lock_id`.
    ///
    /// Every field is taken from what the chain actually returned; nothing is
    /// assumed. Fails closed when the log is absent, not final, or when the
    /// lock is not one this adapter recognises.
    pub fn collect_evidence(&self, lock_id: &[u8; 32], kind: EvidenceKind) -> Result<EvmEvidence> {
        self.preflight()?;
        let head = fetch_finalized(&self.rpc)?;
        let client = EthClient::new(&self.rpc);
        let code_hash = client.code_hash(&self.cfg.contract)?;

        let tracked = {
            let st = self.lock_state()?;
            st.tracked.get(lock_id).copied()
        }
        .ok_or(AdapterError::PreconditionUnsatisfied)?;

        let finalized_block = client
            .block_by_number(head.height)?
            .ok_or(AdapterError::AdapterUnavailable)?;

        let mut from = self.cfg.start_block;
        while from <= head.height {
            let to = from.saturating_add(self.cfg.page_size - 1).min(head.height);
            let mut page = client.logs(from, to, &self.cfg.contract, &[kind.topic0()])?;
            page.sort_by_key(|l| (l.block_number, l.log_index));
            page.dedup_by_key(|l| l.dedupe_key());
            for log in &page {
                let decoded = decode_settlement_log(log, &self.cfg.contract)?;
                if decoded.kind() != kind || &decoded.lock_id() != lock_id {
                    continue;
                }
                let (_, binding, payload) = decoded.identity();
                if binding != tracked.binding {
                    continue;
                }
                crate::finality::require_final(log.block_number, &head)?;
                // Never mint evidence no verifier could ever walk.
                //
                // `verify_onchain` proves ancestry from the endpoint's current
                // head down to the observation and stops at
                // `MAX_ANCESTRY_TOTAL` links. A cold observer replaying deep
                // history would otherwise produce a record that is refused —
                // by every process, including this one — the moment anybody
                // tries to verify it. Collection and verification share one
                // ceiling so that cannot happen.
                if head
                    .height
                    .saturating_sub(log.block_number)
                    .gt(&MAX_ANCESTRY_TOTAL)
                {
                    return Err(AdapterError::BoundsExceeded);
                }
                // Same rule as observation: a log from `eth_getLogs` is only a
                // pointer. Evidence is built only once the receipt, the
                // transaction, the block and the finalized ancestry all
                // corroborate it independently.
                {
                    let mut st = self.lock_state()?;
                    attest_settlement_log_cached(
                        &self.rpc,
                        &self.cfg.contract,
                        log,
                        &head,
                        &mut st.verified,
                    )
                    .map_err(AdapterError::from)?;
                }
                return Ok(EvmEvidence {
                    version: EVIDENCE_VERSION,
                    kind,
                    chain_id: self.cfg.chain_id,
                    contract: self.cfg.contract,
                    code_hash,
                    funder: self.cfg.funder,
                    terms: tracked.terms,
                    binding: tracked.binding,
                    lock_id: *lock_id,
                    block_number: log.block_number,
                    block_hash: log.block_hash,
                    tx_hash: log.tx_hash,
                    log_index: log.log_index,
                    finalized_height: head.height,
                    finalized_block_hash: finalized_block.hash,
                    payload,
                });
            }
            from = to.saturating_add(1);
        }
        Err(AdapterError::PreconditionUnsatisfied)
    }

    /// Synchronous core of `verify_evidence`.
    ///
    /// Three halves, in this order, all mandatory:
    ///
    /// 1. **the endpoint identifies itself.** [`Self::preflight`] is the only
    ///    comparison in this crate against something that did not come out of
    ///    the chain-state answers: the configured chain id and the configured
    ///    deployed-bytecode hash. [`EvmEvidence::verify_static`] compares the
    ///    *blob's own* `chain_id` and `code_hash` fields to the configuration,
    ///    which is self-consistency on the blob and says nothing about who is
    ///    answering. Round 2 of the audit found this step missing here — the
    ///    whole on-chain half could run against an endpoint openly saying it
    ///    was a different chain running different bytecode, and still return
    ///    `Claimed`. `observe` and `collect_evidence` always ran it; this path
    ///    now does too;
    /// 2. the pure re-derivations ([`EvmEvidence::verify_static`]);
    /// 3. the chain-side corroboration ([`EvmEvidence::verify_onchain`]).
    pub fn verify_evidence_blocking(&self, evidence: &[u8]) -> Result<VerifiedOutcome> {
        self.verify_decoded(&EvmEvidence::decode(evidence)?)
    }

    /// The three mandatory steps, in their mandatory order, written once.
    ///
    /// Both public verification entry points funnel through here, so neither
    /// can end up running a different — or shorter — sequence than the other.
    fn verify_decoded(&self, e: &EvmEvidence) -> Result<VerifiedOutcome> {
        self.preflight()?;
        let outcome = e.verify_static(&self.cfg)?;
        e.verify_onchain(&self.rpc, &self.cfg)?;
        Ok(outcome)
    }

    /// [`Self::verify_evidence_blocking`], bound to **one lock**.
    ///
    /// [`EvmEvidence::verify_static`] can bind a record to this *settlement* —
    /// chain, deployment, session, terms hash, roster, asset, parties — but not
    /// to one *lock* of it: `amount`, `deadline` and the adaptor point are
    /// per-lock and have no counterpart in an [`EvmAdapterConfig`], so two
    /// locks of the same session with different amounts both verify. Round 3 of
    /// the audit rated that a P2 and it is documented in full in the
    /// [`crate::evidence`] module header.
    ///
    /// A caller that knows which lock it is waiting for closes the gap here, by
    /// naming it. The check is a comparison against a caller-supplied
    /// `lock_id`, not a lookup in this observer's memory, so a cold verifier
    /// that never saw the lock opened can use it — which is exactly what
    /// [`Self::collect_evidence`]'s tracked-lock gate could not offer.
    ///
    /// The `lock_id` itself is not taken on trust: it is re-derived from the
    /// record's own terms and funder by [`EvmEvidence::verify_static`], so
    /// naming one is naming the terms that produce it.
    pub fn verify_evidence_for_lock(
        &self,
        evidence: &[u8],
        lock_id: &[u8; 32],
    ) -> Result<VerifiedOutcome> {
        let e = EvmEvidence::decode(evidence)?;
        if &e.lock_id != lock_id {
            return Err(AdapterError::EvidenceInvalid);
        }
        self.verify_decoded(&e)
    }

    /// Pure half of evidence verification, with no I/O.
    ///
    /// Exposed because it is the half a property test can hammer, and because a
    /// caller that already trusts its own observation may want the derivation
    /// check without another round trip. The adapter's own
    /// [`CounterpartyAdapter::verify_evidence`] always runs both halves.
    pub fn verify_evidence_offline(&self, evidence: &[u8]) -> Result<VerifiedOutcome> {
        EvmEvidence::decode(evidence)?.verify_static(&self.cfg)
    }
}

impl<R: JsonRpc> CounterpartyAdapter for EvmAdapter<R> {
    fn chain_id(&self) -> CounterpartyChainId {
        evm_counterparty_chain_id(self.cfg.chain_id)
    }

    fn capabilities(&self) -> ChainCapabilities {
        self.cfg.capabilities()
    }

    fn adapter_version(&self) -> u32 {
        ADAPTER_VERSION
    }

    async fn prepare_lock(
        &self,
        terms: &NeutralTerms,
        adaptor_point: &AdaptorPointBytes,
    ) -> core::result::Result<OpaqueArtifact, AdapterError> {
        // Deliberately I/O-free: the artifact must be byte-identical across
        // restarts and across endpoints (I7), so it cannot depend on anything
        // a node might answer differently. Endpoint agreement is checked by
        // `preflight`, which `observe` runs.
        self.prepare_lock_blocking(terms, adaptor_point)
    }

    async fn observe(
        &self,
        cursor: &ChainCursor,
        max: usize,
    ) -> core::result::Result<(Vec<ObservedEvent>, ChainCursor), AdapterError> {
        self.observe_blocking(cursor, max)
    }

    async fn verify_evidence(
        &self,
        evidence: &[u8],
    ) -> core::result::Result<VerifiedOutcome, AdapterError> {
        self.verify_evidence_blocking(evidence)
    }
}

/// Fixtures shared by this crate's unit tests, its integration tests and the
/// integration workstream. Not a production path, but compiled unconditionally
/// so `tests/` can use it.
pub mod test_support {
    use super::*;
    use crate::mock::MockChain;

    /// Chain id used by every fixture (Anvil's default).
    pub const FIXTURE_CHAIN_ID: u64 = 31337;
    /// Contract address used by every fixture.
    pub const FIXTURE_CONTRACT: [u8; 20] = [0xC0; 20];
    /// Funder used by every fixture.
    pub const FIXTURE_FUNDER: [u8; 20] = [0xF0; 20];
    /// Beneficiary used by every fixture.
    pub const FIXTURE_BENEFICIARY: [u8; 20] = [0xBE; 20];

    /// A valid configuration matching a default [`MockChain`].
    pub fn sample_config() -> EvmAdapterConfig {
        EvmAdapterConfig {
            chain_id: FIXTURE_CHAIN_ID,
            contract: FIXTURE_CONTRACT,
            expected_code_hash: MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT).code_hash(),
            dom_chain_id: [0x11; 32],
            direction: Direction::DomToEvm,
            session_id: [0x22; 32],
            terms_hash: [0x33; 32],
            participants_hash: [0x44; 32],
            asset: [0u8; 20],
            beneficiary: FIXTURE_BENEFICIARY,
            funder: FIXTURE_FUNDER,
            start_block: 0,
            page_size: 8,
            max_reorg_depth: 32,
            gas_limit_hint: 300_000,
        }
    }

    /// Lock terms consistent with [`sample_config`]. The adaptor address is a
    /// placeholder; callers that need a real one overwrite it.
    pub fn sample_terms(cfg: &EvmAdapterConfig) -> LockTerms {
        LockTerms {
            dom_chain_id: cfg.dom_chain_id,
            direction: cfg.direction.as_u8(),
            session_id: cfg.session_id,
            terms_hash: cfg.terms_hash,
            participants_hash: cfg.participants_hash,
            asset: cfg.asset,
            amount: word_u128(1_000),
            beneficiary: cfg.beneficiary,
            adaptor_address: [0x66; 20],
            deadline: 1_800_000_000,
        }
    }

    /// Neutral terms consistent with [`sample_config`].
    pub fn sample_neutral(cfg: &EvmAdapterConfig, amount: u128, deadline: u64) -> NeutralTerms {
        NeutralTerms {
            terms_hash: cfg.terms_hash,
            settlement_id: cfg.session_id,
            amount,
            deadline,
        }
    }

    /// A canonical scalar derived from a byte seed (never zero, always `< n`).
    pub fn scalar_from_seed(seed: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[31] = seed.max(1);
        t[7] = seed;
        t
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::binding::adaptor_point_of_scalar;
    use crate::mock::MockChain;

    fn adapter(chain: MockChain) -> EvmAdapter<MockChain> {
        let mut cfg = sample_config();
        cfg.expected_code_hash = chain.code_hash();
        EvmAdapter::new(cfg, chain).expect("valid config")
    }

    #[test]
    fn config_validation_rejects_mainnet_and_nonsense() {
        let mut cfg = sample_config();
        assert_eq!(cfg.validate(), Ok(()));
        cfg.chain_id = ETHEREUM_MAINNET_CHAIN_ID;
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
        let mut cfg = sample_config();
        cfg.chain_id = 0;
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
        let mut cfg = sample_config();
        cfg.page_size = 0;
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
        let mut cfg = sample_config();
        cfg.page_size = MAX_PAGE_SIZE + 1;
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
        let mut cfg = sample_config();
        cfg.max_reorg_depth = 0;
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
        let mut cfg = sample_config();
        cfg.contract = [0u8; 20];
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
        let mut cfg = sample_config();
        cfg.expected_code_hash = [0u8; 32];
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
        let mut cfg = sample_config();
        cfg.funder = [0u8; 20];
        assert_eq!(cfg.validate(), Err(AdapterError::InvalidState));
    }

    #[test]
    fn capabilities_declare_no_confirmation_policy() {
        let caps = sample_config().capabilities();
        assert!(caps.supports_condition_lock);
        assert!(!caps.supports_schnorr_adaptor);
        assert!(!caps.supports_hashlock_fallback);
        assert_eq!(caps.timelock_domain, TimelockDomain::Timestamp);
        assert_eq!(
            caps.finality.min_confirmations, 0,
            "A4-EVM: finalized tag only"
        );
        assert_eq!(
            caps.require(LockMechanism::SchnorrAdaptor),
            Err(AdapterError::UnsupportedCapability)
        );
    }

    #[test]
    fn chain_identifier_is_domain_separated_and_contract_independent() {
        let a = evm_counterparty_chain_id(31337);
        let b = evm_counterparty_chain_id(31337);
        assert_eq!(a, b);
        assert_ne!(a, evm_counterparty_chain_id(11_155_111));
        // Not the raw chain id in disguise.
        assert_ne!(a.0[24..], 31337u64.to_be_bytes());
    }

    #[test]
    fn prepare_lock_is_deterministic_and_unsigned() {
        let a = adapter(MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT));
        let t = scalar_from_seed(3);
        let point = AdaptorPointBytes(adaptor_point_of_scalar(&t).expect("point"));
        let neutral = sample_neutral(a.config(), 5_000, 1_900_000_000);

        let one = a.prepare_lock_blocking(&neutral, &point).expect("artifact");
        let two = a.prepare_lock_blocking(&neutral, &point).expect("artifact");
        assert_eq!(one, two, "I7: retransmission must be byte-identical");
        assert_eq!(one.adapter_version, ADAPTER_VERSION);

        let call = UnsignedEvmCall::decode(&one.bytes).expect("decodes");
        assert_eq!(call.chain_id, FIXTURE_CHAIN_ID);
        assert_eq!(call.to, FIXTURE_CONTRACT);
        assert_eq!(call.value, word_u128(5_000), "native lock funds via value");
        // selector ++ 10 static words
        assert_eq!(call.calldata.len(), 4 + 320);
        assert_eq!(&call.calldata[..4], &selector(SIG_OPEN));
        // The artifact carries nothing that could authorise a spend.
        assert_eq!(call.encode(), one.bytes);
    }

    #[test]
    fn prepare_lock_rejects_terms_that_disagree_with_the_configuration() {
        let a = adapter(MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT));
        let t = scalar_from_seed(3);
        let point = AdaptorPointBytes(adaptor_point_of_scalar(&t).expect("point"));
        let mut neutral = sample_neutral(a.config(), 5_000, 1_900_000_000);
        neutral.terms_hash[0] ^= 1;
        assert_eq!(
            a.prepare_lock_blocking(&neutral, &point),
            Err(AdapterError::PreconditionUnsatisfied)
        );
        let mut neutral = sample_neutral(a.config(), 5_000, 1_900_000_000);
        neutral.settlement_id[0] ^= 1;
        assert_eq!(
            a.prepare_lock_blocking(&neutral, &point),
            Err(AdapterError::PreconditionUnsatisfied)
        );
        let neutral = sample_neutral(a.config(), 0, 1_900_000_000);
        assert_eq!(
            a.prepare_lock_blocking(&neutral, &point),
            Err(AdapterError::PreconditionUnsatisfied)
        );
    }

    #[test]
    fn prepare_lock_rejects_a_malformed_adaptor_point() {
        let a = adapter(MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT));
        let neutral = sample_neutral(a.config(), 5_000, 1_900_000_000);
        assert_eq!(
            a.prepare_lock_blocking(&neutral, &AdaptorPointBytes([0u8; 33])),
            Err(AdapterError::PreconditionUnsatisfied)
        );
    }

    #[test]
    fn erc20_configuration_never_attaches_value() {
        let chain = MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT);
        let mut cfg = sample_config();
        cfg.expected_code_hash = chain.code_hash();
        cfg.asset = [0x7A; 20];
        let a = EvmAdapter::new(cfg, chain).expect("valid");
        let t = scalar_from_seed(4);
        let point = AdaptorPointBytes(adaptor_point_of_scalar(&t).expect("point"));
        let neutral = sample_neutral(a.config(), 9_000, 1_900_000_000);
        let art = a.prepare_lock_blocking(&neutral, &point).expect("artifact");
        let call = UnsignedEvmCall::decode(&art.bytes).expect("decodes");
        assert_eq!(call.value, [0u8; 32], "ERC-20 open must carry no msg.value");
    }

    #[test]
    fn unsigned_call_codec_is_strict() {
        let call = UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: 31337,
            to: [1u8; 20],
            value: [2u8; 32],
            gas_limit_hint: 21_000,
            lock_id: [3u8; 32],
            binding: [4u8; 32],
            calldata: vec![9u8; 36],
        };
        let enc = call.encode();
        assert_eq!(UnsignedEvmCall::decode(&enc), Ok(call));

        let mut extended = enc.clone();
        extended.push(0);
        assert_eq!(
            UnsignedEvmCall::decode(&extended),
            Err(AdapterError::EvidenceInvalid),
            "trailing bytes must be rejected"
        );
        let mut truncated = enc.clone();
        truncated.pop();
        assert_eq!(
            UnsignedEvmCall::decode(&truncated),
            Err(AdapterError::EvidenceInvalid)
        );
        let mut bad_version = enc.clone();
        bad_version[1] = 9;
        assert_eq!(
            UnsignedEvmCall::decode(&bad_version),
            Err(AdapterError::VersionMismatch)
        );
        // A declared length beyond the cap must be refused before allocating.
        let mut huge = enc;
        let head = 2 + 8 + 20 + 32 + 8 + 32 + 32;
        huge[head..head + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            UnsignedEvmCall::decode(&huge),
            Err(AdapterError::BoundsExceeded)
        );
        assert!(UnsignedEvmCall::decode(&[]).is_err());
    }

    #[test]
    fn preflight_rejects_a_foreign_chain_or_foreign_bytecode() {
        let chain = MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT)
            .with_blocks(2)
            .finalize(2);
        let ok = adapter(chain.clone());
        assert_eq!(ok.preflight(), Ok(()));

        let wrong_chain = chain.clone().with_faults(crate::mock::Faults {
            wrong_chain_id: true,
            ..crate::mock::Faults::default()
        });
        assert_eq!(
            adapter(wrong_chain).preflight(),
            Err(AdapterError::EvidenceInvalid)
        );

        let wrong_code = chain.with_faults(crate::mock::Faults {
            wrong_code: true,
            ..crate::mock::Faults::default()
        });
        let mut cfg = sample_config();
        cfg.expected_code_hash = MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT).code_hash();
        let a = EvmAdapter::new(cfg, wrong_code).expect("valid config");
        assert_eq!(a.preflight(), Err(AdapterError::EvidenceInvalid));
    }
}

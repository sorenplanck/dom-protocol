//! Canonical, size-bounded, fully-bound EVM evidence.
//!
//! # The honesty rule
//!
//! Evidence records **what was actually observed**. No field is inferred, and
//! no field has a default. If the endpoint did not tell us the receipt status,
//! the evidence cannot be built; if it did not tell us which block the log was
//! in, the evidence cannot be built. That is why every parser in [`crate::rpc`]
//! rejects a missing member instead of substituting a zero.
//!
//! # What the evidence is bound to
//!
//! An [`EvmEvidence`] is only meaningful if it cannot be replayed anywhere
//! else. It therefore carries all of the following, and each row says how it is
//! established — **compared** against the configuration, or **re-derived** from
//! the record itself:
//!
//! | binding | how | why |
//! |---|---|---|
//! | `chain_id` | compared | the same contract on another chain is a different fact |
//! | `contract` | compared | another deployment is a different fact |
//! | `code_hash` | compared | the same address with different bytecode is a different contract |
//! | `terms.session_id`, `terms.terms_hash` | compared | ties the fact to **one DOM settlement** |
//! | `terms.dom_chain_id`, `terms.direction`, `terms.participants_hash`, `terms.asset`, `terms.beneficiary` | compared | the configured half of the terms |
//! | `terms.amount`, `terms.adaptor_address`, `terms.deadline` | **neither** | per-lock; no configuration counterpart exists to compare them against — see the limitation below. `adaptor_address` alone is pinned for a claim, by `address(t·G)` |
//! | `funder` | compared | part of the `lockId` preimage; anti-squatting |
//! | `binding`, `lock_id` | re-derived | never trusted |
//! | `block_number` / `block_hash` / `tx_hash` / `log_index` | chain-side | where the fact was observed |
//! | `finalized_height` / `finalized_block_hash` | chain-side | *which* finalized chain it was observed on |
//! | `payload` | re-derived | the scalar (claim) or the amount (funding/refund) |
//!
//! The distinction between the two columns is the whole of round 3's finding,
//! so it is worth stating plainly: **re-derivation is not comparison.**
//! `binding` and `lock_id` are computed from the record's own `terms`, so a
//! record whose `session_id`, `terms_hash`, `binding` and `lock_id` agree with
//! one another satisfies every re-derivation here — while naming a completely
//! different DOM settlement. Until round 3 the two settlement-naming rows were
//! in this table and not in the code, and a genuine, fully corroborated
//! settlement of another session on the same deployment verified. Both rows are
//! now compared, in `EvmEvidence::check_bound_to_config`, against the one list
//! in [`crate::adapter::EvmAdapterConfig::binds_terms`].
//!
//! Verification has two halves, both mandatory when going through the adapter,
//! and **only the first of them can decide whose settlement this is**:
//!
//! - [`EvmEvidence::verify_static`] — pure. Compares the record against the
//!   configuration, re-derives `binding` and `lock_id` from the terms, and for
//!   a claim re-derives `address(t·G)` and requires it to equal
//!   `terms.adaptorAddress`. This is the half that makes forging evidence
//!   equivalent to breaking keccak256 or the discrete log, and the only half
//!   that binds the DOM session.
//! - [`EvmEvidence::verify_onchain`] — asks the chain whether that log really
//!   is where the evidence says it is, whether the receipt succeeded, and
//!   whether the observation still descends, parent hash by parent hash, from
//!   the finalized head the endpoint names *now*. Every one of those questions
//!   is answered "yes" for another session's *real* settlement, and answered
//!   correctly, because that settlement really happened: `session_id` and
//!   `terms_hash` are never on the wire, so there is nothing there to compare
//!   them against. The session binding therefore cannot live in this half —
//!   see the note on [`EvmEvidence::verify_onchain`] itself.
//!
//! [`crate::adapter::EvmAdapter::verify_evidence_blocking`] runs the pure half
//! first, unconditionally. Reaching [`EvmEvidence::verify_onchain`] on its own
//! is not verification.
//!
//! # What a verdict does not say: *which lock* (open, and known)
//!
//! The comparison above binds a record to a **settlement**, never to a
//! **lock**. Three `LockTerms` fields — `amount`, `adaptor_address` and
//! `deadline` — have no counterpart in [`crate::adapter::EvmAdapterConfig`]:
//! they arrive per lock, from the neutral terms and the adaptor point, at
//! [`crate::adapter::EvmAdapter::prepare_lock`]. Nothing here can compare them
//! against anything, and so two locks of the *same* session with different
//! amounts or deadlines have different `lock_id`s and **both verify**. A
//! 1-wei `LockOpened` of this session verifies as `Funded`.
//!
//! This is stated rather than fixed, and the reasons are:
//!
//! - **the tracked-lock gate that [`crate::adapter::EvmAdapter::collect_evidence`]
//!   uses cannot be reused here.** Verification must work on a cold verifier
//!   that never observed the lock — the anchor travels inside the record, not
//!   in the observer's memory — and making the verdict depend on which locks
//!   this process happens to remember would make the same record verify in one
//!   process and fail in another;
//! - `counterparty_api::VerifiedOutcome::Funded` carries a height and no lock
//!   identity, so a consumer cannot correlate the verdict with the lock it was
//!   waiting for even if it wanted to. Closing that is an API change beyond
//!   this crate.
//!
//! What is available instead, and what a caller who knows which lock it is
//! waiting for should use, is
//! [`crate::adapter::EvmAdapter::verify_evidence_for_lock`]: the caller names
//! the `lock_id`, and the record must be that lock's. It needs no observer
//! state, so a cold verifier can use it too. Today's in-tree consumers are
//! unaffected by the gap: `f3-harness` acts only on
//! `counterparty_api::VerifiedOutcome::Claimed`, and for a claim the scalar
//! must additionally open *this* settlement's pre-signature.
//!
//! Neither half asks the endpoint to identify itself, and neither can: the
//! `chain_id` and `code_hash` in the blob are compared against the
//! configuration, which is self-consistency on the blob. That question belongs
//! to [`crate::adapter::EvmAdapter::preflight`], and
//! [`crate::adapter::EvmAdapter::verify_evidence_blocking`] runs it first —
//! `observe` and `collect_evidence` always did, and round 2 of the audit found
//! this path did not.
//!
//! # I6
//!
//! `payload` may hold the revealed scalar. [`EvmEvidence`] therefore has a
//! hand-written `Debug` that prints `<redacted>` for it, and no code path
//! anywhere in this crate formats it.

use counterparty_api::{AdapterError, RevealedSecretBytes, VerifiedOutcome};

use crate::abi::{
    decode_address, decode_u64, event_topic0, split_words, word_u64, CLAIMED_DATA_WORDS,
    LOCK_OPENED_DATA_WORDS, REFUNDED_DATA_WORDS, SETTLEMENT_EVENT_TOPICS, SIG_CLAIMED,
    SIG_LOCK_OPENED, SIG_REFUNDED,
};
use crate::adapter::EvmAdapterConfig;
use crate::attest::{attest_settlement_log_cached, verify_finalized_ancestry_deep, VerifiedChain};
use crate::binding::{
    adaptor_address_of_scalar, derive_binding, derive_lock_id, Cut, LockTerms, LOCK_TERMS_FIXED_LEN,
};
use crate::error::Result;
use crate::finality::fetch_finalized;
use crate::rpc::{EthClient, JsonRpc, RpcLog};

/// Evidence encoding version.
pub const EVIDENCE_VERSION: u16 = 1;

/// Exact encoded length of an [`EvmEvidence`]. Evidence is fixed-width, which
/// is the strongest possible size bound (I14).
pub const EVIDENCE_LEN: usize = 2  // version
    + 1                            // kind
    + 8                            // chain_id
    + 20                           // contract
    + 32                           // code_hash
    + 20                           // funder
    + LOCK_TERMS_FIXED_LEN         // terms
    + 32                           // binding
    + 32                           // lock_id
    + 8                            // block_number
    + 32                           // block_hash
    + 32                           // tx_hash
    + 4                            // log_index
    + 8                            // finalized_height
    + 32                           // finalized_block_hash
    + 32; // payload

/// What the evidence attests.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceKind {
    /// A `LockOpened` log: funds are locked.
    Funded,
    /// A `Claimed` log: the scalar was published and the lock settled.
    Claimed,
    /// A `Refunded` log: the lock expired and the funder was repaid.
    Refunded,
}

impl EvidenceKind {
    /// Wire value.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Funded => 1,
            Self::Claimed => 2,
            Self::Refunded => 3,
        }
    }

    /// Strict decode; unknown discriminants fail closed.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Funded),
            2 => Ok(Self::Claimed),
            3 => Ok(Self::Refunded),
            _ => Err(AdapterError::EvidenceInvalid),
        }
    }

    /// `topic0` of the log that produces this kind of evidence.
    pub fn topic0(self) -> [u8; 32] {
        match self {
            Self::Funded => event_topic0(SIG_LOCK_OPENED),
            Self::Claimed => event_topic0(SIG_CLAIMED),
            Self::Refunded => event_topic0(SIG_REFUNDED),
        }
    }

    /// Number of non-indexed data words the log must carry.
    pub fn data_words(self) -> usize {
        match self {
            Self::Funded => LOCK_OPENED_DATA_WORDS,
            Self::Claimed => CLAIMED_DATA_WORDS,
            Self::Refunded => REFUNDED_DATA_WORDS,
        }
    }
}

/// A canonical, fully-bound record of one observed settlement log.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EvmEvidence {
    /// Encoding version.
    pub version: u16,
    /// What is attested.
    pub kind: EvidenceKind,
    /// EVM chain id.
    pub chain_id: u64,
    /// Contract that emitted the log.
    pub contract: [u8; 20],
    /// keccak256 of that contract's deployed bytecode.
    pub code_hash: [u8; 32],
    /// `msg.sender` at `open`; part of the `lockId` preimage.
    pub funder: [u8; 20],
    /// Full lock terms, so `binding` and `lock_id` can be re-derived.
    pub terms: LockTerms,
    /// Recorded binding — re-derived on verification, never trusted.
    pub binding: [u8; 32],
    /// Recorded lock id — re-derived on verification, never trusted.
    pub lock_id: [u8; 32],
    /// Height of the block carrying the log.
    pub block_number: u64,
    /// Hash of that block.
    pub block_hash: [u8; 32],
    /// Hash of the transaction carrying the log.
    pub tx_hash: [u8; 32],
    /// Index of the log within the block.
    pub log_index: u32,
    /// Finalized height at the moment of observation.
    pub finalized_height: u64,
    /// Hash of the finalized block at that height.
    pub finalized_block_hash: [u8; 32],
    /// `Claimed` → the scalar `t`; `Funded`/`Refunded` → the amount.
    pub payload: [u8; 32],
}

impl core::fmt::Debug for EvmEvidence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // I6: `payload` can be the revealed scalar. It is never rendered.
        f.debug_struct("EvmEvidence")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("chain_id", &self.chain_id)
            .field("contract", &self.contract)
            .field("lock_id", &self.lock_id)
            .field("block_number", &self.block_number)
            .field("log_index", &self.log_index)
            .field("finalized_height", &self.finalized_height)
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl EvmEvidence {
    /// Canonical fixed-width encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(EVIDENCE_LEN);
        o.extend_from_slice(&self.version.to_be_bytes());
        o.push(self.kind.as_u8());
        o.extend_from_slice(&self.chain_id.to_be_bytes());
        o.extend_from_slice(&self.contract);
        o.extend_from_slice(&self.code_hash);
        o.extend_from_slice(&self.funder);
        o.extend_from_slice(&self.terms.encode_fixed());
        o.extend_from_slice(&self.binding);
        o.extend_from_slice(&self.lock_id);
        o.extend_from_slice(&self.block_number.to_be_bytes());
        o.extend_from_slice(&self.block_hash);
        o.extend_from_slice(&self.tx_hash);
        o.extend_from_slice(&self.log_index.to_be_bytes());
        o.extend_from_slice(&self.finalized_height.to_be_bytes());
        o.extend_from_slice(&self.finalized_block_hash);
        o.extend_from_slice(&self.payload);
        o
    }

    /// Strict decode. Exact length, known version, known kind, no trailing
    /// bytes. The length is checked before anything is allocated (I14).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EVIDENCE_LEN {
            return Err(AdapterError::EvidenceInvalid);
        }
        let mut c = Cut { b: bytes, at: 0 };
        let version = c.take_u16()?;
        if version != EVIDENCE_VERSION {
            return Err(AdapterError::VersionMismatch);
        }
        let kind = EvidenceKind::from_u8(c.take1()?)?;
        let chain_id = c.take_u64()?;
        let contract = c.take20()?;
        let code_hash = c.take32()?;
        let funder = c.take20()?;
        let terms = LockTerms::decode_fixed(c.take(LOCK_TERMS_FIXED_LEN)?)?;
        let out = Self {
            version,
            kind,
            chain_id,
            contract,
            code_hash,
            funder,
            terms,
            binding: c.take32()?,
            lock_id: c.take32()?,
            block_number: c.take_u64()?,
            block_hash: c.take32()?,
            tx_hash: c.take32()?,
            log_index: c.take_u32()?,
            finalized_height: c.take_u64()?,
            finalized_block_hash: c.take32()?,
            payload: c.take32()?,
        };
        if c.at != bytes.len() {
            return Err(AdapterError::EvidenceInvalid);
        }
        Ok(out)
    }

    /// Is this record a fact about *the settlement this adapter is configured
    /// for*, on *the deployment it is configured for*?
    ///
    /// Pure, cheap, and the only place either half of verification answers that
    /// question — so the two halves cannot answer it differently, and neither
    /// can be reached without it. The settlement half of the list is
    /// [`EvmAdapterConfig::binds_terms`], shared verbatim with
    /// [`crate::adapter::EvmAdapter::track_lock`].
    ///
    /// Re-deriving `binding` and `lock_id` is *not* a substitute for this, and
    /// round 3 of the audit is the proof: both are computed from the record's
    /// own `terms`, so a blob whose `session_id`, `terms_hash`, `binding` and
    /// `lock_id` agree with one another passes every re-derivation. That shows
    /// the blob is internally coherent; only a comparison against the
    /// configuration shows it is coherent with *this* adapter.
    fn check_bound_to_config(&self, cfg: &EvmAdapterConfig) -> Result<()> {
        // Deployment bindings.
        if self.chain_id != cfg.chain_id
            || self.contract != cfg.contract
            || self.code_hash != cfg.expected_code_hash
        {
            return Err(AdapterError::EvidenceInvalid);
        }
        // Settlement bindings: the whole configured half of `LockTerms`,
        // `session_id` and `terms_hash` included, plus the funder — which is
        // not a term but is part of the `lockId` preimage.
        if !cfg.binds_terms(&self.terms) || self.funder != cfg.funder {
            return Err(AdapterError::EvidenceInvalid);
        }
        Ok(())
    }

    /// Pure verification: everything that can be re-derived, is.
    ///
    /// Returns the neutral outcome only when every binding holds.
    pub fn verify_static(&self, cfg: &EvmAdapterConfig) -> Result<VerifiedOutcome> {
        if self.version != EVIDENCE_VERSION {
            return Err(AdapterError::VersionMismatch);
        }
        self.check_bound_to_config(cfg)?;
        // Nothing may be zero where a hash is required: a zeroed field is the
        // shape a "defaulted" field has, and defaults are forbidden here.
        if self.block_hash == [0u8; 32]
            || self.tx_hash == [0u8; 32]
            || self.finalized_block_hash == [0u8; 32]
        {
            return Err(AdapterError::EvidenceInvalid);
        }
        // Re-derive, never trust.
        let binding = derive_binding(self.chain_id, &self.contract, &self.terms)?;
        if binding != self.binding {
            return Err(AdapterError::EvidenceInvalid);
        }
        let lock_id = derive_lock_id(&binding, &self.funder)?;
        if lock_id != self.lock_id {
            return Err(AdapterError::EvidenceInvalid);
        }
        // Finality: the observation must sit at or below the checkpoint it
        // claims. Nothing above the finalized height is ever a verified fact.
        if self.block_number > self.finalized_height {
            return Err(AdapterError::PreconditionUnsatisfied);
        }
        match self.kind {
            EvidenceKind::Claimed => {
                // The strongest re-derivation available: the scalar must
                // actually open the adaptor point the terms committed to.
                let addr = adaptor_address_of_scalar(&self.payload)
                    .map_err(|_| AdapterError::EvidenceInvalid)?;
                if addr != self.terms.adaptor_address {
                    return Err(AdapterError::EvidenceInvalid);
                }
                Ok(VerifiedOutcome::Claimed {
                    revealed: RevealedSecretBytes(self.payload),
                    height: self.block_number,
                })
            }
            EvidenceKind::Funded => {
                if self.payload != self.terms.amount {
                    return Err(AdapterError::EvidenceInvalid);
                }
                Ok(VerifiedOutcome::Funded {
                    height: self.block_number,
                })
            }
            EvidenceKind::Refunded => {
                if self.payload != self.terms.amount {
                    return Err(AdapterError::EvidenceInvalid);
                }
                Ok(VerifiedOutcome::Refunded {
                    height: self.block_number,
                })
            }
        }
    }

    /// Chain-side verification: is the log really where the evidence says?
    ///
    /// # This half cannot decide *whose* settlement it is
    ///
    /// Stated here because round 3 of the audit turned on it. Every comparison
    /// below is evidence-against-chain or evidence-against-itself; the only
    /// configuration field it reads is `cfg.contract`. `session_id` and
    /// `terms_hash` are **not on the wire at all** — the contract never emits
    /// them, they exist only inside the `binding` preimage — so a real
    /// settlement of another DOM session on this deployment satisfies every
    /// check here, *correctly*: the log genuinely carries that session's
    /// `lock_id` and `binding`, exactly as its record says. There is nothing
    /// here to compare a session against, which is why the session binding
    /// lives in [`Self::verify_static`] and nowhere else, and why
    /// [`crate::adapter::EvmAdapter::verify_evidence_blocking`] runs that half
    /// first and unconditionally. **A caller that reaches this method directly
    /// has not verified the evidence.**
    ///
    /// Checked here, all fail-closed: the finalized checkpoint is real and at
    /// least as high as the one recorded; the block at `block_number` still has
    /// `block_hash`; the receipt exists, succeeded, and points at the same
    /// block and transaction; a log with the expected emitter, `topic0`, topic
    /// arity, `lockId`, `binding` and payload exists at `log_index`, and is not
    /// marked `removed`.
    ///
    /// # Ancestry is proved from the endpoint's *current* head, every time
    ///
    /// An earlier version of this method proved ancestry between two values it
    /// read out of the evidence blob — the observation's block and the
    /// checkpoint recorded beside it. Round 2 of the audit showed that this
    /// establishes nothing: at gap 0 the two are the same block and the "proof"
    /// is a hash compared to itself with no round trip at all, and at any other
    /// gap it only re-proves that the attacker's own fork is internally linked,
    /// which every fork is. The same version then *forgave*
    /// `AncestryProofTooDeep` from the head-side walk, so waiting 256 blocks
    /// left the endpoint's canonical height index — the one question
    /// [`crate::attest`] says proves nothing — as the only thing tying the
    /// observation to the chain.
    ///
    /// Both ends of the walk now come from the endpoint, not from the blob:
    ///
    /// - the upper end is the finalized head the endpoint names on this call;
    /// - the lower end is the observation's block hash.
    ///
    /// [`verify_finalized_ancestry_deep`] follows every link between them, in
    /// bounded batches, in two segments — head down to the checkpoint the
    /// evidence recorded, then on down to the observation — so the checkpoint
    /// is *proved to be on the endpoint's finalized chain* rather than merely
    /// read out of the blob. There is no branch that accepts on anything less.
    /// Each segment stops at [`crate::attest::MAX_ANCESTRY_TOTAL`] links and
    /// refuses with [`AdapterError::BoundsExceeded`] — a stated liveness
    /// ceiling, matched by the one
    /// [`crate::adapter::EvmAdapter::collect_evidence`] enforces on the whole
    /// distance, so this crate cannot mint evidence it cannot verify.
    ///
    /// The price of that ceiling is real and is the cost of closing the
    /// finding: a record verified *statelessly* stops verifying once the
    /// finalized head has moved more than `MAX_ANCESTRY_TOTAL` blocks past the
    /// observation, and the answer then is `BoundsExceeded` — "I could not
    /// prove it in one call" — never `Ok`. The remedy is
    /// [`Self::verify_onchain_cached`], below.
    ///
    /// Verification keeps its **own, fresh** [`VerifiedChain`]: a verifier may
    /// not answer out of a proof it made earlier for something else. A caller
    /// that wants the light-client behaviour — amortising the walk across many
    /// verifications — asks for it explicitly with
    /// [`Self::verify_onchain_cached`].
    ///
    /// The log found through `eth_getLogs` is then put through
    /// [`attest_settlement_log_cached`], which re-establishes the whole chain of
    /// independent corroboration — receipt (and the log's presence *inside* it),
    /// transaction, canonical block, finalized ancestry. Verification of
    /// evidence is exactly as strict as its collection was; nothing is taken on
    /// the strength of a `eth_getLogs` answer alone.
    pub fn verify_onchain<R: JsonRpc + ?Sized>(
        &self,
        rpc: &R,
        cfg: &EvmAdapterConfig,
    ) -> Result<()> {
        let mut chain = VerifiedChain::new();
        self.verify_onchain_cached(rpc, cfg, &mut chain)
    }

    /// [`Self::verify_onchain`] against a caller-owned [`VerifiedChain`].
    ///
    /// Every check is identical; the only difference is that the ancestry walk
    /// may reuse links this chain has already followed — and, because a
    /// [`VerifiedChain`] carries the identity of the chain its links belong to
    /// and is reconciled with the head on every call, reusing them is a memory
    /// of a proof rather than a substitute for one.
    ///
    /// This is how a long-lived verifier keeps evidence verifiable past
    /// [`crate::attest::MAX_ANCESTRY_TOTAL`] blocks of age: it extends its chain
    /// as the head moves (see
    /// [`crate::adapter::EvmAdapter::extend_verified_ancestry`]) instead of
    /// re-walking the whole distance on every call.
    pub fn verify_onchain_cached<R: JsonRpc + ?Sized>(
        &self,
        rpc: &R,
        cfg: &EvmAdapterConfig,
        chain: &mut VerifiedChain,
    ) -> Result<()> {
        let client = EthClient::new(rpc);

        // The chain must still serve `finalized`, and must be at least as far
        // along as the evidence claims. A checkpoint from the future is a lie.
        let head = fetch_finalized(rpc)?;
        if self.finalized_height > head.height {
            return Err(AdapterError::EvidenceInvalid);
        }
        let finalized_block = client
            .block_by_number(self.finalized_height)?
            .ok_or(AdapterError::EvidenceInvalid)?;
        if finalized_block.hash != self.finalized_block_hash {
            return Err(AdapterError::EvidenceInvalid);
        }

        // The containing block must still be the block we saw.
        let block = client
            .block_by_number(self.block_number)?
            .ok_or(AdapterError::EvidenceInvalid)?;
        if block.hash != self.block_hash {
            return Err(AdapterError::ReorgDetected);
        }

        // The ancestry proof, rooted in the head the endpoint just named.
        //
        // Neither of the two checks above is a proof of anything: both are the
        // endpoint answering a question about its own canonical height index.
        // These are the lines that decide whether the observation is on the
        // chain the endpoint currently calls final, and they decide it by
        // following every parent hash in between.
        //
        // Two segments of one walk, upper first:
        //
        //   head ──► finalized_height  the checkpoint this evidence recorded is
        //                              a block on the endpoint's finalized
        //                              chain, not merely a hash the blob
        //                              carries;
        //   finalized_height ──► block_number   and the observation descends
        //                              from it.
        //
        // The second segment resumes from the frontier the first left behind,
        // so together they cost exactly one walk from the head to the
        // observation — and asking for the checkpoint as a *proof* rather than
        // as a cache lookup keeps this correct for a warm caller whose
        // retention window has already evicted that height.
        verify_finalized_ancestry_deep(
            rpc,
            self.finalized_height,
            &self.finalized_block_hash,
            &head,
            chain,
        )
        .map_err(AdapterError::from)?;
        verify_finalized_ancestry_deep(rpc, self.block_number, &self.block_hash, &head, chain)
            .map_err(AdapterError::from)?;

        // The transaction must have succeeded, in that block.
        let receipt = client
            .receipt(&self.tx_hash)?
            .ok_or(AdapterError::EvidenceInvalid)?;
        if receipt.status != 1
            || receipt.block_number != self.block_number
            || receipt.block_hash != self.block_hash
        {
            return Err(AdapterError::EvidenceInvalid);
        }

        // The log must be there, and must say what the evidence says it says.
        let logs = client.logs(
            self.block_number,
            self.block_number,
            &cfg.contract,
            &[self.kind.topic0()],
        )?;
        let log = logs
            .iter()
            .find(|l| l.log_index == self.log_index && l.tx_hash == self.tx_hash)
            .ok_or(AdapterError::EvidenceInvalid)?;
        if log.removed || log.block_hash != self.block_hash {
            return Err(AdapterError::EvidenceInvalid);
        }
        // Independent corroboration: receipt (with the log inside it),
        // transaction, canonical block, finalized ancestry.
        //
        // **Nothing is tolerated here.** The previous version forgave
        // `AncestryProofTooDeep` from this call, which is what made waiting buy
        // acceptance. It cannot arise any more: the ancestry above already
        // closed the gap into `chain`, so this attestation finds the link
        // already proved. If it somehow does arise, it is a refusal like any
        // other.
        attest_settlement_log_cached(rpc, &cfg.contract, log, &head, chain)
            .map_err(AdapterError::from)?;

        let decoded = decode_settlement_log(log, &cfg.contract)?;
        let (lock_id, binding, payload) = decoded.identity();
        if lock_id != self.lock_id || binding != self.binding || payload != self.payload {
            return Err(AdapterError::EvidenceInvalid);
        }
        if decoded.kind() != self.kind {
            return Err(AdapterError::EvidenceInvalid);
        }
        Ok(())
    }
}

/// A decoded settlement log.
///
/// `Claimed.t` is a revealed scalar, so this type has a hand-written `Debug`
/// that redacts it (I6).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettlementLog {
    /// `LockOpened`.
    Opened {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Binding hash.
        binding: [u8; 32],
        /// Funder (indexed).
        funder: [u8; 20],
        /// Beneficiary.
        beneficiary: [u8; 20],
        /// Asset (`address(0)` for native).
        asset: [u8; 20],
        /// Locked amount, big-endian `uint256`.
        amount: [u8; 32],
        /// `address(T)`.
        adaptor_address: [u8; 20],
        /// Refund deadline (UNIX timestamp).
        deadline: u64,
    },
    /// `Claimed`.
    Claimed {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Binding hash.
        binding: [u8; 32],
        /// Beneficiary (indexed).
        beneficiary: [u8; 20],
        /// The revealed scalar. Never rendered.
        t: [u8; 32],
    },
    /// `Refunded`.
    Refunded {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Binding hash.
        binding: [u8; 32],
        /// Funder (indexed).
        funder: [u8; 20],
        /// Refunded amount, big-endian `uint256`.
        amount: [u8; 32],
    },
}

impl core::fmt::Debug for SettlementLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Opened { lock_id, .. } => write!(f, "Opened({})", short(lock_id)),
            Self::Claimed { lock_id, .. } => {
                write!(f, "Claimed({}, t=<redacted>)", short(lock_id))
            }
            Self::Refunded { lock_id, .. } => write!(f, "Refunded({})", short(lock_id)),
        }
    }
}

fn short(id: &[u8; 32]) -> String {
    format!("{:02x}{:02x}..", id[0], id[1])
}

impl SettlementLog {
    /// Which kind of evidence this log produces.
    pub fn kind(&self) -> EvidenceKind {
        match self {
            Self::Opened { .. } => EvidenceKind::Funded,
            Self::Claimed { .. } => EvidenceKind::Claimed,
            Self::Refunded { .. } => EvidenceKind::Refunded,
        }
    }

    /// `(lock_id, binding, payload)` — the triple every kind shares.
    pub fn identity(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        match self {
            Self::Opened {
                lock_id,
                binding,
                amount,
                ..
            } => (*lock_id, *binding, *amount),
            Self::Claimed {
                lock_id,
                binding,
                t,
                ..
            } => (*lock_id, *binding, *t),
            Self::Refunded {
                lock_id,
                binding,
                amount,
                ..
            } => (*lock_id, *binding, *amount),
        }
    }

    /// Lock identifier.
    pub fn lock_id(&self) -> [u8; 32] {
        self.identity().0
    }
}

/// Strictly decodes one settlement log.
///
/// Fail-closed on: wrong emitter, unknown `topic0`, wrong topic arity, wrong
/// data word count (truncated *or* padded), non-canonical address padding, and
/// `removed == true`.
pub fn decode_settlement_log(log: &RpcLog, contract: &[u8; 20]) -> Result<SettlementLog> {
    if &log.address != contract {
        return Err(AdapterError::EvidenceInvalid);
    }
    if log.removed {
        return Err(AdapterError::EvidenceInvalid);
    }
    if log.topics.len() != SETTLEMENT_EVENT_TOPICS {
        return Err(AdapterError::EvidenceInvalid);
    }
    let topic0 = log.topics[0];
    let lock_id = log.topics[1];
    let binding = log.topics[2];
    let third = decode_address(&log.topics[3])?;

    if topic0 == event_topic0(SIG_LOCK_OPENED) {
        let w = split_words(&log.data, LOCK_OPENED_DATA_WORDS)?;
        return Ok(SettlementLog::Opened {
            lock_id,
            binding,
            funder: third,
            beneficiary: decode_address(&w[0])?,
            asset: decode_address(&w[1])?,
            amount: w[2],
            adaptor_address: decode_address(&w[3])?,
            deadline: decode_u64(&w[4])?,
        });
    }
    if topic0 == event_topic0(SIG_CLAIMED) {
        let w = split_words(&log.data, CLAIMED_DATA_WORDS)?;
        return Ok(SettlementLog::Claimed {
            lock_id,
            binding,
            beneficiary: third,
            t: w[0],
        });
    }
    if topic0 == event_topic0(SIG_REFUNDED) {
        let w = split_words(&log.data, REFUNDED_DATA_WORDS)?;
        return Ok(SettlementLog::Refunded {
            lock_id,
            binding,
            funder: third,
            amount: w[0],
        });
    }
    Err(AdapterError::EvidenceInvalid)
}

/// Reconstructs the full [`LockTerms`] a `LockOpened` log implies, using the
/// adapter's static configuration for the fields the event does not carry.
///
/// The event carries only what the contract indexed or emitted; `domChainId`,
/// `direction`, `sessionId`, `termsHash` and `participantsHash` live in the
/// configuration. The reconstruction is then *proved* correct by re-deriving
/// the binding and comparing it to the one the contract emitted — if any
/// assumed field were wrong, the hash would not match.
pub fn terms_from_opened(cfg: &EvmAdapterConfig, log: &SettlementLog) -> Result<LockTerms> {
    let SettlementLog::Opened {
        beneficiary,
        asset,
        amount,
        adaptor_address,
        deadline,
        ..
    } = log
    else {
        return Err(AdapterError::EvidenceInvalid);
    };
    Ok(LockTerms {
        dom_chain_id: cfg.dom_chain_id,
        direction: cfg.direction.as_u8(),
        session_id: cfg.session_id,
        terms_hash: cfg.terms_hash,
        participants_hash: cfg.participants_hash,
        asset: *asset,
        amount: *amount,
        beneficiary: *beneficiary,
        adaptor_address: *adaptor_address,
        deadline: *deadline,
    })
}

/// Convenience: the amount word for a `u128`, as the evidence payload wants it.
pub fn amount_word(amount: u128) -> [u8; 32] {
    crate::abi::word_u128(amount)
}

/// Convenience: a deadline as an ABI word (used by tests and vector checks).
pub fn deadline_word(deadline: u64) -> [u8; 32] {
    word_u64(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::test_support::{sample_config, sample_terms};
    use crate::binding::adaptor_address_of_scalar as addr_of;

    fn scalar(n: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[31] = n;
        t[5] = n;
        t
    }

    fn claimed_evidence() -> (EvmEvidence, EvmAdapterConfig) {
        let cfg = sample_config();
        let t = scalar(9);
        let mut terms = sample_terms(&cfg);
        terms.adaptor_address = addr_of(&t).expect("canonical scalar");
        let binding = derive_binding(cfg.chain_id, &cfg.contract, &terms).expect("binding");
        let lock_id = derive_lock_id(&binding, &cfg.funder).expect("lock id");
        (
            EvmEvidence {
                version: EVIDENCE_VERSION,
                kind: EvidenceKind::Claimed,
                chain_id: cfg.chain_id,
                contract: cfg.contract,
                code_hash: cfg.expected_code_hash,
                funder: cfg.funder,
                terms,
                binding,
                lock_id,
                block_number: 5,
                block_hash: [0x51; 32],
                tx_hash: [0x52; 32],
                log_index: 0,
                finalized_height: 7,
                finalized_block_hash: [0x53; 32],
                payload: t,
            },
            cfg,
        )
    }

    #[test]
    fn encoding_is_fixed_width_and_round_trips() {
        let (e, _) = claimed_evidence();
        let enc = e.encode();
        assert_eq!(enc.len(), EVIDENCE_LEN);
        assert_eq!(EvmEvidence::decode(&enc), Ok(e));
    }

    #[test]
    fn decode_rejects_truncation_extension_and_bad_discriminants() {
        let (e, _) = claimed_evidence();
        let enc = e.encode();
        let mut short = enc.clone();
        short.pop();
        assert_eq!(
            EvmEvidence::decode(&short),
            Err(AdapterError::EvidenceInvalid)
        );
        let mut long = enc.clone();
        long.push(0);
        assert_eq!(
            EvmEvidence::decode(&long),
            Err(AdapterError::EvidenceInvalid),
            "trailing bytes must never be ignored"
        );
        let mut bad_version = enc.clone();
        bad_version[0] = 0xFF;
        assert_eq!(
            EvmEvidence::decode(&bad_version),
            Err(AdapterError::VersionMismatch)
        );
        let mut bad_kind = enc;
        bad_kind[2] = 9;
        assert_eq!(
            EvmEvidence::decode(&bad_kind),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn verify_static_accepts_a_well_formed_claim() {
        let (e, cfg) = claimed_evidence();
        assert_eq!(
            e.verify_static(&cfg),
            Ok(VerifiedOutcome::Claimed {
                revealed: RevealedSecretBytes(e.payload),
                height: 5
            })
        );
    }

    #[test]
    fn tampering_with_any_binding_is_rejected() {
        let (base, cfg) = claimed_evidence();

        let mut e = base;
        e.chain_id += 1;
        assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));

        let mut e = base;
        e.contract[0] ^= 1;
        assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));

        let mut e = base;
        e.code_hash[0] ^= 1;
        assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));

        let mut e = base;
        e.binding[0] ^= 1;
        assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));

        let mut e = base;
        e.lock_id[0] ^= 1;
        assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));

        let mut e = base;
        e.funder[0] ^= 1;
        assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));

        let mut e = base;
        e.terms.session_id[0] ^= 1;
        assert_eq!(
            e.verify_static(&cfg),
            Err(AdapterError::EvidenceInvalid),
            "session_id is inside the binding preimage"
        );

        let mut e = base;
        e.terms.terms_hash[0] ^= 1;
        assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));

        let mut e = base;
        e.payload[0] ^= 1;
        assert_eq!(
            e.verify_static(&cfg),
            Err(AdapterError::EvidenceInvalid),
            "a scalar that does not open the adaptor point must be rejected"
        );

        let mut e = base;
        e.block_hash = [0u8; 32];
        assert_eq!(
            e.verify_static(&cfg),
            Err(AdapterError::EvidenceInvalid),
            "a zeroed hash is a defaulted field"
        );
    }

    #[test]
    fn evidence_above_the_finalized_height_is_never_verified() {
        let (mut e, cfg) = claimed_evidence();
        e.block_number = e.finalized_height + 1;
        // Keep the derivations valid; only the finality relation changes.
        assert_eq!(
            e.verify_static(&cfg),
            Err(AdapterError::PreconditionUnsatisfied)
        );
    }

    #[test]
    fn debug_never_renders_the_payload() {
        let (e, _) = claimed_evidence();
        let rendered = format!("{e:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("payload: [9"));
        let l = SettlementLog::Claimed {
            lock_id: [1u8; 32],
            binding: [2u8; 32],
            beneficiary: [3u8; 20],
            t: [0xAB; 32],
        };
        let rl = format!("{l:?}");
        assert!(rl.contains("<redacted>"));
        assert!(!rl.contains("ab, ab"));
    }

    #[test]
    fn evidence_kind_discriminants_round_trip() {
        for k in [
            EvidenceKind::Funded,
            EvidenceKind::Claimed,
            EvidenceKind::Refunded,
        ] {
            assert_eq!(EvidenceKind::from_u8(k.as_u8()), Ok(k));
        }
        assert_eq!(EvidenceKind::from_u8(0), Err(AdapterError::EvidenceInvalid));
        assert_eq!(EvidenceKind::from_u8(4), Err(AdapterError::EvidenceInvalid));
        assert_ne!(
            EvidenceKind::Funded.topic0(),
            EvidenceKind::Claimed.topic0()
        );
        assert_eq!(EvidenceKind::Claimed.data_words(), 1);
        assert_eq!(EvidenceKind::Funded.data_words(), 5);
    }

    #[test]
    fn amount_and_deadline_helpers_match_the_abi() {
        assert_eq!(amount_word(1), crate::abi::word_u128(1));
        assert_eq!(deadline_word(7), crate::abi::word_u64(7));
    }
}

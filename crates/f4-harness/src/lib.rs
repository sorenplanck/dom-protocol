//! F4 harness — the `BondAdapter` of spec §7 over the audited
//! `ConditionLockV2` (D-017, D-F4.2/D-F4.3).
//!
//! One bond, one policy, one lock. The three spends map onto the three
//! F3-audited contract paths and NOTHING else:
//!
//! - lock = `open(LockTerms)` — funder is the solver (`msg.sender`);
//! - release = `refund(lockId)` — permissionless after the deadline,
//!   destination always the funder;
//! - slash = `claim(lockId, t)` — beneficiary-only, before the deadline,
//!   reveals the scalar.
//!
//! There is no third role and no privileged path (I12). This crate holds
//! no key: it builds deterministic unsigned artifacts and hands them to a
//! [`BondBroadcaster`] seam, exactly as the F3 harness does for the
//! settlement leg. The scalar an accepted slash carries is public by
//! construction, and this crate neither logs nor retains it (I6; spec
//! §3.2 rule 2): the claim artifact is rebuilt deterministically from the
//! caller's bytes on every offer, so byte-identical resend (I7) holds
//! without keeping `t` anywhere.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod journal;
mod verifier;

pub use verifier::RevealedScalarVerifier;

use adapter_evm::abi::{concat_words, selector, word_bytes32, word_u256, SIG_CLAIM, SIG_REFUND};
use adapter_evm::adapter::{encode_open_calldata, UNSIGNED_CALL_VERSION};
use adapter_evm::binding::{adaptor_address, adaptor_address_of_scalar, is_canonical_scalar};
use adapter_evm::evidence::amount_word;
use adapter_evm::rpc::JsonRpc;
use adapter_evm::{Direction, EvmAdapter, EvmAdapterConfig, LockTerms, UnsignedEvmCall};
use counterparty_api::{
    AdapterError, ChainCursor, ObservedEvent, RevealedSecretBytes, MAX_EVENTS_PER_OBSERVE,
};
use uspe::bond::{BondAdapter, BondEvent, BondObservation, BroadcastOutcome};
use uspe::objects::{AssuranceObjectError, AssurancePolicyV1, TimelockSpec};

/// Refusals and failures of the EVM bond adapter. Every arm is a named
/// refusal (I13); nothing is stubbed to succeed.
#[derive(Debug, thiserror::Error)]
pub enum BondError {
    /// The policy failed its own frozen validity rules (this includes
    /// collateral above the compensation cap, §7.3 — refused here, before
    /// any transaction is ever built).
    #[error("invalid assurance policy: {0}")]
    Policy(#[from] AssuranceObjectError),
    /// A policy deadline is not in the EVM venue's timestamp domain. A4:
    /// deadlines are never silently converted between domains.
    #[error("policy deadline outside the timestamp domain")]
    WrongTimelockDomain,
    /// `submit_bond` was offered a policy that is not byte-identical to
    /// the one this adapter was constructed for (single definition).
    #[error("policy does not match the configured bond")]
    PolicyMismatch,
    /// The lock id is not the configured bond's lock id.
    #[error("unknown bond lock id")]
    UnknownLock,
    /// Release refused: the bond release deadline has not passed on the
    /// bond chain's own clock.
    #[error("bond release deadline not reached")]
    DeadlineNotReached,
    /// Slash refused: the deadline has passed, so the contract's `claim`
    /// would revert (`Expired`). The slash-execution margin of spec §7.2
    /// exists precisely so an authorized slash never lands here.
    #[error("bond release deadline already passed")]
    DeadlineExpired,
    /// Slash refused: the scalar is outside `0 < t < n`.
    #[error("non-canonical scalar")]
    NonCanonicalScalar,
    /// Slash refused: `address(t*G)` does not match the lock's adaptor
    /// commitment — this scalar does not open this bond.
    #[error("scalar does not open the bond's adaptor commitment")]
    ScalarPointMismatch,
    /// The underlying chain adapter refused or failed.
    #[error("chain adapter: {0}")]
    Adapter(#[from] AdapterError),
}

/// Alias for this crate's fallible results.
pub type Result<T> = core::result::Result<T, BondError>;

/// Whatever authorises and broadcasts an unsigned artifact. The signing
/// boundary: implementations live outside this crate, and no key ever
/// enters it. Must be idempotent for byte-identical input (I7).
pub trait BondBroadcaster {
    /// Offers the exact artifact bytes.
    fn broadcast(&self, call: &UnsignedEvmCall) -> Result<BroadcastOutcome>;
}

/// The bond chain's wall clock (`TimelockDomain::Timestamp`), as the
/// chain reports it. Its own seam because neither the machine nor the
/// adapter owns wall-clock time.
pub trait BondClock {
    /// Current chain time, UNIX seconds.
    fn now_timestamp(&self) -> Result<u64>;
}

/// A clock that answers a fixed reading, moved by the test that owns it.
pub struct FixedClock(core::cell::Cell<u64>);

impl FixedClock {
    /// A clock reading `t` seconds.
    pub fn new(t: u64) -> Self {
        Self(core::cell::Cell::new(t))
    }
    /// Moves the clock to `t`.
    pub fn set(&self, t: u64) {
        self.0.set(t);
    }
}

impl BondClock for FixedClock {
    fn now_timestamp(&self) -> Result<u64> {
        Ok(self.0.get())
    }
}

/// Deployment identity of the bond lock: which contract, which parties,
/// which asset. The `asset` address is the deployment's declared binding
/// of the policy's 32-byte `bond_asset` registry id onto this chain —
/// declaring it here is what makes the mapping explicit and reviewable
/// instead of implied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BondDeployment {
    /// EVM chain id (mainnet is refused downstream).
    pub chain_id: u64,
    /// `ConditionLockV2` / `ConditionLockERC20V2` address.
    pub contract: [u8; 20],
    /// keccak256 of the bytecode expected at `contract`.
    pub expected_code_hash: [u8; 32],
    /// DOM `TrustedChainIdV1` of the protected settlement.
    pub dom_chain_id: [u8; 32],
    /// Direction of the PROTECTED settlement (bound into the lock).
    pub direction: Direction,
    /// keccak256 over the ordered roster encoding of the settlement.
    pub participants_hash: [u8; 32],
    /// `address(0)` for the native contract, the token for the ERC-20 one.
    pub asset: [u8; 20],
    /// The solver: posts the collateral, `msg.sender` of `open`.
    pub funder: [u8; 20],
    /// The protected party: the only address able to execute the slash.
    pub beneficiary: [u8; 20],
    /// Lowest block that can contain this deployment's logs.
    pub start_block: u64,
    /// `eth_getLogs` window size.
    pub page_size: u64,
    /// Reorg tolerance; deeper reorgs fail closed.
    pub max_reorg_depth: u32,
    /// Gas limit hint carried in unsigned artifacts (non-binding).
    pub gas_limit_hint: u64,
}

/// The v1 [`BondAdapter`]: one bond lock on one `ConditionLockV2`
/// deployment, configured from one validated [`AssurancePolicyV1`].
pub struct EvmBondAdapter<R: JsonRpc, B: BondBroadcaster, C: BondClock> {
    policy_bytes: Vec<u8>,
    deployment: BondDeployment,
    adapter: EvmAdapter<R>,
    broadcaster: B,
    clock: C,
    terms: LockTerms,
    binding: [u8; 32],
    lock_id: [u8; 32],
    /// `bond_release_deadline`, timestamp seconds.
    deadline: u64,
}

fn timestamp_of(spec: TimelockSpec) -> Result<u64> {
    match spec {
        TimelockSpec::TimestampSeconds { value } => Ok(value),
        _ => Err(BondError::WrongTimelockDomain),
    }
}

impl<R: JsonRpc, B: BondBroadcaster, C: BondClock> EvmBondAdapter<R, B, C> {
    /// Builds the adapter for ONE policy. Refuses, before anything else
    /// exists: an invalid policy (including collateral above the cap), a
    /// deadline outside the timestamp domain, a non-canonical adaptor
    /// point, and any deployment the underlying adapter refuses
    /// (mainnet among them).
    pub fn new(
        policy: &AssurancePolicyV1,
        deployment: BondDeployment,
        rpc: R,
        broadcaster: B,
        clock: C,
    ) -> Result<Self> {
        // §7.3: refused before any transaction is built. `validate`
        // enforces the cap rule, deadline monotonicity and point
        // canonicality; the byte capture below re-runs it via
        // `canonical_bytes`.
        let policy_bytes = policy.canonical_bytes()?;
        let deadline = timestamp_of(policy.bond_release_deadline)?;
        // The other three deadlines belong to the machine's clock, but
        // the EVM venue requires the whole policy in one domain (§5.1);
        // `validate` proved same-domain, so checking one suffices —
        // checking all four keeps the refusal independent of that proof.
        for spec in [
            policy.collateral_deadline,
            policy.claim_deadline,
            policy.evidence_deadline,
        ] {
            timestamp_of(spec)?;
        }

        let uspe::objects::EvidenceRuleV1::RevealedScalarClaim { adaptor_point } =
            &policy.evidence_rule;
        let adaptor = adaptor_address(&adaptor_point.0)?;

        let cfg = EvmAdapterConfig {
            chain_id: deployment.chain_id,
            contract: deployment.contract,
            expected_code_hash: deployment.expected_code_hash,
            dom_chain_id: deployment.dom_chain_id,
            direction: deployment.direction,
            session_id: policy.protected_settlement.0,
            terms_hash: policy.terms_hash,
            participants_hash: deployment.participants_hash,
            asset: deployment.asset,
            beneficiary: deployment.beneficiary,
            funder: deployment.funder,
            start_block: deployment.start_block,
            page_size: deployment.page_size,
            max_reorg_depth: deployment.max_reorg_depth,
            gas_limit_hint: deployment.gas_limit_hint,
        };
        let adapter = EvmAdapter::new(cfg, rpc)?;

        let terms = LockTerms {
            dom_chain_id: deployment.dom_chain_id,
            direction: deployment.direction.as_u8(),
            session_id: policy.protected_settlement.0,
            terms_hash: policy.terms_hash,
            participants_hash: deployment.participants_hash,
            asset: deployment.asset,
            amount: amount_word(policy.required_collateral),
            beneficiary: deployment.beneficiary,
            adaptor_address: adaptor,
            deadline,
        };
        let (binding, lock_id) = adapter.track_lock(&terms)?;

        Ok(Self {
            policy_bytes,
            deployment,
            adapter,
            broadcaster,
            clock,
            terms,
            binding,
            lock_id,
            deadline,
        })
    }

    /// The bond's `ConditionLockV2` lock id (funder-bound, anti-squat).
    pub fn bond_lock_id(&self) -> [u8; 32] {
        self.lock_id
    }

    /// The bond's binding hash.
    pub fn bond_binding(&self) -> [u8; 32] {
        self.binding
    }

    /// The exact lock terms bound on chain (for cross-checks in tests).
    pub fn lock_terms(&self) -> &LockTerms {
        &self.terms
    }

    /// The underlying chain adapter (read-only composition seam).
    pub fn chain_adapter(&self) -> &EvmAdapter<R> {
        &self.adapter
    }

    fn open_call(&self) -> Result<UnsignedEvmCall> {
        let calldata = encode_open_calldata(&self.terms)?;
        // `msg.value` carries the collateral on the native contract; the
        // ERC-20 variant moves it via `transferFrom` instead.
        let value = if self.deployment.asset == [0u8; 20] {
            self.terms.amount
        } else {
            [0u8; 32]
        };
        Ok(UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: self.deployment.chain_id,
            to: self.deployment.contract,
            value,
            gas_limit_hint: self.deployment.gas_limit_hint,
            lock_id: self.lock_id,
            binding: self.binding,
            calldata,
        })
    }
}

impl<R: JsonRpc, B: BondBroadcaster, C: BondClock> BondAdapter for EvmBondAdapter<R, B, C> {
    type Error = BondError;

    fn submit_bond(&mut self, policy: &AssurancePolicyV1) -> Result<BroadcastOutcome> {
        // Single definition: the offered policy must be byte-identical to
        // the one this adapter was built for. A near-miss policy opening
        // a differently-parameterised lock is exactly the confusion this
        // check exists to make impossible.
        if policy.canonical_bytes()? != self.policy_bytes {
            return Err(BondError::PolicyMismatch);
        }
        // Deterministic rebuild: repeated calls offer identical bytes (I7).
        self.broadcaster.broadcast(&self.open_call()?)
    }

    fn submit_release(&mut self, bond_lock_id: &[u8; 32]) -> Result<BroadcastOutcome> {
        if *bond_lock_id != self.lock_id {
            return Err(BondError::UnknownLock);
        }
        // The contract refuses `refund` strictly before the deadline;
        // failing closed here keeps the refusal named and spends no gas.
        // Anyone may broadcast this artifact — there is no identity input
        // at all (I12); the destination is always the funder.
        if self.clock.now_timestamp()? < self.deadline {
            return Err(BondError::DeadlineNotReached);
        }
        let mut calldata = Vec::with_capacity(4 + 32);
        calldata.extend_from_slice(&selector(SIG_REFUND));
        calldata.extend_from_slice(&concat_words(&[word_bytes32(self.lock_id)])?);
        self.broadcaster.broadcast(&UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: self.deployment.chain_id,
            to: self.deployment.contract,
            value: [0u8; 32],
            gas_limit_hint: self.deployment.gas_limit_hint,
            lock_id: self.lock_id,
            binding: self.binding,
            calldata,
        })
    }

    fn submit_slash(
        &mut self,
        bond_lock_id: &[u8; 32],
        revealed: &RevealedSecretBytes,
    ) -> Result<BroadcastOutcome> {
        if *bond_lock_id != self.lock_id {
            return Err(BondError::UnknownLock);
        }
        // The scalar leaves the redacting wrapper once, here, and the three
        // uses below share that one copy. Taking it out per use would have made
        // three exposure points where the work needs one.
        let scalar = revealed.expose_scalar_bytes();
        // The contract's own claim checks, applied fail-closed before any
        // bytes exist: canonical scalar, the scalar must open THIS lock's
        // adaptor commitment, and the deadline must not have passed.
        if !is_canonical_scalar(&scalar) {
            return Err(BondError::NonCanonicalScalar);
        }
        if adaptor_address_of_scalar(&scalar)? != self.terms.adaptor_address {
            return Err(BondError::ScalarPointMismatch);
        }
        if self.clock.now_timestamp()? >= self.deadline {
            return Err(BondError::DeadlineExpired);
        }
        // The one artifact whose calldata contains the scalar —
        // necessarily: publishing `t` IS the claim. Built, offered, and
        // dropped; never retained, logged or `Debug`-printed here (I6).
        let mut calldata = Vec::with_capacity(4 + 64);
        calldata.extend_from_slice(&selector(SIG_CLAIM));
        calldata.extend_from_slice(&concat_words(&[
            word_bytes32(self.lock_id),
            word_u256(scalar),
        ])?);
        self.broadcaster.broadcast(&UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: self.deployment.chain_id,
            to: self.deployment.contract,
            value: [0u8; 32],
            gas_limit_hint: self.deployment.gas_limit_hint,
            lock_id: self.lock_id,
            binding: self.binding,
            calldata,
        })
    }

    fn observe(&mut self, cursor: &ChainCursor) -> Result<BondObservation> {
        // Observation is the chain adapter's job (I9): finalized facts
        // only, cursor discipline included. This translation filters to
        // the one bond lock and renames — it interprets nothing.
        let (events, next) = self
            .adapter
            .observe_blocking(cursor, MAX_EVENTS_PER_OBSERVE)?;
        let mut out = Vec::with_capacity(events.len());
        for event in events {
            match event {
                ObservedEvent::LockOpened { lock_id, height } if lock_id == self.lock_id => {
                    out.push(BondEvent::CollateralLocked {
                        bond_lock_id: lock_id,
                        height,
                    });
                }
                ObservedEvent::LockClaimed {
                    lock_id,
                    revealed,
                    height,
                } if lock_id == self.lock_id => {
                    out.push(BondEvent::BondClaimed {
                        bond_lock_id: lock_id,
                        revealed,
                        height,
                    });
                }
                ObservedEvent::LockRefunded { lock_id, height } if lock_id == self.lock_id => {
                    out.push(BondEvent::BondRefunded {
                        bond_lock_id: lock_id,
                        height,
                    });
                }
                ObservedEvent::Reorged { from_height } => {
                    out.push(BondEvent::Reorged { from_height });
                }
                // Another lock's life on the same deployment is not this
                // bond's business.
                ObservedEvent::LockOpened { .. }
                | ObservedEvent::LockClaimed { .. }
                | ObservedEvent::LockRefunded { .. } => {}
            }
        }
        Ok(BondObservation {
            events: out,
            cursor: next,
        })
    }
}

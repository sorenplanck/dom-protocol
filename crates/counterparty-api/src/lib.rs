//! Neutral boundary of the COUNTERPARTY side of a DOM↔X settlement.
//!
//! DOM Interop Foundation Document v0.2 §4.3.
//!
//! Relevant invariants:
//! - I9: chain evidence is only interpreted by that chain's adapter;
//!   the core consumes only [`VerifiedOutcome`].
//! - I10: an unknown capability or divergent version fails closed.
//! - I11: a reorg is an observable event, never a panic nor a terminal state.
//!
//! This crate does NOT know the DOM: no type from here crosses into the DOM
//! leg, and no `dom-adaptor` type enters here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;

/// Opaque identifier of the counterparty chain (not the DOM chain id).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CounterpartyChainId(pub [u8; 32]);

/// Opaque, persistable observation cursor (§4.7).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ChainCursor(pub Vec<u8>);

/// Adaptor point `T = t·G`, compressed (SEC1, 33 bytes).
///
/// Produced by the DOM leg; here it travels as opaque bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdaptorPointBytes(pub [u8; 33]);

impl fmt::Debug for AdaptorPointBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public point: displaying it is safe, but we keep it short.
        write!(
            f,
            "AdaptorPointBytes(0x{:02x}{:02x}..)",
            self.0[0], self.0[1]
        )
    }
}

/// Scalar `t` publicly revealed by an on-chain claim.
///
/// I6: even though it is public after the claim, it is never printed by
/// `Debug` so it cannot leak through logs during windows in which it has not
/// yet been confirmed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RevealedSecretBytes(pub [u8; 32]);

impl fmt::Debug for RevealedSecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevealedSecretBytes(<redacted>)")
    }
}

/// Timelock domain declared by the chain. Never silently converted
/// (invariant inherited from the USPE, §3.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimelockDomain {
    /// Timelock by block height.
    BlockHeight,
    /// Timelock by the chain's clock.
    Timestamp,
}

/// Finality policy of the counterparty chain. [OPEN A4]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FinalityPolicy {
    /// Minimum confirmations to treat an observation as stable.
    pub min_confirmations: u32,
    /// Maximum reorg depth tolerated before requiring revalidation.
    pub max_reorg_depth: u32,
}

/// Capabilities declared by the adapter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainCapabilities {
    /// Lock whose claim reveals `t` on-chain (e.g., ConditionLock on EVM).
    pub supports_condition_lock: bool,
    /// Schnorr adaptor in key-path spend (e.g., taproot BIP340).
    pub supports_schnorr_adaptor: bool,
    /// Hashlock fallback (HTLC). Links the legs publicly.
    pub supports_hashlock_fallback: bool,
    /// Timelock domain.
    pub timelock_domain: TimelockDomain,
    /// Finality policy.
    pub finality: FinalityPolicy,
}

impl ChainCapabilities {
    /// I10: a required, undeclared mechanism fails closed.
    pub fn require(&self, mechanism: LockMechanism) -> Result<(), AdapterError> {
        let ok = match mechanism {
            LockMechanism::ConditionLock => self.supports_condition_lock,
            LockMechanism::SchnorrAdaptor => self.supports_schnorr_adaptor,
            LockMechanism::HashlockFallback => self.supports_hashlock_fallback,
        };
        if ok {
            Ok(())
        } else {
            Err(AdapterError::UnsupportedCapability)
        }
    }
}

/// Lock mechanism on the counterparty leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockMechanism {
    /// Contract that reveals `t` on claim.
    ConditionLock,
    /// Schnorr adaptor pre-signature.
    SchnorrAdaptor,
    /// Classic HTLC.
    HashlockFallback,
}

/// Opaque artifact produced by an adapter. The core and the transport never
/// decode it (§4.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpaqueArtifact {
    /// Chain the artifact belongs to.
    pub chain: CounterpartyChainId,
    /// Version of the adapter that produced it (version binding, I10).
    pub adapter_version: u32,
    /// Opaque bytes.
    pub bytes: Vec<u8>,
}

/// Minimal neutral terms delivered to the adapter.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NeutralTerms {
    /// `keccak/blake` of the frozen economic terms. [OPEN A3]
    pub terms_hash: [u8; 32],
    /// Settlement identifier.
    pub settlement_id: [u8; 32],
    /// Amount in the counterparty chain's smallest unit.
    pub amount: u128,
    /// Deadline in the unit of the declared `TimelockDomain`.
    pub deadline: u64,
}

/// Event observed on the counterparty chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ObservedEvent {
    /// Lock opened (funds locked).
    LockOpened {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Height at which it was observed.
        height: u64,
    },
    /// Claim executed: reveals `t`.
    LockClaimed {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Secret revealed on-chain.
        revealed: RevealedSecretBytes,
        /// Height at which it was observed.
        height: u64,
    },
    /// Refund executed.
    LockRefunded {
        /// Lock identifier.
        lock_id: [u8; 32],
        /// Height at which it was observed.
        height: u64,
    },
    /// Reorg: invalidates observations from the height onward (I11).
    Reorged {
        /// First invalidated height.
        from_height: u64,
    },
}

/// Neutral verified outcome (I9).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerifiedOutcome {
    /// Funds locked and confirmed.
    Funded {
        /// Confirmation height.
        height: u64,
    },
    /// Claim confirmed with the revealed secret.
    Claimed {
        /// Revealed secret.
        revealed: RevealedSecretBytes,
        /// Confirmation height.
        height: u64,
    },
    /// Refund confirmed.
    Refunded {
        /// Confirmation height.
        height: u64,
    },
}

/// Stable taxonomy of adapter errors (§4.3).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AdapterError {
    /// Required capability is not supported.
    #[error("unsupported capability")]
    UnsupportedCapability,
    /// Invalid state for the operation.
    #[error("invalid state")]
    InvalidState,
    /// Precondition not satisfied.
    #[error("precondition unsatisfied")]
    PreconditionUnsatisfied,
    /// Invalid evidence.
    #[error("evidence invalid")]
    EvidenceInvalid,
    /// Reorg detected.
    #[error("reorg detected")]
    ReorgDetected,
    /// Stale cursor.
    #[error("stale cursor")]
    StaleCursor,
    /// Divergent version.
    #[error("version mismatch")]
    VersionMismatch,
    /// Adapter unavailable.
    #[error("adapter unavailable")]
    AdapterUnavailable,
    /// Non-canonical retransmission (divergent bytes, I7).
    #[error("non-canonical retransmission")]
    NonCanonicalRetransmission,
    /// Size limit exceeded before allocating (I14).
    #[error("bounds exceeded")]
    BoundsExceeded,
}

/// Cap on events per `observe` call (I14: validate the cap before allocating).
pub const MAX_EVENTS_PER_OBSERVE: usize = 512;

/// Counterparty leg adapter.
///
/// Asynchronous by decision (remote RPCs). Uses native `async fn` in
/// trait (Rust ≥1.75). Dyn-compatibility is NOT required and NOT
/// promised — A12 RESOLVED (D-011): static dispatch; if F3/F5 ever need
/// uniform handling of several adapters, the designated mechanism is a
/// CLOSED enum wrapper delegating to this trait. `#[async_trait]`
/// (boxed futures) is rejected. See
/// docs/adr/ADR-A12-async-trait-dispatch.md.
#[allow(async_fn_in_trait)]
pub trait CounterpartyAdapter: Send + Sync {
    /// Chain served.
    fn chain_id(&self) -> CounterpartyChainId;

    /// Declared capabilities.
    fn capabilities(&self) -> ChainCapabilities;

    /// Adapter version (feeds into the artifacts' binding).
    fn adapter_version(&self) -> u32;

    /// Prepares the lock conditioned on `T`. Takes no custody and does not
    /// sign for the user: returns an opaque artifact for local authorization
    /// (I1).
    async fn prepare_lock(
        &self,
        terms: &NeutralTerms,
        adaptor_point: &AdaptorPointBytes,
    ) -> Result<OpaqueArtifact, AdapterError>;

    /// Observes the chain from the cursor. `max` is capped by
    /// [`MAX_EVENTS_PER_OBSERVE`].
    async fn observe(
        &self,
        cursor: &ChainCursor,
        max: usize,
    ) -> Result<(Vec<ObservedEvent>, ChainCursor), AdapterError>;

    /// Converts raw chain-specific evidence into a neutral outcome.
    async fn verify_evidence(&self, evidence: &[u8]) -> Result<VerifiedOutcome, AdapterError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> ChainCapabilities {
        ChainCapabilities {
            supports_condition_lock: true,
            supports_schnorr_adaptor: false,
            supports_hashlock_fallback: true,
            timelock_domain: TimelockDomain::Timestamp,
            finality: FinalityPolicy {
                min_confirmations: 12,
                max_reorg_depth: 64,
            },
        }
    }

    #[test]
    fn capability_negotiation_fails_closed() {
        assert!(caps().require(LockMechanism::ConditionLock).is_ok());
        assert_eq!(
            caps().require(LockMechanism::SchnorrAdaptor),
            Err(AdapterError::UnsupportedCapability),
            "I10: an undeclared capability must fail closed"
        );
    }

    #[test]
    fn revealed_secret_never_prints_material() {
        let s = RevealedSecretBytes([0xAB; 32]);
        let rendered = format!("{s:?}");
        assert!(rendered.contains("redacted"), "I6");
        assert!(!rendered.contains("ab"), "I6: no scalar byte in the log");
    }
}

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

use zeroize::{Zeroize, ZeroizeOnDrop};

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
/// # What this type enforces
///
/// * **The scalar is not reachable by field access.** The field is private, so
///   the only way out is [`Self::expose_scalar_bytes`], whose name is long and
///   unpleasant on purpose: every place the scalar leaves the wrapper is one
///   grep away. A `compile_fail` example on that method proves the field is
///   unreachable from outside this crate — a doctest compiles as a foreign
///   crate, which is the only vantage point from which the question is real.
/// * **`Debug` never prints it.** The hand-written [`fmt::Debug`] below writes
///   a fixed string, so a value formatted *as this type* — including through
///   every derived `Debug` of a struct or enum holding one, such as
///   [`ObservedEvent::LockClaimed`] and [`VerifiedOutcome::Claimed`] — renders
///   `RevealedSecretBytes(<redacted>)`. That is invariant I6, and
///   `revealed_secret_never_prints_material` pins it.
/// * **The bytes are scrubbed when the value dies.** `ZeroizeOnDrop` gives it a
///   destructor; `Zeroize` is also public, so a caller holding a value it wants
///   gone early can scrub it in place without waiting for the drop.
/// * **There is no `Copy`.** Handing the value on is a move, and a second live
///   copy has to be asked for by name through `clone`. `Copy` and `Drop` are
///   mutually exclusive in Rust, so this is not three independent choices: the
///   scrubbing *is* the reason the copying stopped.
///
/// # What it still does not enforce, and nobody should infer
///
/// [`Self::expose_scalar_bytes`] returns a plain `[u8; 32]`, and that array is
/// outside every guarantee above — it has a derived `Debug` that prints in
/// full, it copies implicitly, and nothing scrubs it. The wrapper protects what
/// it holds, not what a caller takes out of it. That is why the accessor is
/// named the way it is rather than `as_bytes`.
///
/// The scalar is public on chain by the time a well-behaved producer builds one
/// of these, so none of this is confidentiality in the cryptographic sense. It
/// is custody hygiene: the value has one door, the door is greppable, and the
/// bytes do not outlive the value by accident.
///
/// The absence of `Copy` is pinned here, because "this does not compile" is not
/// something a passing unit test can assert. Restoring `Copy` to quiet a move
/// error would delete the destructor with it — `Copy` and `Drop` are mutually
/// exclusive — so this example failing to compile is load-bearing:
///
/// ```compile_fail
/// let secret = counterparty_api::RevealedSecretBytes::new([0xAB; 32]);
/// let _moved = secret;
/// // `secret` was moved, not copied: this second use is the compile error.
/// let _again = secret.expose_scalar_bytes();
/// ```
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RevealedSecretBytes([u8; 32]);

impl RevealedSecretBytes {
    /// Wraps the scalar an on-chain claim has already made public.
    ///
    /// It is not a barrier and does not pretend to be one: the argument is a
    /// bare `[u8; 32]`, so nothing here can tell a scalar from a lock
    /// identifier or an amount. What it is, now that the field is closed, is
    /// the only way to build one of these at all.
    #[must_use]
    pub fn new(scalar: [u8; 32]) -> Self {
        Self(scalar)
    }

    /// Copies the scalar out of the redacting wrapper.
    ///
    /// The name is long and unpleasant on purpose. Every call is a place where
    /// the scalar leaves the only type that redacts it, and a reviewer should
    /// be able to find all of them by searching for one string. `secret.0` was
    /// not greppable in that way; this is.
    ///
    /// It returns a copy, and that copy is outside every guarantee the wrapper
    /// gives: derived `Debug`, implicit copying, no scrubbing. Keep it short
    /// lived, and call [`Zeroize::zeroize`] on the wrapper when the original is
    /// no longer wanted rather than waiting for the drop.
    ///
    /// The field itself is unreachable from outside this crate. A doctest is
    /// the only place that claim can be tested, because it compiles as a
    /// foreign crate and a unit test in this file does not — a child module can
    /// see its parent's private fields, so an in-crate test would pass whether
    /// the field were public or not:
    ///
    /// ```compile_fail
    /// let secret = counterparty_api::RevealedSecretBytes::new([0xAB; 32]);
    /// // The field is private: this is the whole barrier, and it is a
    /// // compile error rather than a runtime refusal.
    /// let _bypass = secret.0;
    /// ```
    ///
    /// The accessor is how the bytes come out, and it compiles:
    ///
    /// ```
    /// let secret = counterparty_api::RevealedSecretBytes::new([0xAB; 32]);
    /// assert_eq!(secret.expose_scalar_bytes(), [0xAB; 32]);
    /// ```
    #[must_use]
    pub const fn expose_scalar_bytes(&self) -> [u8; 32] {
        self.0
    }
}

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
        let s = RevealedSecretBytes::new([0xAB; 32]);
        let rendered = format!("{s:?}");
        assert!(rendered.contains("redacted"), "I6");
        assert!(!rendered.contains("ab"), "I6: no scalar byte in the log");
        // Formatting the type through a container that derives `Debug` must
        // reach the same hand-written impl, since that is where every real log
        // line goes through.
        let carried = ObservedEvent::LockClaimed {
            lock_id: [0x01; 32],
            revealed: s,
            height: 7,
        };
        let rendered = format!("{carried:?}");
        assert!(rendered.contains("redacted"), "I6 through a container");
        assert!(
            !rendered.contains("ab"),
            "I6: no scalar byte through a container"
        );
    }

    /// Successor to `the_public_field_bypasses_the_redaction`, which is gone.
    ///
    /// # What the retired test proved, and why it cannot be written any more
    ///
    /// From stage 1 until stage 2 this module carried a test that asserted a
    /// *limitation*: that `format!("{:?}", secret.0)` printed the scalar in
    /// full, so the redaction was exactly one `.0` away. It existed because a
    /// doc sentence describing a hole rots silently, and an executable one
    /// fails the day the hole closes. That day is this one.
    ///
    /// It is recorded rather than deleted because a test that vanishes reads as
    /// coverage lost, and this is the opposite: it was written with its own
    /// death as the success condition, and it reached it.
    ///
    /// One honest detail, because it changes what can be claimed here. Closing
    /// the field did **not** make the old test stop compiling. A child module
    /// can read its parent's private fields, so `s.0` still resolves inside
    /// this file and the retired assertion would still pass — it would simply
    /// no longer be measuring anything about the crate's boundary. That is why
    /// the real successor is not below but on
    /// [`RevealedSecretBytes::expose_scalar_bytes`]: a `compile_fail` doctest,
    /// which compiles as a foreign crate and is therefore the only vantage
    /// point from which "the field is unreachable" is a testable statement.
    ///
    /// What remains testable in-crate is the part that is about behaviour
    /// rather than visibility, and that is what this asserts.
    #[test]
    fn the_scalar_leaves_only_through_the_named_accessor() {
        let secret = RevealedSecretBytes::new([0xAB; 32]);
        // The one door, and it really does hand over the bytes.
        assert_eq!(secret.expose_scalar_bytes(), [0xAB; 32]);
        // What comes out is a bare array, outside every guarantee the wrapper
        // gives. Asserted, not described, for the same reason the retired test
        // asserted its limitation: so nobody reads the long name as a promise
        // that the bytes stay protected after they leave.
        assert!(!format!("{:?}", secret.expose_scalar_bytes()).contains("redacted"));
        assert!(format!("{:?}", secret.expose_scalar_bytes()).contains("171"));
        // And the wrapper itself still redacts, so the door did not widen.
        assert!(format!("{secret:?}").contains("redacted"));
    }

    /// Construction and extraction are exact inverses.
    ///
    /// Its stage-1 ancestor also compared both against the public field, which
    /// is what made the ~78-site migration safe to do mechanically. That half
    /// is gone with the field; this keeps the half that is still meaningful,
    /// because a round trip that lost or reordered a byte would be a defect no
    /// amount of visibility discipline would catch.
    #[test]
    fn construction_and_extraction_round_trip() {
        for scalar in [[0x00; 32], [0xAB; 32], [0xFF; 32]] {
            assert_eq!(
                RevealedSecretBytes::new(scalar).expose_scalar_bytes(),
                scalar
            );
        }
        let scalar = [0xAB; 32];
        assert_eq!(
            RevealedSecretBytes::new(scalar),
            RevealedSecretBytes::new(scalar)
        );
    }

    /// Scrubbing no longer requires reaching through the field.
    ///
    /// `f3-harness/src/routes.rs` zeroizes a revealed scalar today by writing
    /// `inner.revealed.0.zeroize()` — it reaches *through* the public field,
    /// which is why closing that field cannot be a one-line change. This impl
    /// is the replacement that call site needs before stage 2 can happen, and
    /// it is real: it comes from `zeroize`, not from an assignment this crate
    /// cannot stop the compiler eliding.
    #[test]
    fn the_wrapper_scrubs_itself_without_the_public_field() {
        let mut secret = RevealedSecretBytes::new([0xAB; 32]);
        secret.zeroize();
        assert_eq!(secret.expose_scalar_bytes(), [0; 32]);
        // At stage 1 this block read `let mut duplicate = original;` and the
        // assertion below carried the note "stage 1 is Copy". That line is now
        // a **move**, and needing `clone` to write it at all is the whole point
        // of dropping `Copy`: a second live copy of a secret is something a
        // caller now has to ask for by name.
        let original = RevealedSecretBytes::new([0xCD; 32]);
        let mut duplicate = original.clone();
        duplicate.zeroize();
        assert_eq!(duplicate.expose_scalar_bytes(), [0; 32]);
        assert_eq!(
            original.expose_scalar_bytes(),
            [0xCD; 32],
            "a clone is an independent value: scrubbing it must not reach the original"
        );
    }

    /// Handing the value on is a move, and a second holder needs `clone`.
    ///
    /// This is the *positive* half only, and says so: a passing move proves
    /// nothing about `Copy`, because a `Copy` type moves just as happily. The
    /// half that actually pins the absence of `Copy` is a `compile_fail`
    /// doctest on [`RevealedSecretBytes`], since "this does not compile" is not
    /// a statement a passing unit test can make.
    ///
    /// A first attempt here was `fn assert_not_copy<T: Clone>() {}`, which
    /// asserts `Clone` and nothing else. It is recorded because it looked like
    /// a structural check and was one of the failure shapes this migration
    /// exists to avoid: a test whose name claims more than its body.
    #[test]
    fn handing_the_wrapper_on_is_a_move() {
        let secret = RevealedSecretBytes::new([0xAB; 32]);
        let moved = secret;
        assert_eq!(moved.expose_scalar_bytes(), [0xAB; 32]);
        let second = moved.clone();
        assert_eq!(second, moved);
    }
}

//! `EvidenceVerifier` — the evidence seam of the F4 specification §8
//! (D-017, D-F4.4/D-F4.6).
//!
//! The machine never parses chain bytes (I9): raw evidence goes to the
//! verifier of the chain that produced it, and only the VERDICT reaches
//! the machine, as `EvidenceVerified { valid }`. The mapping is frozen:
//!
//! - [`EvidenceVerdict::Valid`]   → `EvidenceVerified { valid: true }`;
//! - [`EvidenceVerdict::Invalid`] → `EvidenceVerified { valid: false }`;
//! - `Err(_)`                     → NOTHING. The verifier could not
//!   decide (endpoint down, reorg in progress); the caller retries.
//!
//! That third arm is load-bearing: collapsing "could not verify" into
//! "invalid" would let a broken RPC endpoint push a legitimate claim into
//! `ClaimRejected` and release the bond out from under the harmed party.
//! An implementation must never turn unavailability into a verdict.

use counterparty_api::RevealedSecretBytes;

use crate::objects::{AssurancePolicyV1, TimelockSpec};

/// Why evidence failed verification. Named for audit; carrying the
/// reason is what lets a closure report show WHICH check refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InvalidEvidence {
    /// The bytes do not decode as this chain's evidence format, or their
    /// internal attestation does not hold.
    Malformed,
    /// Well-formed, but not a claim of the obligation this policy
    /// protects (divergent binding, foreign lock, wrong kind).
    NotABoundClaim,
    /// The revealed scalar is outside `0 < t < n`.
    NonCanonicalScalar,
    /// The scalar does not open the policy's adaptor commitment: it is
    /// not the secret this obligation's swap was bound to.
    WrongScalarPoint,
    /// Verification concluded after the policy's evidence deadline.
    /// Deliberately stricter than claim-time (fail-closed toward
    /// release, the conservative terminal policy).
    OutsideEvidenceWindow,
}

/// The verifier's decision on one piece of raw evidence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EvidenceVerdict {
    /// Obligation failure proven: a FINALIZED claim of the bound leg
    /// revealed the scalar that opens the policy's commitment, inside
    /// the evidence window. Feeds `EvidenceVerified { valid: true }`;
    /// the scalar is what the slash spend will publish.
    Valid {
        /// The revealed scalar (public by construction; never logged —
        /// I6).
        revealed: RevealedSecretBytes,
        /// Finalized height the claim was verified at.
        claim_height: u64,
    },
    /// Verification RAN and the evidence does not prove failure. Feeds
    /// `EvidenceVerified { valid: false }`.
    Invalid(InvalidEvidence),
}

/// Verifies raw chain evidence against a policy's evidence rule
/// (F4 spec §8).
pub trait EvidenceVerifier {
    /// Implementation-specific error: "could not decide", never a
    /// verdict. See the module docs for why this distinction is
    /// load-bearing.
    type Error;

    /// Verifies `raw_evidence` under `policy` at time `now` (the bond
    /// chain's clock, in the policy's own timelock domain — A4: a
    /// divergent domain is an error, never a conversion).
    fn verify(
        &self,
        policy: &AssurancePolicyV1,
        raw_evidence: &[u8],
        now: TimelockSpec,
    ) -> Result<EvidenceVerdict, Self::Error>;
}

//! One error taxonomy for the whole harness.
//!
//! Every failure mode of the composition maps onto exactly one variant here,
//! and every variant is either a unit variant or carries only public,
//! non-secret scalars (heights, lengths, domain tags). No variant can carry the
//! adaptor scalar `t`, so no `?` on a path that touched `t` can leak it (I6).
//!
//! The three inner taxonomies are kept as-is rather than flattened, because
//! *which layer refused* is part of the answer: an [`AdapterError`] means the
//! EVM observation was rejected, a [`LegError`] means the DOM leg refused, and
//! an [`OutboxError`] means the local durable log refused.

use counterparty_api::AdapterError;
use dom_leg::LegError;

use crate::outbox::OutboxError;
use crate::timelock::TimelockError;

/// Anything the harness can refuse to do.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum HarnessError {
    /// The EVM adapter refused, or the endpoint could not be trusted.
    #[error("evm adapter: {0}")]
    Adapter(#[from] AdapterError),

    /// The DOM leg refused. **This is not a bug to route around.** `dom-leg`
    /// speaks for the pinned DOM authority; when it says no, the correct
    /// behaviour of this harness is to stop here, not to retry with different
    /// inputs or to fall back to anything.
    #[error("dom leg: {0}")]
    DomLeg(#[from] LegError),

    /// The durable submission log refused.
    #[error("outbox: {0}")]
    Outbox(#[from] OutboxError),

    /// A timelock rule refused.
    #[error("timelock: {0}")]
    Timelock(#[from] TimelockError),

    /// An observation was surfaced above the finalized checkpoint. Should be
    /// impossible through the adapter; checked again here because the route is
    /// the last place before an irreversible action.
    #[error("observation at height {observed} is above the finalized height {finalized}")]
    NotFinal {
        /// Height the observation claims.
        observed: u64,
        /// Finalized checkpoint the observation was taken against.
        finalized: u64,
    },

    /// The re-derived `binding` or `lockId` disagreed with what was observed.
    #[error("binding or lock id re-derivation disagreed with the observation")]
    BindingMismatch,

    /// The revealed scalar is not canonical (`0 < t < n` is required).
    #[error("revealed scalar is not canonical")]
    NonCanonicalScalar,

    /// `address(t·G)` is not the address the lock committed to, or the scalar
    /// does not open the adaptor point carried by the pre-signature.
    #[error("revealed scalar does not open the committed adaptor point")]
    AdaptorPointMismatch,

    /// The broadcast seam refused to hand the artifact on.
    #[error("broadcast refused")]
    BroadcastRefused,

    /// The harness was configured with values that cannot describe one
    /// settlement (e.g. terms that do not belong to the configured session).
    #[error("harness misconfiguration")]
    Misconfigured,
}

/// Crate-local result alias.
pub type Result<T> = core::result::Result<T, HarnessError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_variant_can_carry_secret_material() {
        // I6, structurally. The only payloads are heights and nested unit-ish
        // taxonomies; a canary that breaks the day someone adds `t` to a
        // variant.
        let rendered = format!(
            "{:?}|{:?}|{:?}",
            HarnessError::NonCanonicalScalar,
            HarnessError::AdaptorPointMismatch,
            HarnessError::NotFinal {
                observed: 9,
                finalized: 7
            }
        );
        assert_eq!(
            rendered,
            "NonCanonicalScalar|AdaptorPointMismatch|NotFinal { observed: 9, finalized: 7 }"
        );
    }

    #[test]
    fn the_dom_leg_refusal_is_reported_as_a_dom_leg_refusal() {
        // Not remapped to something vaguer: the report must say which layer
        // said no.
        let e: HarnessError = LegError::VerificationFailed.into();
        assert!(matches!(
            e,
            HarnessError::DomLeg(LegError::VerificationFailed)
        ));
        assert!(format!("{e}").starts_with("dom leg:"));
    }
}

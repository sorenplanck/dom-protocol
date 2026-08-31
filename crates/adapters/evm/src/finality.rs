//! A4-EVM: finality is the Ethereum `finalized` tag, and nothing else.
//!
//! # The decision, and why there is no fallback
//!
//! Post-Merge Ethereum has an explicit, consensus-level notion of finality: a
//! checkpoint that two thirds of the stake has justified and then finalized.
//! Reverting it requires slashing at least a third of the total stake. The
//! execution layer exposes it as the `finalized` block tag.
//!
//! A confirmation count ("N blocks deep") is a *probabilistic* proxy for that,
//! invented for proof-of-work. Substituting it when the real thing is
//! unavailable would silently downgrade the safety property that the whole
//! settlement rests on — and it would do so exactly in the situation where the
//! endpoint is already misbehaving. So:
//!
//! - the only source of finality is `eth_getBlockByNumber("finalized", false)`;
//! - if the endpoint returns `null`, errors, or omits a field, the adapter
//!   reports [`AdapterError::AdapterUnavailable`] and surfaces **no** events;
//! - `min_confirmations` is never consulted for gating. It is reported in
//!   [`counterparty_api::ChainCapabilities`] as `0` precisely so that nobody
//!   reads a confirmation policy that does not exist. See
//!   [`crate::adapter::EvmAdapterConfig`].
//!
//! # The gate
//!
//! No [`counterparty_api::ObservedEvent`] and no
//! [`counterparty_api::VerifiedOutcome`] may ever refer to a block above
//! [`FinalizedHead::height`]. [`gate`] is the single predicate that decides
//! this, and every surfacing path goes through it.

//! # Telling "no finalized tag" apart from "no settlement"
//!
//! Both fail closed, but they are not the same fact and must not be reported as
//! the same fact. An endpoint that cannot serve `finalized` is an *external*
//! blocker: the settlement may be perfectly fine and the operator's job is to
//! change provider. [`fetch_finalized_checked`] returns
//! [`RejectReason::FinalizedTagUnavailable`] for exactly that case, distinct
//! from a transport failure and from a malformed answer, so the caller can
//! report `BLOCKED_EXTERNAL` for the right reason.
//! [`fetch_finalized`] keeps the neutral signature for the paths that only need
//! the coarse verdict.

use counterparty_api::AdapterError;

use crate::error::{RejectReason, Result};
use crate::rpc::{EthClient, JsonRpc};

/// The `finalized` tag, spelled once.
pub const FINALIZED_TAG: &str = "finalized";

/// Confirmation count reported in the declared capabilities.
///
/// Zero, and deliberately so: this adapter does not count confirmations. See
/// the module header.
pub const REPORTED_MIN_CONFIRMATIONS: u32 = 0;

/// The finalized head, as the chain reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FinalizedHead {
    /// Height of the finalized block.
    pub height: u64,
    /// Hash of the finalized block. Recorded in evidence so that a verifier can
    /// tell *which* finalized chain the observation belonged to.
    pub hash: [u8; 32],
}

/// Fetches the finalized head. Fails closed; never falls back.
///
/// Returns [`AdapterError::AdapterUnavailable`] when the endpoint cannot serve
/// the tag — which is the case on pre-Merge chains, on some light clients, and
/// on a proxy that is lagging behind its upstream. In all of those cases the
/// correct behaviour is to observe nothing at all.
pub fn fetch_finalized<R: JsonRpc + ?Sized>(rpc: &R) -> Result<FinalizedHead> {
    fetch_finalized_checked(rpc).map_err(AdapterError::from)
}

/// Fetches the finalized head, reporting *why* it could not be had.
///
/// Use this wherever the answer has to be actionable by a human:
/// [`RejectReason::FinalizedTagUnavailable`] means the endpoint does not serve
/// the tag at all, which is a `BLOCKED_EXTERNAL` condition rather than a
/// statement about any settlement.
pub fn fetch_finalized_checked<R: JsonRpc + ?Sized>(
    rpc: &R,
) -> core::result::Result<FinalizedHead, RejectReason> {
    let client = EthClient::new(rpc);
    let header = match client.block_by_tag(FINALIZED_TAG) {
        Ok(Some(h)) => h,
        // `null` result: the endpoint understood the tag but has no finalized
        // block, or does not implement it. Either way the tag is unusable, and
        // A4-EVM has no fallback.
        Ok(None) => return Err(RejectReason::FinalizedTagUnavailable),
        // A transport failure is not evidence that the tag is unsupported.
        Err(AdapterError::AdapterUnavailable) => {
            return Err(RejectReason::FinalizedTagTransportFailure)
        }
        // A structurally broken answer is also unavailability, not a reason to
        // guess.
        Err(_) => return Err(RejectReason::FinalizedHeaderMalformed),
    };
    // The cursor stores the *next* height to scan. At `u64::MAX` that
    // successor is unrepresentable and the paginated loops would otherwise
    // keep scanning the same final page forever (`saturating_add(1)`). A
    // hostile endpoint must not be able to turn a syntactically valid header
    // into an infinite observer loop.
    if header.hash == [0u8; 32] || header.number == u64::MAX {
        return Err(RejectReason::FinalizedHeaderMalformed);
    }
    Ok(FinalizedHead {
        height: header.number,
        hash: header.hash,
    })
}

/// The finality gate: `true` iff an observation at `height` may be surfaced.
pub fn gate(height: u64, finalized: &FinalizedHead) -> bool {
    height <= finalized.height
}

/// Fail-closed form of [`gate`].
pub fn require_final(height: u64, finalized: &FinalizedHead) -> Result<()> {
    if gate(height, finalized) {
        Ok(())
    } else {
        Err(AdapterError::PreconditionUnsatisfied)
    }
}

/// Highest block this scan may look at, given the finalized head and a
/// requested upper bound. Never above the finalized height.
pub fn clamp_to_finalized(requested_to: u64, finalized: &FinalizedHead) -> u64 {
    requested_to.min(finalized.height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockChain;
    use serde_json::{json, Value};

    struct MaxHeightRpc;

    impl JsonRpc for MaxHeightRpc {
        fn call(&self, method: &str, _params: Value) -> Result<Value> {
            assert_eq!(method, "eth_getBlockByNumber");
            Ok(json!({
                "number": "0xffffffffffffffff",
                "hash": "0x0101010101010101010101010101010101010101010101010101010101010101",
                "parentHash": "0x0202020202020202020202020202020202020202020202020202020202020202"
            }))
        }
    }

    #[test]
    fn finalized_head_is_read_from_the_tag() {
        let chain = MockChain::new(31337, [0xC0; 20])
            .with_blocks(10)
            .finalize(6);
        let head = fetch_finalized(&chain).expect("finalized served");
        assert_eq!(head.height, 6);
        assert_eq!(head.hash, chain.block_hash(6).expect("block 6"));
    }

    #[test]
    fn missing_finalized_tag_fails_closed_without_fallback() {
        let chain = MockChain::new(31337, [0xC0; 20]).with_blocks(10);
        // No finalized checkpoint configured => the tag answers `null`.
        assert_eq!(
            fetch_finalized(&chain),
            Err(AdapterError::AdapterUnavailable),
            "A4-EVM forbids substituting a confirmation count"
        );
        // ... and the reason is distinguishable, so the caller can report
        // BLOCKED_EXTERNAL specifically for a missing `finalized` tag.
        assert_eq!(
            fetch_finalized_checked(&chain),
            Err(RejectReason::FinalizedTagUnavailable)
        );
        assert!(fetch_finalized_checked(&chain)
            .expect_err("no tag")
            .is_finalized_tag_unavailable());
    }

    #[test]
    fn transport_failure_is_unavailability_not_a_guess() {
        let chain = MockChain::new(31337, [0xC0; 20])
            .with_blocks(10)
            .finalize(6)
            .breaking_transport();
        assert_eq!(
            fetch_finalized(&chain),
            Err(AdapterError::AdapterUnavailable)
        );
        // A dead transport is *not* evidence that the endpoint lacks the tag.
        let reason = fetch_finalized_checked(&chain).expect_err("transport down");
        assert_eq!(reason, RejectReason::FinalizedTagTransportFailure);
        assert!(!reason.is_finalized_tag_unavailable());
    }

    #[test]
    fn a_malformed_finalized_header_is_not_reported_as_a_missing_tag() {
        let chain = MockChain::new(31337, [0xC0; 20])
            .with_blocks(10)
            .finalize(6)
            .with_faults(crate::mock::Faults {
                garbage_results: true,
                ..crate::mock::Faults::default()
            });
        let reason = fetch_finalized_checked(&chain).expect_err("garbage");
        assert_eq!(reason, RejectReason::FinalizedHeaderMalformed);
        assert!(!reason.is_finalized_tag_unavailable());
        assert_eq!(
            fetch_finalized(&chain),
            Err(AdapterError::AdapterUnavailable)
        );
    }

    #[test]
    fn a_finalized_height_without_a_representable_successor_is_malformed() {
        assert_eq!(
            fetch_finalized_checked(&MaxHeightRpc),
            Err(RejectReason::FinalizedHeaderMalformed)
        );
    }

    #[test]
    fn gate_never_admits_above_the_finalized_height() {
        let head = FinalizedHead {
            height: 100,
            hash: [1u8; 32],
        };
        assert!(gate(0, &head));
        assert!(gate(100, &head));
        assert!(!gate(101, &head));
        assert_eq!(require_final(100, &head), Ok(()));
        assert_eq!(
            require_final(101, &head),
            Err(AdapterError::PreconditionUnsatisfied)
        );
        assert_eq!(clamp_to_finalized(u64::MAX, &head), 100);
        assert_eq!(clamp_to_finalized(50, &head), 50);
    }
}

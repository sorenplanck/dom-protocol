//! The two settlement routes, and the order in which they validate.
//!
//! # The asymmetry
//!
//! A DOM↔EVM settlement has one secret and two directions:
//!
//! - **EVM→DOM**: the EVM leg is claimed first. `t` becomes public in an
//!   on-chain `Claimed` log. The DOM leg is then closed by *adapting* the
//!   pre-signature with that already-public `t`.
//! - **DOM→EVM**: the DOM leg is claimed first. `t` is recovered locally by
//!   *extracting* it from the final DOM signature and the pre-signature. The
//!   EVM leg is then claimed with it, which publishes it.
//!
//! `adapt` and `extract` are therefore not interchangeable, and each route uses
//! exactly one of them. See [`crate::seam`] for why the EVM→DOM route must
//! never touch `extract`.
//!
//! # Validation order is part of the specification
//!
//! Both routes validate before they act, in a fixed order, cheapest and most
//! decisive first. The order matters because each step narrows what the next
//! step is allowed to assume:
//!
//! 1. **finality** — an observation above the finalized checkpoint is not a
//!    fact yet. Nothing downstream may run on it.
//! 2. **scalar canonicity** — `0 < t < n`. Anything else is not a scalar, and
//!    must never reach a curve operation.
//! 3. **`address(t·G) == terms.adaptorAddress`** — the scalar opens the lock
//!    the EVM contract actually committed to.
//! 4. **binding / `lockId` re-derivation** — the observation belongs to *this*
//!    settlement on *this* deployment, and not to a look-alike.
//! 5. **`t` opens the pre-signature's `T`** — the EVM-side commitment and the
//!    DOM-side commitment are the same point. This is the step that ties the
//!    two legs together; without it the EVM leg could be settled against a
//!    point the DOM pre-signature never committed to.
//! 6. **timelock margins** — there is still enough window to finish (see
//!    [`crate::timelock`]).
//! 7. **the DOM leg** — and only then.
//!
//! # Step 7 is live, and that raises the stakes
//!
//! `dom-leg` now performs the real `AdaptorPreSignatureV1::{verify, adapt,
//! extract}` against the pinned authority, so step 7 can **succeed**. Two
//! consequences are load-bearing for everything below:
//!
//! - a refusal is still a refusal. Nothing here softens, retries or works
//!   around a `LegError`; when the DOM leg says no, the route says no, no DOM
//!   claim is built and no EVM call exists to broadcast;
//! - a *mis-wired* route no longer fails loudly. Calling the extraction
//!   operation on the EVM→DOM route would once have produced an error; today
//!   it could produce a plausible-looking scalar. The structural prohibition in
//!   [`crate::seam`] is therefore no longer belt-and-braces — it is the thing
//!   that stops a silent swap.
//!
//! # The scalar's lifetime inside a route
//!
//! Both routes hold `t` in a [`Zeroizing`] working buffer and let it die with
//! the call frame. The one artifact that legitimately carries the scalar out is
//! the EVM `claim(lockId, t)` calldata, because publishing `t` on the EVM leg
//! *is* the claim. Nothing else here persists, logs or renders it.

use adapter_evm::abi::{concat_words, selector, word_bytes32, word_u256, SIG_CLAIM, SIG_REFUND};
use adapter_evm::adapter::UNSIGNED_CALL_VERSION;
use adapter_evm::binding::{
    adaptor_address, adaptor_address_of_scalar, adaptor_point_of_scalar, derive_binding,
    derive_lock_id, is_canonical_scalar, LockTerms,
};
use adapter_evm::evidence::EvmEvidence;
use adapter_evm::rpc::JsonRpc;
use adapter_evm::{EvmAdapter, UnsignedEvmCall};
use counterparty_api::{AdapterError, RevealedSecretBytes, VerifiedOutcome};
use dom_leg::PreSignatureBytes;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{HarnessError, Result};
use crate::seam::DomLegOps;
use crate::timelock::{TimelockPoint, TimelockPolicy};

/// Which deployment an EVM-side derivation belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvmDeployment {
    /// EVM chain id.
    pub chain_id: u64,
    /// `ConditionLockV2` address.
    pub contract: [u8; 20],
    /// `msg.sender` at `open` — part of the `lockId` preimage.
    pub funder: [u8; 20],
    /// Gas limit hint carried in unsigned artifacts. Not a promise.
    pub gas_limit_hint: u64,
}

/// Re-derives `(binding, lock_id)` for a set of terms on a deployment.
pub fn rederive(deployment: &EvmDeployment, terms: &LockTerms) -> Result<([u8; 32], [u8; 32])> {
    let binding = derive_binding(deployment.chain_id, &deployment.contract, terms)?;
    let lock_id = derive_lock_id(&binding, &deployment.funder)?;
    Ok((binding, lock_id))
}

/// Checks that a scalar is canonical, opens the EVM-side commitment
/// `terms.adaptorAddress`, and opens the DOM-side commitment `T` carried by the
/// pre-signature.
///
/// Exposed on its own because it is the post-condition of extraction, and a
/// post-condition deserves to be testable without having to first produce a
/// successful extraction.
///
/// I6: the scalar is never rendered; every failure is a unit-ish variant.
pub fn verify_scalar_opens_both_commitments(
    secret: &[u8; 32],
    pre: &PreSignatureBytes,
    adaptor_address_committed: &[u8; 20],
) -> Result<()> {
    if !is_canonical_scalar(secret) || !dom_leg::scalar_is_canonical(secret) {
        return Err(HarnessError::NonCanonicalScalar);
    }
    let addr = adaptor_address_of_scalar(secret).map_err(|_| HarnessError::NonCanonicalScalar)?;
    if &addr != adaptor_address_committed {
        return Err(HarnessError::AdaptorPointMismatch);
    }
    // The DOM side committed to a compressed point; the EVM side committed to
    // its address. Both must be the same point, so compare the point itself
    // rather than only the (20-byte, lossy) address.
    let point = adaptor_point_of_scalar(secret).map_err(|_| HarnessError::NonCanonicalScalar)?;
    if point != pre.adaptor_point().0 {
        return Err(HarnessError::AdaptorPointMismatch);
    }
    // Belt and braces: the pre-signature's point must also hash to the same
    // EVM address, so a malformed 33-byte encoding cannot slip through.
    let from_point =
        adaptor_address(&pre.adaptor_point().0).map_err(|_| HarnessError::AdaptorPointMismatch)?;
    if &from_point != adaptor_address_committed {
        return Err(HarnessError::AdaptorPointMismatch);
    }
    Ok(())
}

/// Builds the unsigned `claim(lockId, t)` call.
///
/// This is the one artifact in the system whose calldata contains the scalar —
/// necessarily, because publishing `t` on the EVM leg *is* the claim. It is
/// never logged and never `Debug`-printed by this crate.
pub fn build_claim_call(
    deployment: &EvmDeployment,
    lock_id: [u8; 32],
    binding: [u8; 32],
    secret: &[u8; 32],
) -> Result<UnsignedEvmCall> {
    let mut calldata = Vec::with_capacity(4 + 64);
    calldata.extend_from_slice(&selector(SIG_CLAIM));
    calldata.extend_from_slice(&concat_words(&[word_bytes32(lock_id), word_u256(*secret)])?);
    Ok(UnsignedEvmCall {
        version: UNSIGNED_CALL_VERSION,
        chain_id: deployment.chain_id,
        to: deployment.contract,
        value: [0u8; 32],
        gas_limit_hint: deployment.gas_limit_hint,
        lock_id,
        binding,
        calldata,
    })
}

/// Builds the unsigned `refund(lockId)` call.
pub fn build_refund_call(
    deployment: &EvmDeployment,
    lock_id: [u8; 32],
    binding: [u8; 32],
) -> Result<UnsignedEvmCall> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector(SIG_REFUND));
    calldata.extend_from_slice(&concat_words(&[word_bytes32(lock_id)])?);
    Ok(UnsignedEvmCall {
        version: UNSIGNED_CALL_VERSION,
        chain_id: deployment.chain_id,
        to: deployment.contract,
        value: [0u8; 32],
        gas_limit_hint: deployment.gas_limit_hint,
        lock_id,
        binding,
        calldata,
    })
}

// ---------------------------------------------------------------------------
// Route EVM -> DOM
// ---------------------------------------------------------------------------

/// Everything the EVM→DOM route is handed. Every field is re-validated; none
/// is trusted because a caller supplied it.
pub struct EvmToDomInput<'a> {
    /// Deployment the observation came from.
    pub deployment: EvmDeployment,
    /// Full lock terms, as the adapter reconstructed and proved them.
    pub terms: LockTerms,
    /// `lockId` topic of the observed `Claimed` log.
    pub observed_lock_id: [u8; 32],
    /// `binding` topic of the observed `Claimed` log.
    pub observed_binding: [u8; 32],
    /// Height of the block carrying the log.
    pub observed_height: u64,
    /// Finalized checkpoint the observation was taken against.
    pub finalized_height: u64,
    /// The scalar the log published.
    pub revealed: RevealedSecretBytes,
    /// The DOM pre-signature this settlement froze.
    pub pre_signature: &'a PreSignatureBytes,
    /// Current DOM-leg clock reading (block height).
    pub dom_now: TimelockPoint,
    /// DOM-leg refund deadline (block height).
    pub dom_deadline: TimelockPoint,
}

/// The DOM claim this route authorises: a final DOM signature plus the lock it
/// closes. Produced **only** when the DOM leg actually adapted the
/// pre-signature.
#[derive(Clone, PartialEq, Eq)]
pub struct DomClaimAuthorisation {
    /// Lock the claim closes, in the DOM-side identifier space.
    pub lock_id: [u8; 32],
    /// The final DOM signature, as `dom-leg` produced it.
    pub signature: Vec<u8>,
}

impl core::fmt::Debug for DomClaimAuthorisation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DomClaimAuthorisation")
            .field("lock_id", &self.lock_id)
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

/// Everything the evidence-driven EVM→DOM entry point is handed.
///
/// It carries no observation of its own: the chain-side facts all come out of
/// the canonical evidence record, which the adapter re-derives and re-checks.
pub struct EvmEvidenceToDomInput<'a> {
    /// Canonical `adapter_evm::EvmEvidence` encoding of the `Claimed` log.
    pub evidence: &'a [u8],
    /// The DOM pre-signature this settlement froze.
    pub pre_signature: &'a PreSignatureBytes,
    /// Current DOM-leg clock reading (block height).
    pub dom_now: TimelockPoint,
    /// DOM-leg refund deadline (block height).
    pub dom_deadline: TimelockPoint,
}

// --- BEGIN ROUTE EVM->DOM (this region must not name the recovery op) ---

/// EVM→DOM, complete: from a canonical evidence record to a DOM claim.
///
/// This is the entry point the settlement engine should use, because it is the
/// one where **every** validation in the ordered list actually runs. The
/// deployment-side half is decided by the adapter — the only component allowed
/// to interpret EVM chain evidence (I9) — and the settlement-side half by
/// [`evm_to_dom`]:
///
/// | # | check | decided by |
/// |---|---|---|
/// | 1 | `chainId` | `EvmEvidence::verify_static` |
/// | 2 | contract address | `EvmEvidence::verify_static` |
/// | 3 | contract codehash | `EvmEvidence::verify_static` |
/// | 4 | ABI decode of the log data | `EvmEvidence::verify_onchain` |
/// | 5 | emitter address | `EvmEvidence::verify_onchain` |
/// | 6 | `topics[0]` and topic arity | `EvmEvidence::verify_onchain` |
/// | 7 | receipt `status == 1` | `EvmEvidence::verify_onchain` |
/// | 8 | transaction hash | `EvmEvidence::verify_onchain` |
/// | 9 | log index | `EvmEvidence::verify_onchain` |
/// | 10 | block hash and finalized ancestry | `EvmEvidence::verify_onchain` |
/// | 11 | `lockId` re-derivation | `verify_static`, then again in [`evm_to_dom`] |
/// | 12 | `binding` re-derivation | `verify_static`, then again in [`evm_to_dom`] |
/// | 13 | `session_id`, `terms_hash` | bound into `binding`; the terms come from the evidence |
/// | 14 | `T` and `address(T)` | `verify_static`, then again in [`evm_to_dom`] against the pre-signature |
/// | 15 | `0 < t < n` | `verify_static`, then again in [`evm_to_dom`] |
///
/// Every one of them is fail-closed, and the duplicated ones are duplicated on
/// purpose: this function is the last place before an irreversible action, and
/// a check that is cheap to repeat is cheaper than trusting a caller.
///
/// The working buffer holding the scalar is zeroized before returning.
pub fn evm_to_dom_from_evidence<R: JsonRpc, L: DomLegOps>(
    adapter: &EvmAdapter<R>,
    leg: &L,
    dom_policy: &TimelockPolicy,
    input: &EvmEvidenceToDomInput<'_>,
) -> Result<DomClaimAuthorisation> {
    // 1..10. The adapter decides every deployment- and chain-side fact. It
    // both re-derives the static bindings and asks the chain whether the log
    // really is where the record says it is.
    let outcome = adapter.verify_evidence_blocking(input.evidence)?;
    let VerifiedOutcome::Claimed { revealed, height } = outcome else {
        // A `Funded` or `Refunded` record is not a claim, and must never be
        // read as one.
        return Err(HarnessError::Adapter(AdapterError::EvidenceInvalid));
    };
    let record = EvmEvidence::decode(input.evidence)?;
    if height != record.block_number {
        return Err(HarnessError::Adapter(AdapterError::EvidenceInvalid));
    }
    let cfg = adapter.config();
    let deployment = EvmDeployment {
        chain_id: cfg.chain_id,
        contract: cfg.contract,
        funder: cfg.funder,
        gas_limit_hint: cfg.gas_limit_hint,
    };

    // 11..15 plus the DOM-side steps, in [`evm_to_dom`].
    let mut inner = EvmToDomInput {
        deployment,
        terms: record.terms,
        observed_lock_id: record.lock_id,
        observed_binding: record.binding,
        observed_height: record.block_number,
        finalized_height: record.finalized_height,
        revealed,
        pre_signature: input.pre_signature,
        dom_now: input.dom_now,
        dom_deadline: input.dom_deadline,
    };
    let authorised = evm_to_dom(leg, dom_policy, &inner);
    // The scalar was already public before this function ran — it came out of
    // a finalized on-chain log — but the working copy still does not outlive
    // the call (I1/I6).
    inner.revealed.0.zeroize();
    authorised
}

/// EVM→DOM: turn a finalized on-chain `Claimed(t)` into a DOM claim.
///
/// Validates in the order documented in the module header and then calls
/// `adapt_claim`. It never calls the *other* DOM-leg operation, the one that
/// recovers a scalar from a signature: `t` is already public, and re-deriving
/// it here would be a second authority over the same value — one that, now
/// that the seam is live, would return a plausible answer instead of an error.
/// The g_f3 suite enforces this three ways: by counting calls through
/// [`DomLegOps`], structurally over this source region, and with a leg whose
/// recovery operation panics if it is ever reached.
pub fn evm_to_dom<L: DomLegOps>(
    leg: &L,
    dom_policy: &TimelockPolicy,
    input: &EvmToDomInput<'_>,
) -> Result<DomClaimAuthorisation> {
    // 1. Finality. An observation above the checkpoint is not a fact.
    if input.observed_height > input.finalized_height {
        return Err(HarnessError::NotFinal {
            observed: input.observed_height,
            finalized: input.finalized_height,
        });
    }

    // 2-3-5. Canonicity, the EVM commitment and the DOM commitment.
    verify_scalar_opens_both_commitments(
        &input.revealed.0,
        input.pre_signature,
        &input.terms.adaptor_address,
    )?;

    // 4. The observation belongs to this settlement on this deployment.
    let (binding, lock_id) = rederive(&input.deployment, &input.terms)?;
    if binding != input.observed_binding || lock_id != input.observed_lock_id {
        return Err(HarnessError::BindingMismatch);
    }

    // 4b. The pre-signature must belong to this DOM session. That check is
    // NOT repeated here: `dom-leg` performs it inside the operation below,
    // through `pre_signature_from_wire`, and names the divergence with the
    // same `TemplateMismatch`/`TranscriptMismatch` this function would have
    // returned. Doing it twice against a locally-held copy of the bindings
    // would create a second definition of "belongs to this session" that
    // could drift from the authority's.

    // 6. There must still be a window on the DOM leg. The policy refuses a
    // point from the wrong domain, so a timestamp cannot arrive here disguised
    // as a height.
    dom_policy.require_actionable(input.dom_now, input.dom_deadline)?;

    // 7. The DOM leg. If it refuses, this function refuses: nothing is
    // fabricated and no claim is authorised.
    let secret = Zeroizing::new(input.revealed.0);
    let signature = leg.adapt_claim_from_wire(input.pre_signature, &secret)?;
    if signature.is_empty() {
        // A zero-length signature is not a signature. Defensive, because the
        // caller of this function is about to spend money on the strength of it.
        return Err(HarnessError::DomLeg(dom_leg::LegError::VerificationFailed));
    }
    Ok(DomClaimAuthorisation { lock_id, signature })
}

// --- END ROUTE EVM->DOM ---

// ---------------------------------------------------------------------------
// Route DOM -> EVM
// ---------------------------------------------------------------------------

/// Everything the DOM→EVM route is handed.
pub struct DomToEvmInput<'a> {
    /// Deployment the EVM claim will be sent to.
    pub deployment: EvmDeployment,
    /// Full lock terms of the EVM leg.
    pub terms: LockTerms,
    /// The DOM pre-signature this settlement froze.
    pub pre_signature: &'a PreSignatureBytes,
    /// The final DOM signature observed on the DOM leg.
    pub final_signature: &'a [u8],
    /// Current EVM-leg clock reading (UNIX timestamp).
    pub evm_now: TimelockPoint,
}

/// DOM→EVM: recover `t` from the DOM signature and authorise the EVM claim.
///
/// Extraction comes first because there is nothing to validate until there is a
/// scalar; every check after it is a post-condition on what came out. If the
/// DOM leg refuses to extract, this function refuses, and no EVM call exists to
/// be broadcast.
///
/// This is the direction in which `t` is genuinely secret when it appears: it
/// is recovered locally and becomes public only when the returned artifact is
/// broadcast. The scalar therefore lives in a [`Zeroizing`] buffer that dies
/// with this call frame, the plain array the DOM leg handed back is wiped as
/// soon as it has been copied in, and the only thing carrying the value out is
/// the `claim(lockId, t)` calldata.
pub fn dom_to_evm<L: DomLegOps>(
    leg: &L,
    evm_policy: &TimelockPolicy,
    input: &DomToEvmInput<'_>,
) -> Result<UnsignedEvmCall> {
    // 1. The pre-signature must belong to this DOM session before anything
    // cryptographic runs. `dom-leg` enforces that inside the extraction below
    // (`pre_signature_from_wire`), and is the single definition of it; this
    // route does not keep a second copy of the bindings to check against.

    // 2. Recover the scalar. This is the only route that may do so. The plain
    // array the boundary type carries is copied into a zeroizing buffer and
    // then wiped, so from here on there is exactly one live copy.
    let mut recovered = leg.extract_revealed_secret(input.pre_signature, input.final_signature)?;
    let secret = Zeroizing::new(recovered.0);
    recovered.0.zeroize();

    // 3. Post-conditions on what came out: canonical, opens the committed point
    // `T`, and opens the EVM contract's `adaptorAddress`.
    verify_scalar_opens_both_commitments(
        &secret,
        input.pre_signature,
        &input.terms.adaptor_address,
    )?;

    // 4. There must still be a window before the EVM deadline. A `claim` after
    // `deadline` reverts, and the funds would then only be refundable to the
    // funder — so acting too late is worse than not acting.
    evm_policy.require_actionable(
        input.evm_now,
        TimelockPoint::timestamp(input.terms.deadline),
    )?;

    // 5. Build the unsigned artifact. The harness does not sign it and does not
    // broadcast it; that happens outside, with the key.
    let (binding, lock_id) = rederive(&input.deployment, &input.terms)?;
    build_claim_call(&input.deployment, lock_id, binding, &secret)
}

/// Authorises the deadline refund of the EVM leg.
///
/// Separate from the two settlement routes because it is not a settlement: it
/// is the failure path, it needs no secret and it touches the DOM leg not at
/// all. It uses [`TimelockPolicy::require_expired`], which applies the
/// observation margins in the opposite direction so that a stale view cannot
/// make the harness refund early.
pub fn refund_after_deadline(
    deployment: &EvmDeployment,
    terms: &LockTerms,
    evm_policy: &TimelockPolicy,
    evm_now: TimelockPoint,
) -> Result<UnsignedEvmCall> {
    evm_policy.require_expired(evm_now, TimelockPoint::timestamp(terms.deadline))?;
    let (binding, lock_id) = rederive(deployment, terms)?;
    build_refund_call(deployment, lock_id, binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapter_evm::abi::{selector as sel, word_u128};
    use adapter_evm::binding::Direction;
    use dom_leg::pre_signature_layout as layout;

    fn deployment() -> EvmDeployment {
        EvmDeployment {
            chain_id: 31337,
            contract: [0xC0; 20],
            funder: [0xF0; 20],
            gas_limit_hint: 300_000,
        }
    }

    fn scalar(seed: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[31] = seed.max(1);
        t[7] = seed;
        t
    }

    fn pre_for(t: &[u8; 32]) -> PreSignatureBytes {
        let mut buf = [0u8; layout::ENCODED_LEN];
        buf[layout::CLAIM_TEMPLATE_HASH].fill(1);
        buf[layout::ADAPTOR_POINT]
            .copy_from_slice(&adaptor_point_of_scalar(t).unwrap_or_else(|_| unreachable!()));
        buf[layout::TRANSCRIPT_HASH].fill(2);
        PreSignatureBytes::from_slice(&buf).unwrap_or_else(|_| unreachable!("fixed length"))
    }

    fn terms_for(t: &[u8; 32]) -> LockTerms {
        LockTerms {
            dom_chain_id: [0x11; 32],
            direction: Direction::DomToEvm.as_u8(),
            session_id: [0x22; 32],
            terms_hash: [0x33; 32],
            participants_hash: [0x44; 32],
            asset: [0u8; 20],
            amount: word_u128(1_000),
            beneficiary: [0xBE; 20],
            adaptor_address: adaptor_address_of_scalar(t).unwrap_or_else(|_| unreachable!()),
            deadline: 1_900_000_000,
        }
    }

    #[test]
    fn a_correct_scalar_opens_both_commitments() {
        let t = scalar(5);
        let pre = pre_for(&t);
        let terms = terms_for(&t);
        assert_eq!(
            verify_scalar_opens_both_commitments(&t, &pre, &terms.adaptor_address),
            Ok(())
        );
    }

    #[test]
    fn a_non_canonical_scalar_never_reaches_a_curve_operation() {
        let t = scalar(5);
        let pre = pre_for(&t);
        let terms = terms_for(&t);
        for bad in [[0u8; 32], [0xFFu8; 32]] {
            assert_eq!(
                verify_scalar_opens_both_commitments(&bad, &pre, &terms.adaptor_address),
                Err(HarnessError::NonCanonicalScalar)
            );
        }
    }

    #[test]
    fn a_scalar_for_a_different_point_is_refused() {
        let t = scalar(5);
        let other = scalar(6);
        let pre = pre_for(&t);
        let terms = terms_for(&t);
        assert_eq!(
            verify_scalar_opens_both_commitments(&other, &pre, &terms.adaptor_address),
            Err(HarnessError::AdaptorPointMismatch)
        );
    }

    #[test]
    fn a_pre_signature_committing_to_another_point_is_refused() {
        // The EVM address matches but the DOM-side point does not: exactly the
        // splice this check exists to catch.
        let t = scalar(5);
        let terms = terms_for(&t);
        let foreign_pre = pre_for(&scalar(9));
        assert_eq!(
            verify_scalar_opens_both_commitments(&t, &foreign_pre, &terms.adaptor_address),
            Err(HarnessError::AdaptorPointMismatch)
        );
    }

    #[test]
    fn the_claim_call_is_deterministic_and_carries_no_value() {
        let t = scalar(5);
        let d = deployment();
        let a = build_claim_call(&d, [1u8; 32], [2u8; 32], &t).expect("call");
        let b = build_claim_call(&d, [1u8; 32], [2u8; 32], &t).expect("call");
        assert_eq!(a, b, "I7: the artifact must be byte-identical");
        assert_eq!(a.value, [0u8; 32], "claim never carries ETH");
        assert_eq!(a.calldata.len(), 4 + 64);
        assert_eq!(&a.calldata[..4], &sel(SIG_CLAIM));
        assert_eq!(&a.calldata[4..36], &[1u8; 32][..]);
        assert_eq!(&a.calldata[36..68], &t[..]);
    }

    #[test]
    fn the_refund_call_is_deterministic_and_carries_no_secret() {
        let d = deployment();
        let a = build_refund_call(&d, [1u8; 32], [2u8; 32]).expect("call");
        assert_eq!(
            a,
            build_refund_call(&d, [1u8; 32], [2u8; 32]).expect("call")
        );
        assert_eq!(a.calldata.len(), 4 + 32);
        assert_eq!(&a.calldata[..4], &sel(SIG_REFUND));
    }

    #[test]
    fn refund_is_refused_until_the_deadline_is_safely_past() {
        let t = scalar(5);
        let terms = terms_for(&t);
        let p = TimelockPolicy::evm();
        let d = deployment();
        assert!(matches!(
            refund_after_deadline(&d, &terms, &p, TimelockPoint::timestamp(terms.deadline + 1)),
            Err(HarnessError::Timelock(_))
        ));
        let safe = terms.deadline + p.finality_margin + p.rpc_lag_margin;
        assert!(refund_after_deadline(&d, &terms, &p, TimelockPoint::timestamp(safe)).is_ok());
    }

    #[test]
    fn refund_refuses_a_clock_reading_from_the_wrong_domain() {
        let t = scalar(5);
        let terms = terms_for(&t);
        assert!(matches!(
            refund_after_deadline(
                &deployment(),
                &terms,
                &TimelockPolicy::evm(),
                TimelockPoint::height(9_999_999_999)
            ),
            Err(HarnessError::Timelock(
                crate::timelock::TimelockError::DomainMismatch { .. }
            ))
        ));
    }

    #[test]
    fn rederivation_is_deterministic_and_funder_bound() {
        let t = scalar(5);
        let terms = terms_for(&t);
        let a = rederive(&deployment(), &terms).expect("derivation");
        assert_eq!(a, rederive(&deployment(), &terms).expect("derivation"));
        let mut other = deployment();
        other.funder = [0xF1; 20];
        let b = rederive(&other, &terms).expect("derivation");
        assert_eq!(a.0, b.0, "binding does not depend on the funder");
        assert_ne!(a.1, b.1, "lockId does: anti-squatting");
    }
}

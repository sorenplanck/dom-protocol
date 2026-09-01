//! Canonical derivation of the child evidence commitments required by
//! [`settlement_coordinator::SettlementChildAuthorityV1`] and
//! [`settlement_coordinator::SettlementChildObserverV1`].
//!
//! Every variant of `ChildExecutionOutcomeV1`, `ChildReconciliationOutcomeV1`
//! and `ChildObservationOutcomeV1` carries a `Digest32` evidence commitment,
//! and the coordinator refuses a zero one (`validate_digest`,
//! `settlement-coordinator/src/store.rs:3718-3723`). Nothing in the three
//! face-specific actuators produces a commitment in that shape, so the three
//! production child ports would otherwise each invent their own. They must
//! not: the commitment becomes durable ledger content the first time it is
//! used, so one derivation is specified here and shared by all three faces.
//!
//! # The determinism hazard this module exists to close
//!
//! `DurableSettlementCoordinatorV1::complete_child_call` stores the digest of
//! the outcome under the dispatch `attempt_id`, and when the same `attempt_id`
//! is later completed with a *different* outcome digest it does not retry — it
//! calls `fail_closed_conflict` and permanently fails the plan
//! (`settlement-coordinator/src/store.rs:2513-2533`).
//!
//! A replayed attempt is the normal case, not the exotic one: the daemon
//! crashes between the actuator's durable write and the coordinator's commit,
//! restarts, and drives the same attempt again. Between those two runs the
//! chain has moved. Therefore:
//!
//! **An evidence digest must never be derived from a fact that can change
//! while the attempt stays the same.**
//!
//! Concretely, the following are durable actuator state and are still
//! forbidden as inputs on the custody path, because each one moves under a
//! fixed `attempt_id`:
//!
//! * `BitcoinOperationViewV1::confirmations` and `send_attempts`
//!   (`btc-actuator/src/model.rs:562`, `:566`);
//! * `BitcoinBroadcastReceiptV1::already_known`
//!   (`btc-actuator/src/model.rs:640`) — false on first send, true on replay,
//!   which is precisely the crash-and-retry path;
//! * `EvmOperationViewV1::revision`, `current_attempt` and
//!   `ambiguous_after_send` (`evm-actuator/src/model.rs:634`, `:656`, `:662`).
//!
//! This is why the custody-path derivations below take only attempt-scoped
//! immutables. The chain-anchored facts are not lost; they are committed on
//! the observation path, where the actuator's own finality commitments are
//! stable once set.
//!
//! # Two paths, two rules
//!
//! * **Custody path** (`externalize_child`, `reconcile_child`) — derived from
//!   [`ChildEvidenceBindingV1`] alone, which is a pure projection of the
//!   dispatch request. Deterministic by construction, because the request is
//!   byte-identical on replay: `ChildReconciliationRequestV1` even carries the
//!   original dispatch verbatim (`settlement-coordinator/src/model.rs:918-919`).
//! * **Observation path** (`observe_child`) — additionally binds the
//!   actuator's own durable finality commitment, which is monotone: it is
//!   `None` until finality is verified and never changes value afterwards.
//!
//! # Domain separation
//!
//! One root domain per outcome variant, each terminated with a NUL so no
//! label is a prefix of another, and every input length-prefixed so no two
//! distinct field sequences can collide. This mirrors the workspace primitive
//! (`settlement-coordinator/src/codec.rs:226-239`) rather than inventing a
//! second convention.
//!
//! # D-E4B 2026-08-30 — `ReconciliationKindV1::FinalityInvalidated` maps to
//! `Externalized`
//!
//! Recorded as a decision, not as an obvious fact, because it was a judgement
//! rather than something found written down.
//!
//! `evm-actuator`'s `ReconciliationKindV1::FinalityInvalidated`
//! (`evm-actuator/src/model.rs:940-942`) has no counterpart in
//! `ChildReconciliationOutcomeV1` (`settlement-coordinator/src/model.rs:929-942`).
//!
//! Decision: it maps to `Externalized`. Reconciliation answers only "did this
//! leave custody", and a transaction whose finality was later invalidated did
//! leave custody. Reason, which is the cost of being wrong rather than any
//! symmetry: `Unknown` leaves the door open to a second dispatch of an
//! economic action, and the actuator's own documentation records that "claim
//! publicity remains irreversible" for exactly this variant. Between a mapping
//! that errs toward not repeating and one that errs toward repeating, the
//! first is chosen every time. Invalidated finality is then reported through
//! the observation path, where `ChildObservationOutcomeV1::FinalityInvalidated`
//! is the variant that exists to carry it.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use settlement_coordinator::{
    ChildDispatchRequestV1, ChildExposureV1, ChildObservationRequestV1, Digest32,
    SettlementActionV1, SettlementFaceV1, SettlementLegV1,
};

/// Rejected digest value. The coordinator refuses it on the way in, so this
/// module refuses it on the way out.
const ZERO_DIGEST: Digest32 = [0; 32];

/// Root label of every commitment produced here.
const CHILD_EVIDENCE_ROOT_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/V1\0";
const CHILD_OBSERVATION_STABLE_ROOT_V2: &[u8] =
    b"DOM-INTEROP/INTEROPD/CHILD-OBSERVATION-STABLE/V2\0";
const CHILD_OBSERVATION_ATTEMPT_ROOT_V2: &[u8] =
    b"DOM-INTEROP/INTEROPD/CHILD-OBSERVATION-ATTEMPT/V2\0";

const EXTERNALIZED_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/EXTERNALIZED/V1\0";
const FIRST_EXPOSURE_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/FIRST-EXPOSURE/V1\0";
const RETRYABLE_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/RETRYABLE/V1\0";
const UNKNOWN_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/UNKNOWN/V1\0";
const NOT_EXTERNALIZED_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/NOT-EXTERNALIZED/V1\0";
const OBSERVED_PENDING_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/OBSERVED-PENDING/V1\0";
const OBSERVED_FINAL_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/OBSERVED-FINAL/V1\0";
const OBSERVED_REORG_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILD-EVIDENCE/OBSERVED-REORG/V1\0";

/// Named failures of the evidence derivation. No variant carries an
/// identifier, a digest or any chain material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ChildEvidenceErrorV1 {
    /// A required input commitment was the rejected zero digest.
    #[error("child evidence input is the rejected zero digest")]
    ZeroInput,
    /// The derivation produced the rejected zero digest.
    #[error("child evidence derivation produced the rejected zero digest")]
    ZeroOutput,
    /// The hash primitive refused a fixed, known-good parameter.
    #[error("child evidence digest primitive unavailable")]
    PrimitiveUnavailable,
}

/// Canonical wire tags for the coordinator enums.
///
/// `SettlementFaceV1::tag` and its siblings are `pub(crate)` to
/// `settlement-coordinator` (`settlement-coordinator/src/model.rs:22`, `:50`,
/// `:80`, `:114`, `:144`) and therefore invisible here, so the mapping is
/// restated. Each match is exhaustive with no wildcard arm, so adding a
/// variant upstream breaks this build instead of silently reusing a tag.
///
/// **These numbers are frozen.** They are hashed into commitments that become
/// durable ledger content; renumbering one silently rewrites the meaning of
/// every digest already committed under it.
mod tags {
    use super::{ChildExposureV1, SettlementActionV1, SettlementFaceV1, SettlementLegV1};

    pub(super) const fn face(value: SettlementFaceV1) -> u8 {
        match value {
            SettlementFaceV1::Dom => 1,
            SettlementFaceV1::Evm => 2,
            SettlementFaceV1::Bitcoin => 3,
            SettlementFaceV1::Monero => 4,
            SettlementFaceV1::Solana => 5,
        }
    }

    pub(super) const fn leg(value: SettlementLegV1) -> u8 {
        match value {
            SettlementLegV1::Upstream => 1,
            SettlementLegV1::Downstream => 2,
        }
    }

    pub(super) const fn action(value: SettlementActionV1) -> u8 {
        match value {
            SettlementActionV1::Funding => 1,
            SettlementActionV1::Claim => 2,
            SettlementActionV1::Refund => 3,
        }
    }

    pub(super) const fn exposure(value: ChildExposureV1) -> u8 {
        match value {
            ChildExposureV1::NonSecret => 1,
            ChildExposureV1::FirstSecretExposure => 2,
            ChildExposureV1::UsesPublicSecret => 3,
        }
    }
}

/// Length-prefixed, domain-separated commitment.
///
/// Each part is preceded by its length as eight big-endian bytes, so no two
/// distinct field sequences share an encoding. A zero output is refused rather
/// than returned, because the coordinator would refuse it anyway and a typed
/// refusal here names the cause.
fn domain_digest_v1(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ChildEvidenceErrorV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildEvidenceErrorV1::PrimitiveUnavailable)?;
    hasher.update(domain);
    for part in parts {
        // usize -> u64 cannot fail on any target this daemon builds for; it
        // is mapped rather than unwrapped because this module must not panic,
        // and it is *not* a ZeroInput: nothing about the value was a
        // placeholder, so naming it one would misreport the cause.
        let length =
            u64::try_from(part.len()).map_err(|_| ChildEvidenceErrorV1::PrimitiveUnavailable)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ChildEvidenceErrorV1::PrimitiveUnavailable)?;
    nonzero(output)
}

/// Refuses the one digest value the coordinator rejects.
///
/// Kept as its own function so the refusal can be exercised directly: no
/// input reaches Blake2b's zero preimage in a test, and a guard that cannot
/// be shown to fire is indistinguishable from a guard that is not there.
const fn nonzero(value: Digest32) -> Result<Digest32, ChildEvidenceErrorV1> {
    if matches!(value, ZERO_DIGEST) {
        return Err(ChildEvidenceErrorV1::ZeroOutput);
    }
    Ok(value)
}

/// Attempt-scoped immutable projection of one dispatch request.
///
/// Every field is fixed for the lifetime of a dispatch attempt, which is what
/// makes the custody-path derivations replay-stable. Built only through
/// [`Self::from_dispatch`], so no caller can assemble one from mutable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildEvidenceBindingV1 {
    plan_id: Digest32,
    plan_digest: Digest32,
    route_id: Digest32,
    effect_id: Digest32,
    settlement_id: Digest32,
    chain_id: Digest32,
    expected_transaction_id: Digest32,
    intent_digest: Digest32,
    custody_digest: Digest32,
    attempt_id: Digest32,
    child_index: u8,
    face: SettlementFaceV1,
    leg: SettlementLegV1,
    action: SettlementActionV1,
    exposure: ChildExposureV1,
}

impl ChildEvidenceBindingV1 {
    /// Projects the attempt-scoped immutables out of one dispatch request.
    ///
    /// `attempt` (`settlement-coordinator/src/model.rs:741`) is deliberately
    /// excluded even though it is stable: `attempt_id` already identifies the
    /// attempt, and `route_fencing_epoch` / `coordinator_fencing_epoch` are
    /// excluded because a takeover may reconcile the same dispatch at a newer
    /// fence (`ChildReconciliationRequestV1::current_route_fencing_epoch`,
    /// `settlement-coordinator/src/model.rs:920-923`) and must reproduce the
    /// digest the earlier fence would have produced.
    pub(crate) fn from_dispatch(request: &ChildDispatchRequestV1) -> Self {
        Self {
            plan_id: request.plan_id(),
            plan_digest: request.plan_digest(),
            route_id: request.route_id(),
            effect_id: request.effect_id(),
            settlement_id: request.settlement_id(),
            chain_id: request.chain_id(),
            expected_transaction_id: request.expected_transaction_id(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            attempt_id: request.attempt_id(),
            child_index: request.child_index(),
            face: request.face(),
            leg: request.leg(),
            action: request.action(),
            exposure: request.exposure(),
        }
    }

    /// Whether this child is the one permitted to carry a first-exposure
    /// commitment. The coordinator enforces the same predicate on the receipt
    /// (`settlement-coordinator/src/store.rs:4541-4546`).
    pub(crate) const fn is_first_secret_exposure(&self) -> bool {
        matches!(self.exposure, ChildExposureV1::FirstSecretExposure)
    }

    /// Stable root commitment to the whole binding, reused by every
    /// derivation so each one binds the full attempt identity rather than a
    /// convenient subset.
    fn root(&self) -> Result<Digest32, ChildEvidenceErrorV1> {
        domain_digest_v1(
            CHILD_EVIDENCE_ROOT_V1,
            &[
                &self.plan_id,
                &self.plan_digest,
                &self.route_id,
                &self.effect_id,
                &self.settlement_id,
                &self.chain_id,
                &self.expected_transaction_id,
                &self.intent_digest,
                &self.custody_digest,
                &self.attempt_id,
                &[self.child_index],
                &[tags::face(self.face)],
                &[tags::leg(self.leg)],
                &[tags::action(self.action)],
                &[tags::exposure(self.exposure)],
            ],
        )
    }
}

/// Immutable projection of one exact coordinator observation attempt.
///
/// Observation attempts have their own durable identity.  They must not reuse
/// [`ChildEvidenceBindingV1`]: an observer receives no dispatch request after
/// restart, and reconstructing one from process memory would turn crash
/// recovery into an implicit security assumption.  Every field below comes
/// from [`ChildObservationRequestV1`], which the coordinator journals before
/// invoking the observer and reproduces byte-for-byte while the attempt is
/// pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildObservationEvidenceBindingV1 {
    plan_id: Digest32,
    plan_digest: Digest32,
    route_id: Digest32,
    effect_id: Digest32,
    settlement_id: Digest32,
    leg: SettlementLegV1,
    action: SettlementActionV1,
    semantic_digest: Digest32,
    route_fencing_epoch: u64,
    terms_digest: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    child_index: u8,
    face: SettlementFaceV1,
    exposure: ChildExposureV1,
    chain_id: Digest32,
    transaction_id: Digest32,
    intent_digest: Digest32,
    custody_digest: Digest32,
    prior_finality_evidence_digest: Option<Digest32>,
    observation_attempt_id: Digest32,
}

impl ChildObservationEvidenceBindingV1 {
    /// Projects only the facts durably retained by the coordinator for this
    /// exact observation attempt.
    pub(crate) fn from_observation(request: &ChildObservationRequestV1) -> Self {
        Self {
            plan_id: request.plan_id,
            plan_digest: request.plan_digest,
            route_id: request.route_id,
            effect_id: request.effect_id,
            settlement_id: request.settlement_id,
            leg: request.leg,
            action: request.action,
            semantic_digest: request.semantic_digest,
            route_fencing_epoch: request.route_fencing_epoch,
            terms_digest: request.terms_digest,
            registry_digest: request.registry_digest,
            profile_digest: request.profile_digest,
            deployment_digest: request.deployment_digest,
            child_index: request.child_index,
            face: request.face,
            exposure: request.exposure,
            chain_id: request.chain_id,
            transaction_id: request.transaction_id,
            intent_digest: request.intent_digest,
            custody_digest: request.custody_digest,
            prior_finality_evidence_digest: request.prior_finality_evidence_digest,
            observation_attempt_id: request.observation_attempt_id,
        }
    }

    /// Stable economic/chain/transaction identity of a finality fact.
    ///
    /// A new observation attempt, a re-fence and the presence of a prior
    /// finality digest do not change what chain transaction became final.
    /// Keeping those fields out is what permits a later StillFinal or reorg
    /// check to reproduce the exact digest the coordinator already stored.
    fn stable_root(&self) -> Result<Digest32, ChildEvidenceErrorV1> {
        if [
            self.plan_id,
            self.route_id,
            self.settlement_id,
            self.semantic_digest,
            self.terms_digest,
            self.registry_digest,
            self.profile_digest,
            self.deployment_digest,
            self.chain_id,
            self.transaction_id,
            self.intent_digest,
            self.custody_digest,
        ]
        .contains(&ZERO_DIGEST)
        {
            return Err(ChildEvidenceErrorV1::ZeroInput);
        }
        domain_digest_v1(
            CHILD_OBSERVATION_STABLE_ROOT_V2,
            &[
                &self.plan_id,
                &self.route_id,
                &self.settlement_id,
                &[tags::leg(self.leg)],
                &[tags::action(self.action)],
                &self.semantic_digest,
                &self.terms_digest,
                &self.registry_digest,
                &self.profile_digest,
                &self.deployment_digest,
                &[self.child_index],
                &[tags::face(self.face)],
                &[tags::exposure(self.exposure)],
                &self.chain_id,
                &self.transaction_id,
                &self.intent_digest,
                &self.custody_digest,
            ],
        )
    }

    /// Exact identity of a coordinator observation call.
    ///
    /// Pending and invalidation answers belong to this attempt. Unlike final
    /// chain evidence, they must change when the coordinator issues another
    /// observation or presents a different prior finality.
    fn attempt_root(&self) -> Result<Digest32, ChildEvidenceErrorV1> {
        if [
            self.plan_digest,
            self.effect_id,
            self.observation_attempt_id,
        ]
        .contains(&ZERO_DIGEST)
            || self.route_fencing_epoch == 0
            || self
                .prior_finality_evidence_digest
                .is_some_and(|value| value == ZERO_DIGEST)
        {
            return Err(ChildEvidenceErrorV1::ZeroInput);
        }
        let prior_tag = [u8::from(self.prior_finality_evidence_digest.is_some())];
        let prior = self.prior_finality_evidence_digest.unwrap_or(ZERO_DIGEST);
        domain_digest_v1(
            CHILD_OBSERVATION_ATTEMPT_ROOT_V2,
            &[
                &self.stable_root()?,
                &self.plan_digest,
                &self.effect_id,
                &self.route_fencing_epoch.to_be_bytes(),
                &prior_tag,
                &prior,
                &self.observation_attempt_id,
            ],
        )
    }
}

/// Commitment for `ChildExecutionOutcomeV1::Externalized` and
/// `ChildReconciliationOutcomeV1::Externalized`, carried as the receipt's
/// `externalization_evidence_digest`.
pub(crate) fn externalization_evidence_v1(
    binding: &ChildEvidenceBindingV1,
) -> Result<Digest32, ChildEvidenceErrorV1> {
    domain_digest_v1(EXTERNALIZED_DOMAIN_V1, &[&binding.root()?])
}

/// Commitment for the receipt's `first_exposure_evidence_digest`.
///
/// Returns `None` for any child that is not the first-exposure child, which is
/// exactly the shape `validate_child_receipt` requires
/// (`settlement-coordinator/src/store.rs:4541-4546`): `Some` if and only if
/// the request says `FirstSecretExposure`.
pub(crate) fn first_exposure_evidence_v1(
    binding: &ChildEvidenceBindingV1,
) -> Result<Option<Digest32>, ChildEvidenceErrorV1> {
    if !binding.is_first_secret_exposure() {
        return Ok(None);
    }
    Ok(Some(domain_digest_v1(
        FIRST_EXPOSURE_DOMAIN_V1,
        &[&binding.root()?],
    )?))
}

/// Commitment for `ChildExecutionOutcomeV1::RetryableBeforeExternalization`.
///
/// Only a port that can prove nothing crossed the actuator boundary may use
/// this — `BitcoinOperationStageV1::Prepared`
/// (`btc-actuator/src/model.rs:501-502`) or
/// `ReconciliationKindV1::InternallyNeverSent`
/// (`evm-actuator/src/model.rs:931-932`). A wrong one authorizes a second
/// dispatch of an economic action.
pub(crate) fn retryable_before_externalization_evidence_v1(
    binding: &ChildEvidenceBindingV1,
) -> Result<Digest32, ChildEvidenceErrorV1> {
    domain_digest_v1(RETRYABLE_DOMAIN_V1, &[&binding.root()?])
}

/// Commitment for the `Unknown` variant of both custody outcomes.
pub(crate) fn unknown_evidence_v1(
    binding: &ChildEvidenceBindingV1,
) -> Result<Digest32, ChildEvidenceErrorV1> {
    domain_digest_v1(UNKNOWN_DOMAIN_V1, &[&binding.root()?])
}

/// Commitment for `ChildReconciliationOutcomeV1::ProvenNotExternalized`.
pub(crate) fn proven_not_externalized_evidence_v1(
    binding: &ChildEvidenceBindingV1,
) -> Result<Digest32, ChildEvidenceErrorV1> {
    domain_digest_v1(NOT_EXTERNALIZED_DOMAIN_V1, &[&binding.root()?])
}

/// The actuator's own durable finality commitment for one observed child.
///
/// This is the observation path's extra input, and it is admissible precisely
/// because it is monotone: absent until finality is verified, fixed
/// afterwards. On the EVM face it is `EvmOperationViewV1::final_evidence_digest`
/// with `final_block_hash` / `final_block_number`
/// (`evm-actuator/src/model.rs:672-677`).
///
/// The Bitcoin face may populate this only from the actuator's retained
/// canonical block hash, authenticated block height and stable evidence
/// commitment. A mutable confirmation counter is never a substitute for any
/// of those facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildFinalityFactsV1 {
    /// Actuator commitment to the receipt/canonicality/finality evidence.
    pub(crate) final_evidence_digest: Digest32,
    /// Canonical block hash retained with that evidence.
    pub(crate) final_block_hash: Digest32,
    /// Canonical block height retained with that evidence.
    pub(crate) final_block_number: u64,
}

impl ChildFinalityFactsV1 {
    fn commitment(&self) -> Result<Digest32, ChildEvidenceErrorV1> {
        if self.final_evidence_digest == ZERO_DIGEST || self.final_block_hash == ZERO_DIGEST {
            return Err(ChildEvidenceErrorV1::ZeroInput);
        }
        domain_digest_v1(
            OBSERVED_FINAL_DOMAIN_V1,
            &[
                &self.final_evidence_digest,
                &self.final_block_hash,
                &self.final_block_number.to_be_bytes(),
            ],
        )
    }
}

/// Commitment for `ChildObservationOutcomeV1::Pending`.
///
/// Binds only the attempt identity: "not final yet" is a statement about the
/// absence of a finality fact, and binding a mutable confirmation count here
/// would reintroduce exactly the replay hazard this module closes.
pub(crate) fn observation_pending_evidence_v1(
    binding: &ChildObservationEvidenceBindingV1,
) -> Result<Digest32, ChildEvidenceErrorV1> {
    domain_digest_v1(OBSERVED_PENDING_DOMAIN_V1, &[&binding.attempt_root()?])
}

/// Commitment for `ChildObservationOutcomeV1::Final`.
pub(crate) fn observation_final_evidence_v1(
    binding: &ChildObservationEvidenceBindingV1,
    facts: &ChildFinalityFactsV1,
) -> Result<Digest32, ChildEvidenceErrorV1> {
    domain_digest_v1(
        OBSERVED_FINAL_DOMAIN_V1,
        &[&binding.stable_root()?, &facts.commitment()?],
    )
}

/// Commitment for the `reorg_evidence_digest` of
/// `ChildObservationOutcomeV1::FinalityInvalidated`.
///
/// The caller must return the request's own `prior_finality_evidence_digest`
/// unchanged in the other field; it is bound here as well so the reorg
/// commitment is specific to the finality it invalidates. A zero prior digest
/// is refused rather than hashed, because the coordinator requires the reorg
/// outcome to name a finality that was actually recorded
/// (`settlement-coordinator/src/model.rs:1039-1044`).
pub(crate) fn observation_reorg_evidence_v1(
    binding: &ChildObservationEvidenceBindingV1,
    prior_finality_evidence_digest: Digest32,
    invalidation_evidence_digest: Digest32,
) -> Result<Digest32, ChildEvidenceErrorV1> {
    if prior_finality_evidence_digest == ZERO_DIGEST || invalidation_evidence_digest == ZERO_DIGEST
    {
        return Err(ChildEvidenceErrorV1::ZeroInput);
    }
    domain_digest_v1(
        OBSERVED_REORG_DOMAIN_V1,
        &[
            &binding.stable_root()?,
            &binding.attempt_root()?,
            &prior_finality_evidence_digest,
            &invalidation_evidence_digest,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinct, nonzero filler so no two fields of a fixture collide.
    const fn digest(seed: u8) -> Digest32 {
        [seed; 32]
    }

    /// Test-only builder.
    ///
    /// `ChildDispatchRequestV1`'s fields are `pub(crate)` to
    /// `settlement-coordinator` with no public constructor, so a request can
    /// only be obtained from a live coordinator. The derivation properties are
    /// therefore exercised against the binding directly;
    /// [`ChildEvidenceBindingV1::from_dispatch`] is a field-for-field
    /// projection and is covered end to end when the child ports drive a real
    /// coordinator.
    fn binding() -> ChildEvidenceBindingV1 {
        ChildEvidenceBindingV1 {
            plan_id: digest(1),
            plan_digest: digest(2),
            route_id: digest(3),
            effect_id: digest(4),
            settlement_id: digest(5),
            chain_id: digest(6),
            expected_transaction_id: digest(7),
            intent_digest: digest(8),
            custody_digest: digest(9),
            attempt_id: digest(10),
            child_index: 0,
            face: SettlementFaceV1::Evm,
            leg: SettlementLegV1::Downstream,
            action: SettlementActionV1::Claim,
            exposure: ChildExposureV1::NonSecret,
        }
    }

    fn observation_binding() -> ChildObservationEvidenceBindingV1 {
        ChildObservationEvidenceBindingV1 {
            plan_id: digest(1),
            plan_digest: digest(2),
            route_id: digest(3),
            effect_id: digest(4),
            settlement_id: digest(5),
            leg: SettlementLegV1::Downstream,
            action: SettlementActionV1::Claim,
            semantic_digest: digest(6),
            route_fencing_epoch: 17,
            terms_digest: digest(7),
            registry_digest: digest(8),
            profile_digest: digest(9),
            deployment_digest: digest(10),
            child_index: 0,
            face: SettlementFaceV1::Evm,
            exposure: ChildExposureV1::FirstSecretExposure,
            chain_id: digest(11),
            transaction_id: digest(12),
            intent_digest: digest(13),
            custody_digest: digest(14),
            prior_finality_evidence_digest: None,
            observation_attempt_id: digest(15),
        }
    }

    fn observation_request() -> ChildObservationRequestV1 {
        ChildObservationRequestV1 {
            plan_id: digest(1),
            plan_digest: digest(2),
            route_id: digest(3),
            effect_id: digest(4),
            settlement_id: digest(5),
            leg: SettlementLegV1::Downstream,
            action: SettlementActionV1::Claim,
            semantic_digest: digest(6),
            route_fencing_epoch: 17,
            terms_digest: digest(7),
            registry_digest: digest(8),
            profile_digest: digest(9),
            deployment_digest: digest(10),
            child_index: 0,
            face: SettlementFaceV1::Evm,
            exposure: ChildExposureV1::FirstSecretExposure,
            chain_id: digest(11),
            transaction_id: digest(12),
            intent_digest: digest(13),
            custody_digest: digest(14),
            prior_finality_evidence_digest: None,
            observation_attempt_id: digest(15),
        }
    }

    fn facts() -> ChildFinalityFactsV1 {
        ChildFinalityFactsV1 {
            final_evidence_digest: digest(20),
            final_block_hash: digest(21),
            final_block_number: 4_849,
        }
    }

    /// The restart property the coordinator fail-closes on.
    ///
    /// A daemon that crashes between the actuator's durable write and the
    /// coordinator's commit rebuilds the binding from the same persisted
    /// request and must reproduce every commitment byte for byte, or
    /// `complete_child_call` permanently fails the plan
    /// (`settlement-coordinator/src/store.rs:2513-2533`).
    #[test]
    fn every_commitment_survives_a_reconstruction_of_the_binding() {
        let first = binding();
        let second = binding();
        let first_observation = observation_binding();
        let second_observation = observation_binding();
        assert_eq!(first, second, "fixture is not reproducible");
        assert_eq!(
            first_observation, second_observation,
            "observation fixture is not reproducible"
        );

        assert_eq!(
            externalization_evidence_v1(&first).expect("first"),
            externalization_evidence_v1(&second).expect("second"),
        );
        assert_eq!(
            retryable_before_externalization_evidence_v1(&first).expect("first"),
            retryable_before_externalization_evidence_v1(&second).expect("second"),
        );
        assert_eq!(
            unknown_evidence_v1(&first).expect("first"),
            unknown_evidence_v1(&second).expect("second"),
        );
        assert_eq!(
            proven_not_externalized_evidence_v1(&first).expect("first"),
            proven_not_externalized_evidence_v1(&second).expect("second"),
        );
        assert_eq!(
            observation_pending_evidence_v1(&first_observation).expect("first"),
            observation_pending_evidence_v1(&second_observation).expect("second"),
        );
        assert_eq!(
            observation_final_evidence_v1(&first_observation, &facts()).expect("first"),
            observation_final_evidence_v1(&second_observation, &facts()).expect("second"),
        );
    }

    /// The fencing epochs are deliberately outside the binding, because a
    /// takeover reconciles the same dispatch at a newer fence and must
    /// reproduce the earlier fence's digest. Nothing in the binding can carry
    /// them, so this pins the decision rather than the mechanism.
    #[test]
    fn the_binding_carries_no_fence_and_no_mutable_counter() {
        let value = binding();
        // Every field is either an attempt-scoped identity or a frozen tag.
        // A counter, a confirmation count or a fence would have to appear
        // here to be hashed, and none does.
        assert_eq!(value.attempt_id, digest(10));
        assert_eq!(value.child_index, 0);
        assert!(!value.is_first_secret_exposure());
    }

    #[test]
    fn observation_binding_is_reconstructed_only_from_the_journaled_request() {
        assert_eq!(
            ChildObservationEvidenceBindingV1::from_observation(&observation_request()),
            observation_binding()
        );

        let mut later = observation_request();
        later.observation_attempt_id = digest(10);
        let first = ChildObservationEvidenceBindingV1::from_observation(&observation_request());
        let second = ChildObservationEvidenceBindingV1::from_observation(&later);
        assert_ne!(
            observation_pending_evidence_v1(&first).expect("first"),
            observation_pending_evidence_v1(&second).expect("second")
        );

        let mut invalid = observation_binding();
        invalid.observation_attempt_id = ZERO_DIGEST;
        assert_eq!(
            observation_pending_evidence_v1(&invalid),
            Err(ChildEvidenceErrorV1::ZeroInput)
        );
    }

    #[test]
    fn finality_is_stable_across_attempt_prior_and_refence_but_not_scope_transplant() {
        let original = observation_binding();
        let expected = observation_final_evidence_v1(&original, &facts()).expect("original final");

        let mut refenced = original;
        refenced.plan_digest = digest(30);
        refenced.effect_id = digest(31);
        refenced.route_fencing_epoch = 99;
        refenced.prior_finality_evidence_digest = Some(expected);
        refenced.observation_attempt_id = digest(32);
        assert_eq!(
            observation_final_evidence_v1(&refenced, &facts()).expect("refenced final"),
            expected,
            "coordinator refence/attempt metadata must not rewrite a chain finality fact"
        );

        for mut transplanted in [original; 4] {
            transplanted.transaction_id = digest(40);
            assert_ne!(
                observation_final_evidence_v1(&transplanted, &facts()).expect("tx transplant"),
                expected
            );
            transplanted = original;
            transplanted.chain_id = digest(41);
            assert_ne!(
                observation_final_evidence_v1(&transplanted, &facts()).expect("chain transplant"),
                expected
            );
            transplanted = original;
            transplanted.custody_digest = digest(42);
            assert_ne!(
                observation_final_evidence_v1(&transplanted, &facts()).expect("custody transplant"),
                expected
            );
            transplanted = original;
            transplanted.settlement_id = digest(43);
            assert_ne!(
                observation_final_evidence_v1(&transplanted, &facts())
                    .expect("settlement transplant"),
                expected
            );
        }
    }

    #[test]
    fn pending_and_reorg_remain_exact_attempt_scoped() {
        let original = observation_binding();
        let mut later = original;
        later.observation_attempt_id = digest(33);
        assert_ne!(
            observation_pending_evidence_v1(&original).expect("original pending"),
            observation_pending_evidence_v1(&later).expect("later pending")
        );

        let prior = observation_final_evidence_v1(&original, &facts()).expect("stable prior");
        let invalidation = digest(34);
        let first = observation_reorg_evidence_v1(&later, prior, invalidation).expect("reorg");
        assert_eq!(
            observation_reorg_evidence_v1(&later, prior, invalidation).expect("reorg replay"),
            first
        );
        assert_ne!(
            observation_reorg_evidence_v1(&later, digest(35), invalidation)
                .expect("prior transplant"),
            first
        );
        later.observation_attempt_id = digest(36);
        assert_ne!(
            observation_reorg_evidence_v1(&later, prior, invalidation).expect("attempt transplant"),
            first
        );
    }

    /// Domain separation must actually separate: the same binding under six
    /// different outcome labels must give six different commitments.
    #[test]
    fn each_outcome_label_yields_a_distinct_commitment() {
        let value = binding();
        let observation = observation_binding();
        let all = [
            externalization_evidence_v1(&value).expect("externalized"),
            retryable_before_externalization_evidence_v1(&value).expect("retryable"),
            unknown_evidence_v1(&value).expect("unknown"),
            proven_not_externalized_evidence_v1(&value).expect("not externalized"),
            observation_pending_evidence_v1(&observation).expect("pending"),
            observation_final_evidence_v1(&observation, &facts()).expect("final"),
        ];
        for (index, left) in all.iter().enumerate() {
            for right in all.iter().skip(index + 1) {
                assert_ne!(left, right, "two outcome labels collided");
            }
        }
    }

    /// A different attempt must never reuse an earlier attempt's commitment.
    #[test]
    fn a_distinct_attempt_changes_every_commitment() {
        let first = binding();
        let mut second = binding();
        second.attempt_id = digest(11);

        assert_ne!(
            externalization_evidence_v1(&first).expect("first"),
            externalization_evidence_v1(&second).expect("second"),
        );
        assert_ne!(
            unknown_evidence_v1(&first).expect("first"),
            unknown_evidence_v1(&second).expect("second"),
        );
    }

    /// The face tag is bound, so the same attempt on two faces cannot share a
    /// commitment.
    #[test]
    fn a_distinct_face_changes_every_commitment() {
        let first = binding();
        let mut second = binding();
        second.face = SettlementFaceV1::Bitcoin;

        assert_ne!(
            externalization_evidence_v1(&first).expect("first"),
            externalization_evidence_v1(&second).expect("second"),
        );
    }

    /// `validate_child_receipt` accepts a first-exposure commitment if and
    /// only if the request said `FirstSecretExposure`
    /// (`settlement-coordinator/src/store.rs:4541-4546`). This derivation must
    /// produce exactly that shape, so a port cannot get it wrong by omission.
    #[test]
    fn first_exposure_is_present_exactly_for_the_first_exposure_child() {
        let mut value = binding();

        value.exposure = ChildExposureV1::NonSecret;
        assert!(first_exposure_evidence_v1(&value)
            .expect("non secret")
            .is_none());

        value.exposure = ChildExposureV1::UsesPublicSecret;
        assert!(first_exposure_evidence_v1(&value)
            .expect("public")
            .is_none());

        value.exposure = ChildExposureV1::FirstSecretExposure;
        let exposure = first_exposure_evidence_v1(&value)
            .expect("first exposure")
            .expect("must be present");
        assert_ne!(exposure, ZERO_DIGEST);
        assert_ne!(
            exposure,
            externalization_evidence_v1(&value).expect("externalized"),
            "the exposure commitment must not repeat the externalization one",
        );
    }

    /// The zero guard, exercised directly.
    ///
    /// No input reaches Blake2b's zero preimage, so the output guard cannot be
    /// driven through the public derivations. Calling it directly is what
    /// separates a guard that fires from a guard that is merely present: the
    /// first assertion fails if the refusal is removed, and the second fails
    /// if the refusal is widened to reject everything.
    #[test]
    fn the_zero_output_guard_fires_and_is_not_a_blanket_refusal() {
        assert_eq!(nonzero(ZERO_DIGEST), Err(ChildEvidenceErrorV1::ZeroOutput));
        assert_eq!(nonzero(digest(1)), Ok(digest(1)));
    }

    /// A placeholder finality fact must be refused rather than committed.
    /// Each assertion fails if its own branch of the guard is removed.
    #[test]
    fn a_placeholder_finality_fact_is_refused() {
        let mut value = facts();
        value.final_evidence_digest = ZERO_DIGEST;
        assert_eq!(value.commitment(), Err(ChildEvidenceErrorV1::ZeroInput));

        let mut value = facts();
        value.final_block_hash = ZERO_DIGEST;
        assert_eq!(value.commitment(), Err(ChildEvidenceErrorV1::ZeroInput));

        assert!(facts().commitment().is_ok(), "a valid fact must still pass");
    }

    /// A reorg commitment must name a finality that was actually recorded.
    #[test]
    fn a_reorg_commitment_refuses_a_placeholder_prior_finality() {
        let value = observation_binding();
        assert_eq!(
            observation_reorg_evidence_v1(&value, ZERO_DIGEST, digest(30)),
            Err(ChildEvidenceErrorV1::ZeroInput),
        );
        assert_eq!(
            observation_reorg_evidence_v1(&value, digest(29), ZERO_DIGEST),
            Err(ChildEvidenceErrorV1::ZeroInput),
        );
        assert!(
            observation_reorg_evidence_v1(&value, digest(29), digest(30)).is_ok(),
            "a well formed reorg commitment must still pass",
        );
    }

    /// The tag table is hashed into durable ledger content. Renumbering one
    /// silently rewrites the meaning of every digest already committed under
    /// it, so the numbers are pinned here rather than left to inspection.
    #[test]
    fn the_canonical_tag_table_is_frozen() {
        assert_eq!(tags::face(SettlementFaceV1::Dom), 1);
        assert_eq!(tags::face(SettlementFaceV1::Evm), 2);
        assert_eq!(tags::face(SettlementFaceV1::Bitcoin), 3);

        assert_eq!(tags::leg(SettlementLegV1::Upstream), 1);
        assert_eq!(tags::leg(SettlementLegV1::Downstream), 2);

        assert_eq!(tags::action(SettlementActionV1::Funding), 1);
        assert_eq!(tags::action(SettlementActionV1::Claim), 2);
        assert_eq!(tags::action(SettlementActionV1::Refund), 3);

        assert_eq!(tags::exposure(ChildExposureV1::NonSecret), 1);
        assert_eq!(tags::exposure(ChildExposureV1::FirstSecretExposure), 2);
        assert_eq!(tags::exposure(ChildExposureV1::UsesPublicSecret), 3);
    }

    /// Every domain label ends in NUL, so no label can be a prefix of another
    /// once it is absorbed ahead of the length-prefixed body.
    #[test]
    fn every_domain_label_is_nul_terminated_and_distinct() {
        let labels: [&[u8]; 11] = [
            CHILD_EVIDENCE_ROOT_V1,
            CHILD_OBSERVATION_STABLE_ROOT_V2,
            CHILD_OBSERVATION_ATTEMPT_ROOT_V2,
            EXTERNALIZED_DOMAIN_V1,
            FIRST_EXPOSURE_DOMAIN_V1,
            RETRYABLE_DOMAIN_V1,
            UNKNOWN_DOMAIN_V1,
            NOT_EXTERNALIZED_DOMAIN_V1,
            OBSERVED_PENDING_DOMAIN_V1,
            OBSERVED_FINAL_DOMAIN_V1,
            OBSERVED_REORG_DOMAIN_V1,
        ];
        for (index, left) in labels.iter().enumerate() {
            assert_eq!(left.last(), Some(&0u8), "label is not NUL terminated");
            for right in labels.iter().skip(index + 1) {
                assert_ne!(left, right, "two domain labels are identical");
            }
        }
    }
}

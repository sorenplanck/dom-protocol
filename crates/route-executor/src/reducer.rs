//! Pure route transition function.  It performs no I/O and emits only
//! declarative effects/timer mutations for the durable store to commit.

use thiserror::Error;

use crate::codec::{domain_digest_v1, CanonicalCodecV1, CodecErrorV1};
use crate::model::{
    validate_digest, validate_event, ActionKindV1, ActionProgressV1, ActionStateV1,
    CoordinationPhaseV1, EffectDispatchV1, EffectPriorityV1, EffectReferenceV1, EventIdV1,
    ExposureSourceV1, HealthStateV1, LegIdV1, RouteDecisionV1, RouteEffectV1, RouteEventV1,
    RouteSnapshotV1, RouteTimerMutationV1, RouteTimerV1, SecretVisibilityV1,
};

/// Pure transition rejection.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ReduceErrorV1 {
    /// Snapshot or event failed canonical/value validation.
    #[error("invalid route material")]
    InvalidMaterial,
    /// Event is not legal in the current multidimensional state.
    #[error("invalid route transition")]
    InvalidTransition,
    /// Funding was attempted without both durable refunds.
    #[error("both refunds must be armed before funding")]
    RefundsNotArmed,
    /// Downstream funding was attempted before upstream finality.
    #[error("upstream funding is not final")]
    UpstreamNotFinal,
    /// A claim was attempted before its required public/finality condition.
    #[error("claim precondition is not satisfied")]
    ClaimPrecondition,
    /// New work is prohibited while the route is in a recovery lane.
    #[error("route permits recovery work only")]
    RecoveryOnly,
    /// Recovery state cannot be cleared while funds remain open.
    #[error("cannot leave recovery while funds remain open")]
    RecoveryLocked,
    /// A secret-bearing action tried to enter the generic byte outbox.
    #[error("secret-bearing action requires external custody")]
    SecretCustodyRequired,
    /// First secret-bearing externalization omitted matching public evidence.
    #[error("first secret exposure evidence is required")]
    ExposureRequired,
    /// A checked integer would overflow.
    #[error("route counter overflow")]
    CounterOverflow,
}

impl From<CodecErrorV1> for ReduceErrorV1 {
    fn from(_: CodecErrorV1) -> Self {
        Self::InvalidMaterial
    }
}

/// Apply one canonical event to a snapshot.
///
/// The function is deterministic over `(snapshot, event_id, event,
/// fencing_epoch)`.  The caller must persist the returned snapshot, journal,
/// effects and timers atomically before dispatching anything.
pub fn reduce_route_v1(
    current: &RouteSnapshotV1,
    event_id: EventIdV1,
    event: &RouteEventV1,
    fencing_epoch: u64,
) -> Result<RouteDecisionV1, ReduceErrorV1> {
    current.validate()?;
    validate_digest(&event_id)?;
    validate_event(event)?;
    if fencing_epoch == 0 {
        return Err(ReduceErrorV1::InvalidMaterial);
    }

    let event_bytes = event.encode_canonical()?;
    let event_digest = domain_digest_v1(b"DOM-ROUTE-EVENT-DIGEST-V1", &[&event_bytes]);
    let mut next = current.clone();
    let mut effects = Vec::new();
    let mut superseded_effects = Vec::new();
    let mut timers = Vec::new();

    match event {
        RouteEventV1::FreezeTerms(bindings) => {
            freeze_terms(current, &mut next, bindings)?;
        }
        RouteEventV1::FreezeTermsV2(checkpoint) => {
            if checkpoint.route_id != current.route_id {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            freeze_terms(current, &mut next, &checkpoint.bindings)?;
        }
        RouteEventV1::ArmRefunds(refunds) => {
            require_new_work_allowed(current)?;
            if current.bindings.is_none()
                || current.refunds.is_some()
                || current.coordination != CoordinationPhaseV1::TermsFrozen
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            next.refunds = Some(refunds.clone());
        }
        RouteEventV1::CommitAction(intent) => {
            if current.aborted_unfunded {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            validate_action_preconditions(current, intent.leg, intent.kind)?;
            if intent.kind == ActionKindV1::Funding {
                require_new_work_allowed(current)?;
            }
            if intent.kind == ActionKindV1::Claim && !intent.contains_route_secret {
                return Err(ReduceErrorV1::SecretCustodyRequired);
            }
            if intent.contains_route_secret
                && !matches!(intent.dispatch, EffectDispatchV1::ExternalCustody { .. })
            {
                return Err(ReduceErrorV1::SecretCustodyRequired);
            }

            let effect_id = derive_effect_id_v1(
                current.route_id,
                event_id,
                fencing_epoch,
                intent.leg,
                intent.kind,
                intent.semantic_digest,
            );
            let expected_transaction_id = match intent.dispatch {
                EffectDispatchV1::ExternalCustody { transaction_id, .. } => Some(transaction_id),
                EffectDispatchV1::RunnerPayload { .. } => None,
            };
            let reference = EffectReferenceV1 {
                effect_id,
                fencing_epoch,
                semantic_digest: intent.semantic_digest,
                contains_route_secret: intent.contains_route_secret,
                expected_transaction_id,
            };
            *next.leg_mut(intent.leg).action_mut(intent.kind) = ActionStateV1::Committed(reference);

            let priority = if intent.leg == LegIdV1::Upstream
                && intent.kind == ActionKindV1::Claim
                && matches!(current.secret_visibility, SecretVisibilityV1::Public { .. })
            {
                EffectPriorityV1::SecretPublicUrgent
            } else if intent.kind == ActionKindV1::Refund || current.health.restricts_to_recovery()
            {
                EffectPriorityV1::Recovery
            } else {
                EffectPriorityV1::Normal
            };
            effects.push(RouteEffectV1 {
                route_id: current.route_id,
                effect_id,
                fencing_epoch,
                leg: intent.leg,
                kind: intent.kind,
                priority,
                semantic_digest: intent.semantic_digest,
                contains_route_secret: intent.contains_route_secret,
                dispatch: intent.dispatch.clone(),
            });
        }
        RouteEventV1::ReauthorizeCommittedAction {
            prior_effect_id,
            intent,
            ..
        } => {
            if current.aborted_unfunded {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            let prior = match current.leg(intent.leg).action(intent.kind) {
                ActionStateV1::Committed(reference) => reference.clone(),
                _ => return Err(ReduceErrorV1::InvalidTransition),
            };
            let expected_transaction_id = match intent.dispatch {
                EffectDispatchV1::ExternalCustody { transaction_id, .. } => Some(transaction_id),
                EffectDispatchV1::RunnerPayload { .. } => None,
            };
            if prior.effect_id != *prior_effect_id
                || prior.fencing_epoch >= fencing_epoch
                || prior.semantic_digest != intent.semantic_digest
                || prior.contains_route_secret != intent.contains_route_secret
                || prior.expected_transaction_id != expected_transaction_id
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            if intent.contains_route_secret
                && !matches!(intent.dispatch, EffectDispatchV1::ExternalCustody { .. })
            {
                return Err(ReduceErrorV1::SecretCustodyRequired);
            }
            let effect_id = derive_effect_id_v1(
                current.route_id,
                event_id,
                fencing_epoch,
                intent.leg,
                intent.kind,
                intent.semantic_digest,
            );
            let replacement = EffectReferenceV1 {
                effect_id,
                fencing_epoch,
                semantic_digest: intent.semantic_digest,
                contains_route_secret: intent.contains_route_secret,
                expected_transaction_id,
            };
            *next.leg_mut(intent.leg).action_mut(intent.kind) =
                ActionStateV1::Committed(replacement);
            effects.push(RouteEffectV1 {
                route_id: current.route_id,
                effect_id,
                fencing_epoch,
                leg: intent.leg,
                kind: intent.kind,
                priority: effect_priority(current, intent.leg, intent.kind),
                semantic_digest: intent.semantic_digest,
                contains_route_secret: intent.contains_route_secret,
                dispatch: intent.dispatch.clone(),
            });
            superseded_effects.push(*prior_effect_id);
        }
        RouteEventV1::ReauthorizePartiallyExternalizedCustody {
            prior_effect_id,
            intent,
            ..
        } => {
            if current.aborted_unfunded
                || !matches!(intent.dispatch, EffectDispatchV1::ExternalCustody { .. })
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            let prior = match current.leg(intent.leg).action(intent.kind) {
                ActionStateV1::Committed(reference) => reference.clone(),
                _ => return Err(ReduceErrorV1::InvalidTransition),
            };
            let expected_transaction_id = match intent.dispatch {
                EffectDispatchV1::ExternalCustody { transaction_id, .. } => Some(transaction_id),
                EffectDispatchV1::RunnerPayload { .. } => {
                    return Err(ReduceErrorV1::InvalidTransition)
                }
            };
            if prior.effect_id != *prior_effect_id
                || prior.fencing_epoch >= fencing_epoch
                || prior.semantic_digest != intent.semantic_digest
                || prior.contains_route_secret != intent.contains_route_secret
                || prior.expected_transaction_id != expected_transaction_id
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            let effect_id = derive_effect_id_v1(
                current.route_id,
                event_id,
                fencing_epoch,
                intent.leg,
                intent.kind,
                intent.semantic_digest,
            );
            let replacement = EffectReferenceV1 {
                effect_id,
                fencing_epoch,
                semantic_digest: intent.semantic_digest,
                contains_route_secret: intent.contains_route_secret,
                expected_transaction_id,
            };
            *next.leg_mut(intent.leg).action_mut(intent.kind) =
                ActionStateV1::Committed(replacement);
            effects.push(RouteEffectV1 {
                route_id: current.route_id,
                effect_id,
                fencing_epoch,
                leg: intent.leg,
                kind: intent.kind,
                priority: effect_priority(current, intent.leg, intent.kind),
                semantic_digest: intent.semantic_digest,
                contains_route_secret: intent.contains_route_secret,
                dispatch: intent.dispatch.clone(),
            });
            superseded_effects.push(*prior_effect_id);
        }
        RouteEventV1::CustodyProgressRecorded {
            leg,
            kind,
            effect_id,
            exposure,
            ..
        } => {
            let committed = match current.leg(*leg).action(*kind) {
                ActionStateV1::Committed(reference) => reference,
                _ => return Err(ReduceErrorV1::InvalidTransition),
            };
            if committed.effect_id != *effect_id {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            if let Some(exposure) = exposure {
                if !committed.contains_route_secret
                    || exposure.source != ExposureSourceV1::Externalized
                {
                    return Err(ReduceErrorV1::InvalidTransition);
                }
                expose_secret_once(&mut next, exposure.clone());
            }
        }
        RouteEventV1::ActionExternalized {
            leg,
            kind,
            effect_id,
            transaction_id,
            exposure,
        } => {
            let committed = match current.leg(*leg).action(*kind) {
                ActionStateV1::Committed(reference) => reference.clone(),
                _ => return Err(ReduceErrorV1::InvalidTransition),
            };
            if committed.effect_id != *effect_id
                || committed
                    .expected_transaction_id
                    .is_some_and(|expected| expected != *transaction_id)
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            if committed.contains_route_secret {
                if matches!(current.secret_visibility, SecretVisibilityV1::Private)
                    && exposure.is_none()
                {
                    return Err(ReduceErrorV1::ExposureRequired);
                }
                if let Some(exposure) = exposure {
                    if exposure.transaction_id != *transaction_id {
                        return Err(ReduceErrorV1::InvalidMaterial);
                    }
                    expose_secret_once(&mut next, exposure.clone());
                }
            } else if exposure.is_some() {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            *next.leg_mut(*leg).action_mut(*kind) = ActionStateV1::Externalized {
                effect: committed,
                transaction_id: *transaction_id,
            };
        }
        RouteEventV1::ActionFinalized {
            leg,
            kind,
            transaction_id,
            evidence_digest,
        } => {
            let reference = match current.leg(*leg).action(*kind) {
                ActionStateV1::Externalized {
                    effect,
                    transaction_id: existing,
                } if existing == transaction_id => effect.clone(),
                ActionStateV1::FinalityInvalidated {
                    effect,
                    transaction_id: existing,
                    ..
                } if existing == transaction_id => effect.clone(),
                _ => return Err(ReduceErrorV1::InvalidTransition),
            };
            *next.leg_mut(*leg).action_mut(*kind) = ActionStateV1::Final {
                effect: reference,
                transaction_id: *transaction_id,
                evidence_digest: *evidence_digest,
            };
        }
        RouteEventV1::ObservationInvalidated {
            leg,
            kind,
            transaction_id,
            reorg_evidence_digest,
        } => {
            let (reference, prior_evidence_digest) = match current.leg(*leg).action(*kind) {
                ActionStateV1::Final {
                    effect,
                    transaction_id: existing,
                    evidence_digest,
                } if existing == transaction_id => (effect.clone(), *evidence_digest),
                _ => return Err(ReduceErrorV1::InvalidTransition),
            };
            *next.leg_mut(*leg).action_mut(*kind) = ActionStateV1::FinalityInvalidated {
                effect: reference,
                transaction_id: *transaction_id,
                prior_evidence_digest,
                reorg_evidence_digest: *reorg_evidence_digest,
            };
            next.health = HealthStateV1::RecoveryOnly;
        }
        RouteEventV1::SecretObserved(exposure) => {
            expose_secret_once(&mut next, exposure.clone());
        }
        RouteEventV1::SetHealth { target, .. } => {
            if *target == HealthStateV1::Running
                && current.health.restricts_to_recovery()
                && current.has_open_funds()
            {
                return Err(ReduceErrorV1::RecoveryLocked);
            }
            next.health = *target;
        }
        RouteEventV1::ScheduleTimer {
            kind,
            deadline_unix_ms,
            context_digest,
        } => {
            if current.aborted_unfunded
                || (current.coordination == CoordinationPhaseV1::Terminal
                    && !current.has_open_funds())
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            timers.push(RouteTimerMutationV1::Schedule(RouteTimerV1 {
                route_id: current.route_id,
                timer_id: derive_timer_id(current.route_id, event_id, fencing_epoch),
                fencing_epoch,
                kind: *kind,
                deadline_unix_ms: *deadline_unix_ms,
                context_digest: *context_digest,
            }));
        }
        RouteEventV1::CancelTimer { timer_id } => {
            timers.push(RouteTimerMutationV1::Cancel {
                timer_id: *timer_id,
            });
        }
        RouteEventV1::AbortUnfunded { .. } => {
            require_new_work_allowed(current)?;
            if current.has_open_funds()
                || current.upstream.funding.progress() != ActionProgressV1::NotPrepared
                || current.downstream.funding.progress() != ActionProgressV1::NotPrepared
                || !matches!(current.secret_visibility, SecretVisibilityV1::Private)
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            next.aborted_unfunded = true;
        }
    }

    next.revision = current
        .revision
        .checked_add(1)
        .ok_or(ReduceErrorV1::CounterOverflow)?;
    next.last_event_sequence = current
        .last_event_sequence
        .checked_add(1)
        .ok_or(ReduceErrorV1::CounterOverflow)?;
    next.last_event_digest = event_digest;
    next.recompute_coordination();

    if matches!(current.secret_visibility, SecretVisibilityV1::Public { .. })
        && !matches!(next.secret_visibility, SecretVisibilityV1::Public { .. })
    {
        return Err(ReduceErrorV1::InvalidTransition);
    }
    if current.health.restricts_to_recovery()
        && current.has_open_funds()
        && !next.health.restricts_to_recovery()
    {
        return Err(ReduceErrorV1::RecoveryLocked);
    }
    next.validate()?;

    Ok(RouteDecisionV1 {
        snapshot: next,
        effects,
        superseded_effects,
        timers,
    })
}

fn freeze_terms(
    current: &RouteSnapshotV1,
    next: &mut RouteSnapshotV1,
    bindings: &crate::model::FrozenBindingsV1,
) -> Result<(), ReduceErrorV1> {
    require_new_work_allowed(current)?;
    if current.bindings.is_some()
        || current.refunds.is_some()
        || current.coordination != CoordinationPhaseV1::Negotiating
    {
        return Err(ReduceErrorV1::InvalidTransition);
    }
    next.bindings = Some(bindings.clone());
    Ok(())
}

fn require_new_work_allowed(snapshot: &RouteSnapshotV1) -> Result<(), ReduceErrorV1> {
    if snapshot.health.restricts_to_recovery() {
        Err(ReduceErrorV1::RecoveryOnly)
    } else if snapshot.aborted_unfunded {
        Err(ReduceErrorV1::InvalidTransition)
    } else {
        Ok(())
    }
}

fn validate_action_preconditions(
    snapshot: &RouteSnapshotV1,
    leg: LegIdV1,
    kind: ActionKindV1,
) -> Result<(), ReduceErrorV1> {
    if snapshot.refunds.is_none() {
        return Err(ReduceErrorV1::RefundsNotArmed);
    }
    if snapshot.leg(leg).action(kind).progress() != ActionProgressV1::NotPrepared {
        return Err(ReduceErrorV1::InvalidTransition);
    }

    match kind {
        ActionKindV1::Funding => {
            if snapshot.upstream.is_terminal() || snapshot.downstream.is_terminal() {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            if snapshot.leg(leg).claim.progress() != ActionProgressV1::NotPrepared
                || snapshot.leg(leg).refund.progress() != ActionProgressV1::NotPrepared
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
            if leg == LegIdV1::Downstream
                && (snapshot.upstream.funding.progress() != ActionProgressV1::Final
                    || snapshot.upstream.claim.progress() != ActionProgressV1::NotPrepared
                    || snapshot.upstream.refund.progress() != ActionProgressV1::NotPrepared)
            {
                return Err(ReduceErrorV1::UpstreamNotFinal);
            }
        }
        ActionKindV1::Claim => {
            if snapshot.leg(leg).refund.progress() != ActionProgressV1::NotPrepared {
                return Err(ReduceErrorV1::ClaimPrecondition);
            }
            if leg == LegIdV1::Downstream {
                if snapshot.health.restricts_to_recovery()
                    || snapshot.downstream.funding.progress() != ActionProgressV1::Final
                    || snapshot.upstream.funding.progress() != ActionProgressV1::Final
                    || snapshot.upstream.claim.progress() != ActionProgressV1::NotPrepared
                    || snapshot.upstream.refund.progress() != ActionProgressV1::NotPrepared
                {
                    return Err(ReduceErrorV1::ClaimPrecondition);
                }
            } else if !matches!(
                snapshot.upstream.funding,
                ActionStateV1::Final { .. } | ActionStateV1::FinalityInvalidated { .. }
            ) || !matches!(
                snapshot.secret_visibility,
                SecretVisibilityV1::Public { .. }
            ) {
                return Err(ReduceErrorV1::ClaimPrecondition);
            }
        }
        ActionKindV1::Refund => {
            if !matches!(
                snapshot.leg(leg).funding.progress(),
                ActionProgressV1::Externalized | ActionProgressV1::Final
            ) || snapshot.leg(leg).claim.progress() != ActionProgressV1::NotPrepared
            {
                return Err(ReduceErrorV1::InvalidTransition);
            }
        }
    }
    Ok(())
}

fn effect_priority(
    snapshot: &RouteSnapshotV1,
    leg: LegIdV1,
    kind: ActionKindV1,
) -> EffectPriorityV1 {
    if leg == LegIdV1::Upstream
        && kind == ActionKindV1::Claim
        && matches!(
            snapshot.secret_visibility,
            SecretVisibilityV1::Public { .. }
        )
    {
        EffectPriorityV1::SecretPublicUrgent
    } else if kind == ActionKindV1::Refund || snapshot.health.restricts_to_recovery() {
        EffectPriorityV1::Recovery
    } else {
        EffectPriorityV1::Normal
    }
}

fn expose_secret_once(snapshot: &mut RouteSnapshotV1, exposure: crate::model::PublicExposureV1) {
    if matches!(snapshot.secret_visibility, SecretVisibilityV1::Private) {
        snapshot.secret_visibility = SecretVisibilityV1::Public {
            first_exposure: exposure,
        };
    }
}

/// Derives the exact outbox identity that [`reduce_route_v1`] will assign to
/// an action authorization.
///
/// Production action authorities use this before returning an
/// [`crate::ActionIntentV1`] so a chain actuator can bind its durable
/// preparation to the same effect identity.  Keeping this function in the
/// reducer crate prevents composition roots from copying or drifting from the
/// consensus-relevant derivation.
pub fn derive_effect_id_v1(
    route_id: [u8; 32],
    event_id: [u8; 32],
    fencing_epoch: u64,
    leg: LegIdV1,
    kind: ActionKindV1,
    semantic_digest: [u8; 32],
) -> [u8; 32] {
    let leg_tag = [match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    }];
    let kind_tag = [match kind {
        ActionKindV1::Funding => 0,
        ActionKindV1::Claim => 1,
        ActionKindV1::Refund => 2,
    }];
    domain_digest_v1(
        b"DOM-ROUTE-EFFECT-ID-V1",
        &[
            &route_id,
            &event_id,
            &fencing_epoch.to_be_bytes(),
            &leg_tag,
            &kind_tag,
            &semantic_digest,
        ],
    )
}

fn derive_timer_id(route_id: [u8; 32], event_id: [u8; 32], fencing_epoch: u64) -> [u8; 32] {
    domain_digest_v1(
        b"DOM-ROUTE-TIMER-ID-V1",
        &[&route_id, &event_id, &fencing_epoch.to_be_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::digest_bytes_v1;
    use crate::model::{
        ActionIntentV1, EffectDispatchV1, ExposureSourceV1, FrozenBindingsV1,
        FrozenRouteAdmissionCheckpointV2, FrozenRouteTimeFactsV2, PublicExposureV1,
        RefundBindingsV1,
    };

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn apply(snapshot: RouteSnapshotV1, index: u8, event: RouteEventV1) -> RouteSnapshotV1 {
        reduce_route_v1(&snapshot, id(index), &event, 1)
            .expect("valid transition")
            .snapshot
    }

    fn armed() -> RouteSnapshotV1 {
        let snapshot = RouteSnapshotV1::new(id(1)).expect("route");
        let snapshot = apply(
            snapshot,
            2,
            RouteEventV1::FreezeTerms(FrozenBindingsV1 {
                terms_digest: id(3),
                profile_bundle_digest: id(4),
                deployment_bundle_digest: id(5),
            }),
        );
        apply(
            snapshot,
            6,
            RouteEventV1::ArmRefunds(RefundBindingsV1 {
                upstream_refund_digest: id(7),
                downstream_refund_digest: id(8),
            }),
        )
    }

    fn frozen_admission_v2(route_id: [u8; 32]) -> FrozenRouteAdmissionCheckpointV2 {
        FrozenRouteAdmissionCheckpointV2 {
            network_id: id(90),
            route_id,
            bindings: FrozenBindingsV1 {
                terms_digest: id(91),
                profile_bundle_digest: id(92),
                deployment_bundle_digest: id(93),
            },
            composition_v2_digest: id(94),
            registry_epoch: 7,
            registry_manifest_digest: id(93),
            upstream_terms_digest: id(95),
            downstream_terms_digest: id(96),
            upstream_roster_snapshot: id(97),
            downstream_roster_snapshot: id(98),
            participant_bindings_digest: id(99),
            relay_binding_digest: id(100),
            registry_authority_set_digest: id(101),
            time_policy_authority_set_digest: id(102),
            time_evidence_authority_set_digest: id(103),
            time: FrozenRouteTimeFactsV2 {
                route_scope_digest: id(104),
                policy_digest: id(105),
                evidence_digest: id(106),
                proof_digest: id(107),
                evidence_sequence: 1,
                issued_at_seconds: 1_000,
                valid_until_seconds: 2_000,
                validated_at_seconds: 1_100,
            },
        }
    }

    #[test]
    fn production_v2_freeze_is_single_and_cannot_mix_with_legacy_v1() {
        let initial = RouteSnapshotV1::new(id(1)).expect("route");
        let checkpoint = frozen_admission_v2(initial.route_id);
        let frozen = reduce_route_v1(
            &initial,
            id(2),
            &RouteEventV1::FreezeTermsV2(Box::new(checkpoint.clone())),
            1,
        )
        .expect("V2 freeze");
        assert_eq!(frozen.snapshot.bindings, Some(checkpoint.bindings.clone()));
        assert_eq!(
            reduce_route_v1(
                &frozen.snapshot,
                id(3),
                &RouteEventV1::FreezeTerms(checkpoint.bindings.clone()),
                1,
            ),
            Err(ReduceErrorV1::InvalidTransition)
        );

        let legacy = reduce_route_v1(
            &initial,
            id(4),
            &RouteEventV1::FreezeTerms(checkpoint.bindings.clone()),
            1,
        )
        .expect("legacy remains replayable");
        assert_eq!(
            reduce_route_v1(
                &legacy.snapshot,
                id(5),
                &RouteEventV1::FreezeTermsV2(Box::new(checkpoint.clone())),
                1,
            ),
            Err(ReduceErrorV1::InvalidTransition)
        );

        let wrong_route = frozen_admission_v2(id(6));
        assert_eq!(
            reduce_route_v1(
                &initial,
                id(7),
                &RouteEventV1::FreezeTermsV2(Box::new(wrong_route)),
                1,
            ),
            Err(ReduceErrorV1::InvalidTransition)
        );
    }

    fn runner_intent(leg: LegIdV1, kind: ActionKindV1, value: u8) -> ActionIntentV1 {
        let payload = vec![value; 16];
        ActionIntentV1 {
            leg,
            kind,
            semantic_digest: id(value),
            contains_route_secret: false,
            dispatch: EffectDispatchV1::RunnerPayload {
                payload_digest: digest_bytes_v1(&payload),
                payload,
            },
        }
    }

    #[test]
    fn funding_requires_both_refunds_and_safe_order() {
        let initial = RouteSnapshotV1::new(id(1)).expect("route");
        let event =
            RouteEventV1::CommitAction(runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 9));
        assert_eq!(
            reduce_route_v1(&initial, id(2), &event, 1),
            Err(ReduceErrorV1::RefundsNotArmed)
        );

        let armed = armed();
        let downstream = RouteEventV1::CommitAction(runner_intent(
            LegIdV1::Downstream,
            ActionKindV1::Funding,
            10,
        ));
        assert_eq!(
            reduce_route_v1(&armed, id(11), &downstream, 1),
            Err(ReduceErrorV1::UpstreamNotFinal)
        );
    }

    #[test]
    fn public_effect_derivation_is_the_reducers_exact_identity() {
        let snapshot = armed();
        let event_id = id(12);
        let intent = runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 13);
        let expected = derive_effect_id_v1(
            snapshot.route_id,
            event_id,
            7,
            intent.leg,
            intent.kind,
            intent.semantic_digest,
        );
        let decision = reduce_route_v1(&snapshot, event_id, &RouteEventV1::CommitAction(intent), 7)
            .expect("valid action authorization");
        let retained = decision
            .snapshot
            .upstream
            .funding
            .effect()
            .expect("committed effect");
        assert_eq!(retained.effect_id, expected);
        assert_eq!(decision.effects.len(), 1);
        assert_eq!(decision.effects[0].effect_id, expected);
    }

    #[test]
    fn partially_externalized_takeover_is_distinct_and_custody_only() {
        let snapshot = armed();
        let intent = ActionIntentV1 {
            leg: LegIdV1::Upstream,
            kind: ActionKindV1::Funding,
            semantic_digest: id(14),
            contains_route_secret: false,
            dispatch: EffectDispatchV1::ExternalCustody {
                custody_digest: id(15),
                transaction_id: id(16),
            },
        };
        let committed = reduce_route_v1(
            &snapshot,
            id(17),
            &RouteEventV1::CommitAction(intent.clone()),
            1,
        )
        .expect("initial custody action");
        let prior_effect_id = committed
            .snapshot
            .upstream
            .funding
            .effect()
            .expect("committed effect")
            .effect_id;
        let resumed = reduce_route_v1(
            &committed.snapshot,
            id(18),
            &RouteEventV1::ReauthorizePartiallyExternalizedCustody {
                prior_effect_id,
                partial_externalization_evidence_digest: id(19),
                intent: intent.clone(),
            },
            2,
        )
        .expect("authenticated partial custody resumes");
        let replacement = resumed
            .snapshot
            .upstream
            .funding
            .effect()
            .expect("replacement effect");
        assert_eq!(replacement.fencing_epoch, 2);
        assert_ne!(replacement.effect_id, prior_effect_id);
        assert_eq!(resumed.superseded_effects, vec![prior_effect_id]);
        assert_eq!(resumed.effects.len(), 1);
        assert_eq!(resumed.effects[0].dispatch, intent.dispatch);

        let runner = runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 20);
        assert_eq!(
            reduce_route_v1(
                &committed.snapshot,
                id(21),
                &RouteEventV1::ReauthorizePartiallyExternalizedCustody {
                    prior_effect_id,
                    partial_externalization_evidence_digest: id(22),
                    intent: runner,
                },
                2,
            ),
            Err(ReduceErrorV1::InvalidMaterial)
        );
    }

    #[test]
    fn custody_prefix_progress_is_journaled_without_completing_the_action() {
        let snapshot = armed();
        let intent = ActionIntentV1 {
            leg: LegIdV1::Upstream,
            kind: ActionKindV1::Funding,
            semantic_digest: id(60),
            contains_route_secret: false,
            dispatch: EffectDispatchV1::ExternalCustody {
                custody_digest: id(61),
                transaction_id: id(62),
            },
        };
        let committed = reduce_route_v1(&snapshot, id(63), &RouteEventV1::CommitAction(intent), 1)
            .expect("custody funding committed");
        let reference = committed
            .snapshot
            .upstream
            .funding
            .effect()
            .expect("committed effect")
            .clone();
        let progress = reduce_route_v1(
            &committed.snapshot,
            id(64),
            &RouteEventV1::CustodyProgressRecorded {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Funding,
                effect_id: reference.effect_id,
                progress_evidence_digest: id(65),
                exposure: None,
            },
            1,
        )
        .expect("proper custody prefix is durable");
        assert_eq!(
            progress.snapshot.upstream.funding,
            ActionStateV1::Committed(reference)
        );
        assert!(progress.effects.is_empty());
        assert!(matches!(
            progress.snapshot.secret_visibility,
            SecretVisibilityV1::Private
        ));
    }

    #[test]
    fn secret_public_never_regresses_when_finality_is_invalidated() {
        let mut snapshot = armed();
        let exposure = PublicExposureV1 {
            source: ExposureSourceV1::Mempool,
            chain_id: id(20),
            transaction_id: id(21),
            evidence_digest: id(22),
            observed_at_unix_ms: 100,
        };
        snapshot = apply(snapshot, 23, RouteEventV1::SecretObserved(exposure.clone()));
        let later = PublicExposureV1 {
            source: ExposureSourceV1::Block,
            observed_at_unix_ms: 200,
            ..exposure.clone()
        };
        snapshot = apply(snapshot, 24, RouteEventV1::SecretObserved(later));
        assert_eq!(
            snapshot.secret_visibility,
            SecretVisibilityV1::Public {
                first_exposure: exposure
            }
        );
    }

    #[test]
    fn recovery_only_forbids_funding_but_keeps_refund_path() {
        let mut snapshot = armed();
        snapshot = apply(
            snapshot,
            30,
            RouteEventV1::CommitAction(runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 31)),
        );
        let funding_effect = snapshot
            .upstream
            .funding
            .effect()
            .expect("committed funding")
            .effect_id;
        snapshot = apply(
            snapshot,
            31,
            RouteEventV1::ActionExternalized {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Funding,
                effect_id: funding_effect,
                transaction_id: id(39),
                exposure: None,
            },
        );
        snapshot = apply(
            snapshot,
            32,
            RouteEventV1::SetHealth {
                target: HealthStateV1::RecoveryOnly,
                reason_digest: id(33),
            },
        );

        let refund =
            RouteEventV1::CommitAction(runner_intent(LegIdV1::Upstream, ActionKindV1::Refund, 34));
        let decision = reduce_route_v1(&snapshot, id(35), &refund, 1).expect("refund remains live");
        assert_eq!(decision.effects[0].priority, EffectPriorityV1::Recovery);

        let resume = RouteEventV1::SetHealth {
            target: HealthStateV1::Running,
            reason_digest: id(36),
        };
        assert_eq!(
            reduce_route_v1(&snapshot, id(37), &resume, 1),
            Err(ReduceErrorV1::RecoveryLocked)
        );
    }

    #[test]
    fn refund_is_not_terminal_until_finality_event() {
        let mut snapshot = armed();
        snapshot = apply(
            snapshot,
            40,
            RouteEventV1::CommitAction(runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 41)),
        );
        let funding_effect = snapshot
            .upstream
            .funding
            .effect()
            .expect("funding")
            .effect_id;
        snapshot = apply(
            snapshot,
            42,
            RouteEventV1::ActionExternalized {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Funding,
                effect_id: funding_effect,
                transaction_id: id(43),
                exposure: None,
            },
        );
        snapshot = apply(
            snapshot,
            44,
            RouteEventV1::CommitAction(runner_intent(LegIdV1::Upstream, ActionKindV1::Refund, 45)),
        );
        let refund_effect = snapshot.upstream.refund.effect().expect("refund").effect_id;
        snapshot = apply(
            snapshot,
            46,
            RouteEventV1::ActionExternalized {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Refund,
                effect_id: refund_effect,
                transaction_id: id(47),
                exposure: None,
            },
        );
        assert!(!snapshot.upstream.is_terminal());
        snapshot = apply(
            snapshot,
            48,
            RouteEventV1::ActionFinalized {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Refund,
                transaction_id: id(47),
                evidence_digest: id(49),
            },
        );
        assert!(snapshot.upstream.is_terminal());
        assert_ne!(snapshot.coordination, CoordinationPhaseV1::Terminal);
    }
}

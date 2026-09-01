//! Restart-safe activation boundary for one production F6 position.
//!
//! The Relay inbox is the sole durable owner of an RFQ before the position's
//! F6 stores can be opened.  This port therefore never acknowledges an RFQ
//! merely because it decoded: it reconstructs a move-only pending capability
//! from the authenticated delivery and returns a typed `Awaiting` refusal
//! until a purpose-limited activation authority can construct the real
//! [`ProductionSolverF6AuthorityV2`].  The exact same inbox row is then
//! redelivered to that authority, whose own receipt is the first result that
//! may mark the row delivered.

use kaystra_core::types::{Digest32, ParticipantId};
use relay::auth::message_type;
use rfq::v2::{RfqV2, SettlementPositionV2};
use route_transport::{
    DurablePayloadCommitV1, DurableRelayInboxV1, F6AppliedReplayErrorV1, F6AppliedReplayReportV1,
    F6PayloadDeliveryV1, F6TransportPortV1, RouteWireContextV1,
};

use crate::production_f6::{ProductionF6ErrorV2, ProductionSolverF6AuthorityV2};

const ZERO_DIGEST: Digest32 = [0; 32];

/// Exact authenticated authority whose absence keeps startup in the awaiting
/// phase.  Position-bearing variants prevent one leg's authority from
/// satisfying the other leg.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionPendingAuthorityV1 {
    /// No lifecycle factory has yet been installed for this F6 position.
    F6Activation { position: SettlementPositionV2 },
    /// The activation factory is installed, but no exact authenticated RFQ
    /// has yet been delivered from the durable Relay inbox.
    AuthenticatedRfq { position: SettlementPositionV2 },
    /// Current threshold-signed solver-status ingress is not available.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    SolverStatusEvidence,
    /// Current RFQ-scoped DOM-time evidence is not available.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    PreF6TimeEvidence { position: SettlementPositionV2 },
    /// The independent threshold bond-attestation signers are unavailable.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    BondAttestationSigners { position: SettlementPositionV2 },
    /// The adapter-owned refund/payout terms authority is unavailable.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    AdapterTerms { position: SettlementPositionV2 },
    /// The two explicit, authenticated final-claim role scopes are absent.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    ComposedFinalClaimRolePlan,
    /// The complementary EVM account-owning daemon has not authenticated its
    /// role handoff.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    RemoteEvmAccount,
}

/// Route facts fixed before the Relay worker accepts any F6 envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionAwaitingF6PinsV2 {
    wire: RouteWireContextV1,
    position: SettlementPositionV2,
    initiator: ParticipantId,
}

impl ProductionAwaitingF6PinsV2 {
    pub(crate) fn new(
        wire: RouteWireContextV1,
        position: SettlementPositionV2,
        initiator: ParticipantId,
    ) -> Result<Self, ProductionF6LifecycleErrorV2> {
        if [
            wire.network_id,
            wire.session_id,
            wire.route_id,
            wire.roster_snapshot,
            initiator.0,
        ]
        .contains(&ZERO_DIGEST)
            || wire.policy_version == 0
        {
            return Err(ProductionF6LifecycleErrorV2::InvalidBinding);
        }
        Ok(Self {
            wire,
            position,
            initiator,
        })
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn position(&self) -> SettlementPositionV2 {
        self.position
    }
}

/// Move-only proof reconstructed from one still-pending, roster-authenticated
/// Relay RFQ.  It has no codec and cannot outlive the activation call.
pub(crate) struct AuthenticatedPendingRfqV2 {
    wire: RouteWireContextV1,
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    sequence: u64,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    envelope_digest: Digest32,
    rfq: RfqV2,
}

impl AuthenticatedPendingRfqV2 {
    pub(crate) const fn wire(&self) -> RouteWireContextV1 {
        self.wire
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn envelope_digest(&self) -> Digest32 {
        self.envelope_digest
    }

    pub(crate) const fn rfq(&self) -> RfqV2 {
        self.rfq
    }
}

/// Typed outcome from an activation factory.  `Awaiting` must mean no fake F6
/// commit was produced; any durable prefix created by the factory is resumed
/// when the inbox redelivers the same RFQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionF6ActivationRefusalV2 {
    #[error("production authenticated input is still pending")]
    Awaiting(ProductionPendingAuthorityV1),
    #[error("production F6 activation binding was refused")]
    InvalidBinding,
    #[error("production F6 activation authority is temporarily unavailable")]
    Unavailable,
}

pub(crate) mod activation_seal {
    pub trait Sealed {}
}

/// Purpose-limited factory allowed to turn one authenticated pending RFQ into
/// the concrete F6 authority graph.  It has no generic store or payload API.
pub(crate) trait ProductionF6ActivationAuthorityV2: activation_seal::Sealed {
    fn activate(
        &mut self,
        pending: &AuthenticatedPendingRfqV2,
    ) -> Result<ProductionSolverF6AuthorityV2, ProductionF6ActivationRefusalV2>;
}

/// Redacted error returned to the Relay dispatcher.  An error means the inbox
/// row remains pending and therefore remains the restart source of truth.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionF6LifecycleErrorV2 {
    #[error("production F6 lifecycle binding is invalid")]
    InvalidBinding,
    #[error("production F6 delivery is not the exact pending RFQ")]
    InvalidPendingRfq,
    #[error("production authenticated input is still pending")]
    Awaiting(ProductionPendingAuthorityV1),
    #[error("production F6 activation authority is unavailable")]
    ActivationUnavailable,
    #[error("production F6 applied history must be replayed before pending delivery")]
    RecoveryRequired,
    #[error("active production F6 authority refused the delivery")]
    Active(#[source] ProductionF6ErrorV2),
}

/// One position's real production lifecycle port.
pub(crate) struct ProductionF6LifecyclePortV2 {
    pins: ProductionAwaitingF6PinsV2,
    activation: Option<Box<dyn ProductionF6ActivationAuthorityV2>>,
    active: Option<ProductionSolverF6AuthorityV2>,
    recovery_in_progress: bool,
    recovery_complete: bool,
}

impl core::fmt::Debug for ProductionF6LifecyclePortV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionF6LifecyclePortV2")
            .field("position", &self.pins.position)
            .field("activation_installed", &self.activation.is_some())
            .field("active", &self.active.is_some())
            .field("recovery_complete", &self.recovery_complete)
            .finish()
    }
}

impl ProductionF6LifecyclePortV2 {
    /// Starts in a genuine awaiting phase.  No substitute F6 authority is
    /// installed, and every valid RFQ remains pending in the Relay inbox.
    pub(crate) const fn awaiting(pins: ProductionAwaitingF6PinsV2) -> Self {
        Self {
            pins,
            activation: None,
            active: None,
            recovery_in_progress: false,
            recovery_complete: false,
        }
    }

    /// Installs the one authenticated factory for this process opening.
    pub(crate) fn install_activation_authority<A>(
        &mut self,
        authority: A,
    ) -> Result<(), ProductionF6LifecycleErrorV2>
    where
        A: ProductionF6ActivationAuthorityV2 + 'static,
    {
        if self.activation.is_some() || self.active.is_some() {
            return Err(ProductionF6LifecycleErrorV2::InvalidBinding);
        }
        self.activation = Some(Box::new(authority));
        Ok(())
    }

    /// Exact reason this position cannot yet consume its first RFQ.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn pending_authority(&self) -> Option<ProductionPendingAuthorityV1> {
        if self.active.is_some() {
            None
        } else if self.activation.is_none() {
            Some(ProductionPendingAuthorityV1::F6Activation {
                position: self.pins.position,
            })
        } else {
            Some(ProductionPendingAuthorityV1::AuthenticatedRfq {
                position: self.pins.position,
            })
        }
    }

    /// Reconstructs and authenticates the concrete F6 authority from every
    /// applied inbox row before any pending row may be dispatched.
    ///
    /// The inbox remains read-only. A partial downstream reopen is retained
    /// so an exact retry can replay from the first applied RFQ again; the
    /// lifecycle becomes dispatchable only after the entire retained applied
    /// prefix returned byte-exact duplicate receipts.
    pub(crate) fn recover_applied_history(
        &mut self,
        inbox: &DurableRelayInboxV1,
    ) -> Result<F6AppliedReplayReportV1, F6AppliedReplayErrorV1<ProductionF6LifecycleErrorV2>> {
        if self.recovery_in_progress {
            return Err(F6AppliedReplayErrorV1::F6(
                ProductionF6LifecycleErrorV2::RecoveryRequired,
            ));
        }
        self.recovery_in_progress = true;
        let result = inbox.replay_applied_f6(self);
        self.recovery_in_progress = false;
        if result.is_ok() {
            self.recovery_complete = true;
        }
        result
    }

    fn authenticate_pending_rfq(
        &self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<AuthenticatedPendingRfqV2, ProductionF6LifecycleErrorV2> {
        if delivery.message_type() != message_type::RFQ
            || delivery.sender_id() != self.pins.initiator
            || *delivery.envelope_digest() == ZERO_DIGEST
        {
            return Err(ProductionF6LifecycleErrorV2::InvalidPendingRfq);
        }
        let rfq = RfqV2::decode(delivery.payload())
            .map_err(|_| ProductionF6LifecycleErrorV2::InvalidPendingRfq)?;
        rfq.validate()
            .map_err(|_| ProductionF6LifecycleErrorV2::InvalidPendingRfq)?;
        if rfq.initiator != self.pins.initiator
            || rfq.session_id != self.pins.wire.session_id
            || rfq.policy_version != self.pins.wire.policy_version
            || rfq.route.position != self.pins.position
        {
            return Err(ProductionF6LifecycleErrorV2::InvalidPendingRfq);
        }
        Ok(AuthenticatedPendingRfqV2 {
            wire: self.pins.wire,
            sequence: delivery.sequence(),
            envelope_digest: *delivery.envelope_digest(),
            rfq,
        })
    }
}

impl F6TransportPortV1 for ProductionF6LifecyclePortV2 {
    type Error = ProductionF6LifecycleErrorV2;

    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        if !self.recovery_in_progress && !self.recovery_complete {
            return Err(ProductionF6LifecycleErrorV2::RecoveryRequired);
        }
        if let Some(active) = self.active.as_mut() {
            return active
                .accept_f6(delivery)
                .map_err(ProductionF6LifecycleErrorV2::Active);
        }
        let pending = self.authenticate_pending_rfq(&delivery)?;
        let Some(activation) = self.activation.as_mut() else {
            return Err(ProductionF6LifecycleErrorV2::Awaiting(
                ProductionPendingAuthorityV1::F6Activation {
                    position: self.pins.position,
                },
            ));
        };
        let authority = activation.activate(&pending).map_err(|error| match error {
            ProductionF6ActivationRefusalV2::Awaiting(authority) => {
                ProductionF6LifecycleErrorV2::Awaiting(authority)
            }
            ProductionF6ActivationRefusalV2::InvalidBinding => {
                ProductionF6LifecycleErrorV2::InvalidBinding
            }
            ProductionF6ActivationRefusalV2::Unavailable => {
                ProductionF6LifecycleErrorV2::ActivationUnavailable
            }
        })?;
        self.active = Some(authority);
        self.active
            .as_mut()
            .ok_or(ProductionF6LifecycleErrorV2::ActivationUnavailable)?
            .accept_f6(delivery)
            .map_err(ProductionF6LifecycleErrorV2::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::rc::Rc;

    use btc_crypto::SecpContext;
    use relay::auth::{RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
    use relay::server::RelayV1;
    use relay::{RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
    use rfq::v2::{
        NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, RfqRequestV2, RouteV2,
    };
    use rfq::{AssetId, ChainId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1};
    use route_transport::{
        DurableInboxConfigV1, DurablePayloadDispositionV1, DurableRelayInboxV1, F6DispatchErrorV1,
    };
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(AuthenticatedPendingRfqV2: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(ProductionF6LifecyclePortV2: Clone, Copy);

    struct PendingActivationV2 {
        calls: Rc<Cell<u64>>,
        expected_sequence: u64,
        expected_envelope: Digest32,
        pending: ProductionPendingAuthorityV1,
    }

    impl activation_seal::Sealed for PendingActivationV2 {}

    impl ProductionF6ActivationAuthorityV2 for PendingActivationV2 {
        fn activate(
            &mut self,
            pending: &AuthenticatedPendingRfqV2,
        ) -> Result<ProductionSolverF6AuthorityV2, ProductionF6ActivationRefusalV2> {
            if pending.sequence() != self.expected_sequence
                || pending.envelope_digest() != self.expected_envelope
                || pending.wire() != wire()
                || pending.rfq().rfq_id == ZERO_DIGEST
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            self.calls.set(self.calls.get().saturating_add(1));
            Err(ProductionF6ActivationRefusalV2::Awaiting(self.pending))
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("test F6 application refused")]
    struct ApplyingF6ErrorV2;

    struct ApplyingF6V2;

    impl F6TransportPortV1 for ApplyingF6V2 {
        type Error = ApplyingF6ErrorV2;

        fn accept_f6(
            &mut self,
            delivery: F6PayloadDeliveryV1<'_>,
        ) -> Result<DurablePayloadCommitV1, Self::Error> {
            DurablePayloadCommitV1::new(
                DurablePayloadDispositionV1::Applied,
                *delivery.envelope_digest(),
                false,
            )
            .map_err(|_| ApplyingF6ErrorV2)
        }
    }

    #[test]
    fn pending_authority_is_position_exact_and_never_claims_active() {
        let pins = pins();
        let lifecycle = ProductionF6LifecyclePortV2::awaiting(pins);
        assert_eq!(
            lifecycle.pending_authority(),
            Some(ProductionPendingAuthorityV1::F6Activation {
                position: SettlementPositionV2::Upstream
            })
        );
    }

    #[test]
    fn pins_reject_zero_or_unscoped_wire_facts() {
        let mut wire = wire();
        wire.route_id = ZERO_DIGEST;
        assert!(matches!(
            ProductionAwaitingF6PinsV2::new(
                wire,
                SettlementPositionV2::Upstream,
                ParticipantId([0x61; 32]),
            ),
            Err(ProductionF6LifecycleErrorV2::InvalidBinding)
        ));
    }

    #[test]
    fn durable_inbox_retains_exact_rfq_across_awaiting_restart() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let inbox_root = temporary.path().join("f6-inbox");
        let roster = roster();
        let config = DurableInboxConfigV1::new([0x71; 32], [0xd1; 32], wire(), solver(), 16)?;
        let mut relay = RelayV1::new();
        let rfq = rfq()?;
        let envelope = signed_rfq_envelope(rfq.canonical_bytes()?)?;
        relay.submit(&envelope)?;

        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config, &roster)?;
        let ingested = inbox.ingest_ephemeral_v1(
            &relay,
            &roster,
            TimelockSpec::TimestampSeconds { value: 1_000 },
        )?;
        assert_eq!(ingested.accepted, 1);
        let mut lifecycle = ProductionF6LifecyclePortV2::awaiting(pins());
        assert!(matches!(
            inbox.dispatch_f6(&mut lifecycle),
            Err(F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::RecoveryRequired
            ))
        ));
        assert_eq!(inbox.stats()?.pending_f6, 1);
        assert_eq!(lifecycle.recover_applied_history(&inbox)?.replayed, 0);
        assert!(matches!(
            inbox.dispatch_f6(&mut lifecycle),
            Err(F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::Awaiting(
                    ProductionPendingAuthorityV1::F6Activation {
                        position: SettlementPositionV2::Upstream
                    }
                )
            ))
        ));
        let before_restart = inbox.stats()?;
        assert_eq!(before_restart.pending_f6, 1);
        assert_eq!(before_restart.delivered, 0);
        assert_eq!(before_restart.failed_closed, 0);
        drop(inbox);

        let mut reopened = DurableRelayInboxV1::open(&inbox_root, config, &roster)?;
        let mut recovered = ProductionF6LifecyclePortV2::awaiting(pins());
        assert_eq!(recovered.recover_applied_history(&reopened)?.replayed, 0);
        assert!(matches!(
            reopened.dispatch_f6(&mut recovered),
            Err(F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::Awaiting(
                    ProductionPendingAuthorityV1::F6Activation {
                        position: SettlementPositionV2::Upstream
                    }
                )
            ))
        ));
        let after_restart = reopened.stats()?;
        assert_eq!(after_restart.pending_f6, 1);
        assert_eq!(after_restart.delivered, 0);
        assert_eq!(after_restart.failed_closed, 0);
        Ok(())
    }

    #[test]
    fn activation_receives_exact_pending_rfq_and_names_next_authority() -> Result<(), Box<dyn Error>>
    {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let inbox_root = temporary.path().join("typed-pending-f6-inbox");
        let roster = roster();
        let config = DurableInboxConfigV1::new([0x74; 32], [0xd1; 32], wire(), solver(), 16)?;
        let mut relay = RelayV1::new();
        let payload = rfq()?.canonical_bytes()?;
        let envelope = signed_rfq_envelope(payload)?;
        let parsed = RelayEnvelopeV1::decode(&envelope)?;
        let envelope_digest = parsed.envelope_digest()?;
        relay.submit(&envelope)?;
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config, &roster)?;
        inbox.ingest_ephemeral_v1(
            &relay,
            &roster,
            TimelockSpec::TimestampSeconds { value: 1_000 },
        )?;
        let calls = Rc::new(Cell::new(0));
        let mut lifecycle = ProductionF6LifecyclePortV2::awaiting(pins());
        assert_eq!(lifecycle.recover_applied_history(&inbox)?.replayed, 0);
        lifecycle.install_activation_authority(PendingActivationV2 {
            calls: Rc::clone(&calls),
            expected_sequence: 0,
            expected_envelope: envelope_digest,
            pending: ProductionPendingAuthorityV1::SolverStatusEvidence,
        })?;
        assert_eq!(
            lifecycle.pending_authority(),
            Some(ProductionPendingAuthorityV1::AuthenticatedRfq {
                position: SettlementPositionV2::Upstream
            })
        );
        assert!(matches!(
            inbox.dispatch_f6(&mut lifecycle),
            Err(F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::Awaiting(
                    ProductionPendingAuthorityV1::SolverStatusEvidence
                )
            ))
        ));
        assert_eq!(calls.get(), 1);
        assert_eq!(inbox.stats()?.pending_f6, 1);
        assert_eq!(inbox.stats()?.delivered, 0);
        assert!(matches!(
            inbox.dispatch_f6(&mut lifecycle),
            Err(F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::Awaiting(
                    ProductionPendingAuthorityV1::SolverStatusEvidence
                )
            ))
        ));
        assert_eq!(calls.get(), 2);
        assert_eq!(inbox.stats()?.pending_f6, 1);
        assert_eq!(inbox.stats()?.delivered, 0);
        Ok(())
    }

    #[test]
    fn applied_rfq_replay_requires_exact_authority_before_pending_dispatch(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let inbox_root = temporary.path().join("applied-rfq-recovery");
        let roster = roster();
        let config = DurableInboxConfigV1::new([0x75; 32], [0xd1; 32], wire(), solver(), 16)?;
        let mut relay = RelayV1::new();
        let envelope = signed_rfq_envelope(rfq()?.canonical_bytes()?)?;
        let envelope_digest = RelayEnvelopeV1::decode(&envelope)?.envelope_digest()?;
        relay.submit(&envelope)?;
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config, &roster)?;
        inbox.ingest_ephemeral_v1(
            &relay,
            &roster,
            TimelockSpec::TimestampSeconds { value: 1_000 },
        )?;
        assert_eq!(inbox.dispatch_f6(&mut ApplyingF6V2)?.applied, 1);
        let before = inbox.stats()?;
        drop(inbox);

        let reopened = DurableRelayInboxV1::open(&inbox_root, config, &roster)?;
        let calls = Rc::new(Cell::new(0));
        let mut lifecycle = ProductionF6LifecyclePortV2::awaiting(pins());
        lifecycle.install_activation_authority(PendingActivationV2 {
            calls: Rc::clone(&calls),
            expected_sequence: 0,
            expected_envelope: envelope_digest,
            pending: ProductionPendingAuthorityV1::SolverStatusEvidence,
        })?;
        assert!(matches!(
            lifecycle.recover_applied_history(&reopened),
            Err(F6AppliedReplayErrorV1::F6(
                ProductionF6LifecycleErrorV2::Awaiting(
                    ProductionPendingAuthorityV1::SolverStatusEvidence
                )
            ))
        ));
        assert_eq!(calls.get(), 1);
        assert_eq!(reopened.stats()?, before);
        assert!(!lifecycle.recovery_complete);

        let wrong_position =
            ProductionAwaitingF6PinsV2::new(wire(), SettlementPositionV2::Downstream, initiator())?;
        let mut transplanted = ProductionF6LifecyclePortV2::awaiting(wrong_position);
        assert!(matches!(
            transplanted.recover_applied_history(&reopened),
            Err(F6AppliedReplayErrorV1::F6(
                ProductionF6LifecycleErrorV2::InvalidPendingRfq
            ))
        ));
        assert_eq!(reopened.stats()?, before);
        assert!(!transplanted.recovery_complete);
        Ok(())
    }

    #[test]
    fn cross_position_rfq_remains_pending_without_activation_call() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let inbox_root = temporary.path().join("transplanted-f6-inbox");
        let roster = roster();
        let config = DurableInboxConfigV1::new([0x72; 32], [0xd1; 32], wire(), solver(), 16)?;
        let mut relay = RelayV1::new();
        let mut foreign = rfq()?;
        foreign.route.position = SettlementPositionV2::Downstream;
        foreign = RfqV2::create(RfqRequestV2 {
            initiator: foreign.initiator,
            route: foreign.route,
            mode: foreign.mode,
            fee_limit: foreign.fee_limit,
            negotiation_clock: foreign.negotiation_clock,
            quote_deadline: foreign.quote_deadline,
            assurance_policy_ref: foreign.assurance_policy_ref,
            policy_version: foreign.policy_version,
            session_id: foreign.session_id,
        })?;
        let envelope = signed_rfq_envelope(foreign.canonical_bytes()?)?;
        let parsed = RelayEnvelopeV1::decode(&envelope)?;
        relay.submit(&envelope)?;
        let mut inbox = DurableRelayInboxV1::create(&inbox_root, config, &roster)?;
        inbox.ingest_ephemeral_v1(
            &relay,
            &roster,
            TimelockSpec::TimestampSeconds { value: 1_000 },
        )?;
        let calls = Rc::new(Cell::new(0));
        let mut lifecycle = ProductionF6LifecyclePortV2::awaiting(pins());
        assert_eq!(lifecycle.recover_applied_history(&inbox)?.replayed, 0);
        lifecycle.install_activation_authority(PendingActivationV2 {
            calls: Rc::clone(&calls),
            expected_sequence: 0,
            expected_envelope: parsed.envelope_digest()?,
            pending: ProductionPendingAuthorityV1::SolverStatusEvidence,
        })?;
        assert!(matches!(
            inbox.dispatch_f6(&mut lifecycle),
            Err(F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::InvalidPendingRfq
            ))
        ));
        assert_eq!(calls.get(), 0);
        assert_eq!(inbox.stats()?.pending_f6, 1);
        assert_eq!(inbox.stats()?.delivered, 0);
        Ok(())
    }

    fn wire() -> RouteWireContextV1 {
        RouteWireContextV1 {
            network_id: [0x11; 32],
            session_id: [0x22; 32],
            route_id: [0x33; 32],
            roster_snapshot: [0x44; 32],
            policy_version: 3,
        }
    }

    fn pins() -> ProductionAwaitingF6PinsV2 {
        ProductionAwaitingF6PinsV2::new(
            wire(),
            SettlementPositionV2::Upstream,
            ParticipantId([0x61; 32]),
        )
        .expect("fixed lifecycle pins are valid")
    }

    fn initiator() -> ParticipantId {
        ParticipantId([0x61; 32])
    }

    fn solver() -> ParticipantId {
        ParticipantId([0x62; 32])
    }

    fn roster() -> RosterRegistryV1 {
        let secp = SecpContext::new(&[0x91; 32]);
        let initiator_key = secp
            .sign_bip340(&[0x52; 32], &[0x01; 32], &[0x02; 32])
            .expect("fixture key is valid")
            .1;
        let solver_key = secp
            .sign_bip340(&[0x53; 32], &[0x01; 32], &[0x03; 32])
            .expect("fixture key is valid")
            .1;
        RosterRegistryV1::new().with_snapshot(
            wire().roster_snapshot,
            RosterSnapshotV1::new()
                .with_member(
                    initiator(),
                    RosterMemberV1 {
                        xonly_key: initiator_key,
                        role: SenderRoleV1::Initiator,
                    },
                )
                .with_member(
                    solver(),
                    RosterMemberV1 {
                        xonly_key: solver_key,
                        role: SenderRoleV1::Solver,
                    },
                ),
        )
    }

    fn rfq() -> Result<RfqV2, Box<dyn Error>> {
        let clock = NegotiationClockV2 {
            chain_id: ChainId([0x81; 32]),
            profile_digest: [0x82; 32],
            authority_scope: [0x83; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        Ok(RfqV2::create(RfqRequestV2 {
            initiator: initiator(),
            route: RouteV2 {
                composition_id: [0x51; 32],
                position: SettlementPositionV2::Upstream,
                legs: [
                    RouteLegV1 {
                        chain_id: ChainId([0x84; 32]),
                        asset: AssetId([0x85; 32]),
                        direction: LegDirectionV1::UserGives,
                    },
                    RouteLegV1 {
                        chain_id: clock.chain_id,
                        asset: AssetId([0x86; 32]),
                        direction: LegDirectionV1::UserReceives,
                    },
                ],
            },
            mode: RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 90,
            },
            fee_limit: FeeLimitV1 {
                dom_max: 4,
                counterparty_max: 6,
            },
            negotiation_clock: clock,
            quote_deadline: NegotiationInstantV2 {
                clock,
                value: 1_100,
            },
            assurance_policy_ref: PolicyId([0x87; 32]),
            policy_version: wire().policy_version,
            session_id: wire().session_id,
        })?)
    }

    fn signed_rfq_envelope(payload: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut envelope = RelayEnvelopeV1 {
            network_id: wire().network_id,
            message_type: message_type::RFQ,
            session_id: wire().session_id,
            route_id: wire().route_id,
            sender_id: initiator(),
            recipient_id: solver(),
            sender_role: SenderRoleV1::Initiator,
            sequence: 0,
            previous_transcript_hash: ZERO_DIGEST,
            payload,
            expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
            policy_version: wire().policy_version,
            roster_snapshot: wire().roster_snapshot,
            signature: [0; 64],
        };
        let digest = envelope.envelope_digest()?;
        envelope.signature = SecpContext::new(&[0x91; 32])
            .sign_bip340(&[0x52; 32], &digest, &[0x92; 32])?
            .0;
        Ok(envelope.canonical_bytes()?)
    }
}

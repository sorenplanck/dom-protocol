//! DOM claim -> exact XMR sweep outbox bridge.
//!
//! Kaystra remains the sole economic state machine. This sink consumes the
//! scalar already extracted by the DOM claim-consumption effect. It never
//! creates another settlement coordinator.

#![forbid(unsafe_code)]

use adapter_dom_real::RevealedSecretSinkV1;
use counterparty_api::RevealedSecretBytes;
use kaystra_core::{
    settlement_engine::EffectOutcome,
    state::{Effect, EvidenceRefV1},
    store_port::ClaimedEffectV1,
    types::SettlementId,
};
use xmr_crypto::XmrSpendShare;
use xmr_delivery::{DeliveryError, DeliveryRecord, DeliveryState, DeliveryStore};
use xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar;
use xmr_live_sidecar_api::{BuildSweepRequestV2, SecretScalarBytes, API_VERSION_V2};
use xmr_secret_store::{SecretMaterialStore, SecretStoreError};
use xmr_setup_profile::ValidatedXmrSetup;
use xmr_spend_port::{ExactBroadcastPort, SpendPortError, SweepBuildPort};

/// XMR sink installed into `RealDomEffectSinkV1`.
pub struct XmrClaimToSpendSink<S, D, B, R> {
    settlement_id: SettlementId,
    setup: ValidatedXmrSetup,
    secrets: S,
    delivery: D,
    builder: B,
    broadcaster: R,
}

impl<S, D, B, R> core::fmt::Debug for XmrClaimToSpendSink<S, D, B, R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrClaimToSpendSink")
            .field("settlement_id", &self.settlement_id)
            .field("setup", &self.setup)
            .field("secrets", &"<encrypted-store>")
            .field("delivery", &"<exact-byte-store>")
            .finish_non_exhaustive()
    }
}

impl<S, D, B, R> XmrClaimToSpendSink<S, D, B, R>
where
    S: SecretMaterialStore,
    D: DeliveryStore,
    B: SweepBuildPort,
    R: ExactBroadcastPort,
{
    /// Binds all ports to one validated settlement setup.
    pub fn new(
        setup: ValidatedXmrSetup,
        secrets: S,
        delivery: D,
        builder: B,
        broadcaster: R,
    ) -> Self {
        Self {
            settlement_id: SettlementId(setup.settlement_id()),
            setup,
            secrets,
            delivery,
            builder,
            broadcaster,
        }
    }

    /// Exposes ports for test-only inspection without private material.
    pub fn ports(&self) -> (&S, &D, &B, &R) {
        (
            &self.secrets,
            &self.delivery,
            &self.builder,
            &self.broadcaster,
        )
    }

    fn consume(
        &mut self,
        effect: &ClaimedEffectV1,
        evidence: &EvidenceRefV1,
        revealed: &RevealedSecretBytes,
    ) -> EffectOutcome {
        if effect.settlement_id != self.settlement_id {
            return EffectOutcome::Rejected;
        }
        match &effect.kind {
            Effect::RequestClaimConsumption { evidence: expected } if expected == evidence => {}
            _ => return EffectOutcome::Rejected,
        }
        let settlement_id = self.setup.settlement_id();
        let source_effect_id = effect.effect_id.0;

        match self.delivery.load(&settlement_id) {
            Ok(Some(record)) => {
                if record.source_effect_id != source_effect_id {
                    return EffectOutcome::Rejected;
                }
                return match record.state {
                    DeliveryState::Confirmed | DeliveryState::Submitted => {
                        match self.delete_secrets_after_durability() {
                            Ok(()) => EffectOutcome::Completed,
                            Err(outcome) => outcome,
                        }
                    }
                    DeliveryState::Prepared => {
                        if let Err(outcome) = self.delete_secrets_after_durability() {
                            return outcome;
                        }
                        self.broadcast_prepared(record)
                    }
                };
            }
            Ok(None) => {}
            Err(error) => return map_delivery_error(error),
        }

        let remote_scalar = match revealed_dom_secret_to_xmr_scalar(
            revealed.expose_scalar_bytes(),
            &self.setup.claim(),
        ) {
            Ok(value) => value,
            Err(_) => return EffectOutcome::Rejected,
        };
        let remote_share = match XmrSpendShare::from_canonical_bytes(remote_scalar) {
            Ok(value) => value,
            Err(_) => return EffectOutcome::Rejected,
        };
        let material = match self.secrets.load(&settlement_id, &self.setup.terms_hash()) {
            Ok(value) => value,
            Err(error) => return map_secret_error(error),
        };

        let funding_tx_hash = self.setup.funding_tx_hash();
        let expected_amount_piconero = self.setup.expected_amount_piconero();
        let destination = self.setup.destination().to_owned();
        let expected_spend_public_key = self.setup.combined_spend_public_key();
        let builder = &mut self.builder;
        let response = match material.expose(|local_bytes, view_bytes| {
            let local = XmrSpendShare::from_canonical_bytes(*local_bytes)
                .map_err(|_| SpendPortError::Rejected)?;
            let combined = local
                .combine(&remote_share)
                .map_err(|_| SpendPortError::Rejected)?;
            if combined
                .public_key()
                .map_err(|_| SpendPortError::Rejected)?
                != expected_spend_public_key
            {
                return Err(SpendPortError::Rejected);
            }
            combined.with_scalar(|spend_scalar| {
                builder.build_sweep(BuildSweepRequestV2 {
                    api_version: API_VERSION_V2,
                    request_nonce: source_effect_id,
                    settlement_id,
                    funding_tx_hash,
                    expected_amount_piconero,
                    destination,
                    spend_scalar: SecretScalarBytes::new(*spend_scalar),
                    expected_spend_public_key,
                    view_scalar: SecretScalarBytes::new(*view_bytes),
                    auth_tag: [0; 32],
                })
            })
        }) {
            Ok(value) => value,
            Err(error) => return map_port_error(error),
        };
        if response.validate_for(&source_effect_id).is_err() {
            return EffectOutcome::Rejected;
        }
        let record = match self.delivery.prepare_exact(
            settlement_id,
            source_effect_id,
            response.tx_hash,
            &response.raw_tx,
        ) {
            Ok(value) => value,
            Err(error) => return map_delivery_error(error),
        };

        // Exact signed bytes are durable. Delete reconstruction secrets before
        // any potentially ambiguous network submission.
        if let Err(outcome) = self.delete_secrets_after_durability() {
            return outcome;
        }
        self.broadcast_prepared(record)
    }

    fn delete_secrets_after_durability(&self) -> Result<(), EffectOutcome> {
        match self.secrets.delete(&self.setup.settlement_id()) {
            Ok(()) | Err(SecretStoreError::NotFound) => Ok(()),
            Err(error) => Err(map_secret_error(error)),
        }
    }

    fn broadcast_prepared(&mut self, record: DeliveryRecord) -> EffectOutcome {
        match self
            .broadcaster
            .submit_exact(record.tx_hash, &record.raw_tx)
        {
            Ok(_) => match self.delivery.mark_submitted(&record.settlement_id) {
                Ok(()) => EffectOutcome::Completed,
                Err(error) => map_delivery_error(error),
            },
            Err(error) => map_port_error(error),
        }
    }
}

impl<S, D, B, R> RevealedSecretSinkV1 for XmrClaimToSpendSink<S, D, B, R>
where
    S: SecretMaterialStore,
    D: DeliveryStore,
    B: SweepBuildPort,
    R: ExactBroadcastPort,
{
    fn consume_revealed_secret(
        &mut self,
        effect: &ClaimedEffectV1,
        evidence: &EvidenceRefV1,
        revealed: &RevealedSecretBytes,
    ) -> EffectOutcome {
        self.consume(effect, evidence, revealed)
    }
}

fn map_port_error(error: SpendPortError) -> EffectOutcome {
    match error {
        SpendPortError::Retryable => EffectOutcome::RetryLater,
        SpendPortError::Rejected => EffectOutcome::Rejected,
    }
}

fn map_delivery_error(error: DeliveryError) -> EffectOutcome {
    match error {
        DeliveryError::Poisoned | DeliveryError::StorageUnavailable | DeliveryError::NotFound => {
            EffectOutcome::RetryLater
        }
        DeliveryError::InvalidTransaction
        | DeliveryError::BoundsExceeded
        | DeliveryError::ConflictingRetransmission
        | DeliveryError::Corrupt => EffectOutcome::Rejected,
    }
}

fn map_secret_error(error: SecretStoreError) -> EffectOutcome {
    match error {
        SecretStoreError::Unavailable | SecretStoreError::NotFound => EffectOutcome::RetryLater,
        SecretStoreError::InvalidMaterial
        | SecretStoreError::Conflict
        | SecretStoreError::AuthenticationFailed => EffectOutcome::Rejected,
    }
}

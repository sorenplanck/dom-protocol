//! DOM claim -> exact Solana escrow Claim outbox bridge.
//!
//! Kaystra remains the sole economic state machine. This sink consumes the
//! scalar already extracted by the DOM claim-consumption effect and turns it
//! into exactly one durable, replayable `Claim` transaction against the
//! escrow program. It never creates another settlement coordinator.
//!
//! Unlike the XMR sink there is no local share to combine: the revealed DOM
//! scalar is the whole witness the program verifies, so the bridge's job is
//! validation, exact-bytes durability, witness-store hygiene, and broadcast —
//! in that order. The stored route witness is deleted only after the signed
//! claim bytes are durable, mirroring the XMR discipline.

#![forbid(unsafe_code)]

use adapter_dom_real::RevealedSecretSinkV1;
use counterparty_api::RevealedSecretBytes;
use kaystra_core::{
    settlement_engine::EffectOutcome,
    state::{Effect, EvidenceRefV1},
    store_port::ClaimedEffectV1,
    types::SettlementId,
};
use solana_delivery::{
    DeliveryError, DeliveryRecord, DeliveryState, DeliveryStore, MAX_SIGNED_TRANSACTION_BYTES,
};
use solana_profile::ValidatedSolanaSetup;
use solana_secret_store::{SecretStoreError, WitnessMaterialStore};
use solana_types::SolanaSignature;
use xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar;

/// Port failures, split by whether a retry can change the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimPortError {
    /// Transient: RPC quorum unavailable, blockhash expired, and the like.
    #[error("retryable Solana claim port failure")]
    Retryable,
    /// Permanent for these inputs.
    #[error("rejected Solana claim port request")]
    Rejected,
}

/// One built claim: exact signed wire bytes plus their primary signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltClaimV1 {
    /// Echo of the request nonce (the source effect id).
    pub request_nonce: [u8; 32],
    /// Exact signed transaction bytes, ready for `sendTransaction`.
    pub raw_transaction: Vec<u8>,
    /// The transaction's primary (fee payer) signature.
    pub signature: SolanaSignature,
}

impl BuiltClaimV1 {
    /// Structural validation independent of the port that produced it: the
    /// nonce must echo, the bytes must be a plausible signed transaction no
    /// larger than a packet, and the named signature must be the first one
    /// in the wire encoding, so the delivery journal keys on a signature the
    /// bytes actually carry.
    pub fn validate_for(&self, request_nonce: &[u8; 32]) -> Result<(), ClaimPortError> {
        if &self.request_nonce != request_nonce
            || self.raw_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES
        {
            return Err(ClaimPortError::Rejected);
        }
        // Legacy wire form: shortvec signature count, then 64 bytes each.
        // One-byte counts cover every transaction a packet can hold.
        let (count, first) = match self.raw_transaction.split_first() {
            Some((count, rest)) if (1..=19).contains(count) => (*count as usize, rest),
            _ => return Err(ClaimPortError::Rejected),
        };
        if first.len() < count * 64 || first[..64] != self.signature.0[..] {
            return Err(ClaimPortError::Rejected);
        }
        Ok(())
    }
}

/// Builds one exact signed `Claim` transaction for the bound settlement.
///
/// Implementations own everything the bridge must not: the fee payer key,
/// the recent-blockhash fetch, and the instruction assembly through
/// `solana-program-client` and `solana-transaction-builder`.
pub trait ClaimBuildPort: Send {
    fn build_claim(
        &mut self,
        request_nonce: [u8; 32],
        setup: &ValidatedSolanaSetup,
        revealed_secret_be: [u8; 32],
    ) -> Result<BuiltClaimV1, ClaimPortError>;
}

/// Submits exact, already-journalled bytes. Byte-for-byte, no re-signing.
pub trait ExactBroadcastPort: Send {
    fn submit_exact(
        &mut self,
        signature: SolanaSignature,
        raw_transaction: &[u8],
    ) -> Result<(), ClaimPortError>;
}

/// Solana sink installed into `RealDomEffectSinkV1`.
pub struct SolanaClaimSink<S, D, B, R> {
    settlement_id: SettlementId,
    setup: ValidatedSolanaSetup,
    secrets: S,
    delivery: D,
    builder: B,
    broadcaster: R,
}

impl<S, D, B, R> core::fmt::Debug for SolanaClaimSink<S, D, B, R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SolanaClaimSink")
            .field("settlement_id", &self.settlement_id)
            .field("secrets", &"<encrypted-store>")
            .field("delivery", &"<exact-byte-store>")
            .finish_non_exhaustive()
    }
}

impl<S, D, B, R> SolanaClaimSink<S, D, B, R>
where
    S: WitnessMaterialStore,
    D: DeliveryStore,
    B: ClaimBuildPort,
    R: ExactBroadcastPort,
{
    /// Binds all ports to one validated settlement setup.
    pub fn new(
        setup: ValidatedSolanaSetup,
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
                if record.source_operation_id != source_effect_id {
                    return EffectOutcome::Rejected;
                }
                return match record.state {
                    DeliveryState::Finalized | DeliveryState::Submitted => {
                        match self.delete_witness_after_durability() {
                            Ok(()) => EffectOutcome::Completed,
                            Err(outcome) => outcome,
                        }
                    }
                    DeliveryState::Prepared => {
                        if let Err(outcome) = self.delete_witness_after_durability() {
                            return outcome;
                        }
                        self.broadcast_prepared(record)
                    }
                };
            }
            Ok(None) => {}
            Err(error) => return map_delivery_error(error),
        }

        // The revealed scalar must open exactly this settlement's registered
        // cross-curve claim on both curves. Anything else is not ours.
        let revealed_secret_be = revealed.expose_scalar_bytes();
        if revealed_dom_secret_to_xmr_scalar(revealed_secret_be, &self.setup.claim()).is_err() {
            return EffectOutcome::Rejected;
        }

        let response =
            match self
                .builder
                .build_claim(source_effect_id, &self.setup, revealed_secret_be)
            {
                Ok(value) => value,
                Err(error) => return map_port_error(error),
            };
        if response.validate_for(&source_effect_id).is_err() {
            return EffectOutcome::Rejected;
        }
        let record = match self.delivery.prepare_exact(
            settlement_id,
            source_effect_id,
            response.signature,
            &response.raw_transaction,
        ) {
            Ok(value) => value,
            Err(error) => return map_delivery_error(error),
        };

        // Exact signed bytes are durable. Delete the stored route witness
        // before any potentially ambiguous network submission.
        if let Err(outcome) = self.delete_witness_after_durability() {
            return outcome;
        }
        self.broadcast_prepared(record)
    }

    fn delete_witness_after_durability(&self) -> Result<(), EffectOutcome> {
        match self.secrets.delete(&self.setup.settlement_id()) {
            Ok(()) | Err(SecretStoreError::NotFound) => Ok(()),
            Err(error) => Err(map_secret_error(error)),
        }
    }

    fn broadcast_prepared(&mut self, record: DeliveryRecord) -> EffectOutcome {
        match self
            .broadcaster
            .submit_exact(record.signature, &record.raw_transaction)
        {
            Ok(()) => match self.delivery.mark_submitted(&record.settlement_id) {
                Ok(()) => EffectOutcome::Completed,
                Err(error) => map_delivery_error(error),
            },
            Err(error) => map_port_error(error),
        }
    }
}

impl<S, D, B, R> RevealedSecretSinkV1 for SolanaClaimSink<S, D, B, R>
where
    S: WitnessMaterialStore,
    D: DeliveryStore,
    B: ClaimBuildPort,
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

fn map_port_error(error: ClaimPortError) -> EffectOutcome {
    match error {
        ClaimPortError::Retryable => EffectOutcome::RetryLater,
        ClaimPortError::Rejected => EffectOutcome::Rejected,
    }
}

fn map_delivery_error(error: DeliveryError) -> EffectOutcome {
    match error {
        DeliveryError::Poisoned | DeliveryError::StorageUnavailable | DeliveryError::NotFound => {
            EffectOutcome::RetryLater
        }
        DeliveryError::Invalid
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

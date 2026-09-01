//! Solana implementation of the neutral counterparty adapter boundary.

#![forbid(unsafe_code)]

use counterparty_api::{
    AdapterError, AdaptorPointBytes, ChainCapabilities, ChainCursor, CounterpartyAdapter,
    CounterpartyChainId, FinalityPolicy, LockMechanism, NeutralTerms, ObservedEvent,
    OpaqueArtifact, RevealedSecretBytes, TimelockDomain, VerifiedOutcome, MAX_EVENTS_PER_OBSERVE,
};
use solana_evidence::{SolanaEvidenceBodyV1, SolanaEvidenceEnvelopeV1};

/// Chain-specific backend hidden behind the neutral adapter.
#[allow(async_fn_in_trait)]
pub trait SolanaAdapterBackend: Send + Sync {
    /// Build the exact initialize artifact for local signing.
    async fn prepare_initialize(
        &self,
        terms: &NeutralTerms,
        adaptor_point: &AdaptorPointBytes,
    ) -> Result<Vec<u8>, AdapterError>;

    /// Observe already-filtered Solana program events.
    async fn observe(
        &self,
        cursor: &[u8],
        max: usize,
    ) -> Result<(Vec<ObservedEvent>, Vec<u8>), AdapterError>;
}

/// Neutral Solana adapter.
pub struct SolanaCounterpartyAdapter<B> {
    backend: B,
    chain_id: CounterpartyChainId,
    version: u32,
    finality: FinalityPolicy,
}

impl<B> SolanaCounterpartyAdapter<B> {
    /// Construct an adapter with frozen identity/finality.
    pub fn new(
        backend: B,
        chain_id: CounterpartyChainId,
        version: u32,
        finality: FinalityPolicy,
    ) -> Result<Self, AdapterError> {
        if chain_id.0 == [0; 32]
            || version == 0
            || finality.min_confirmations == 0
            || finality.max_reorg_depth < finality.min_confirmations
        {
            return Err(AdapterError::PreconditionUnsatisfied);
        }
        Ok(Self {
            backend,
            chain_id,
            version,
            finality,
        })
    }
}

impl<B: SolanaAdapterBackend> CounterpartyAdapter for SolanaCounterpartyAdapter<B> {
    fn chain_id(&self) -> CounterpartyChainId {
        self.chain_id
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            supports_condition_lock: true,
            supports_schnorr_adaptor: false,
            supports_hashlock_fallback: false,
            timelock_domain: TimelockDomain::Timestamp,
            finality: self.finality,
        }
    }

    fn adapter_version(&self) -> u32 {
        self.version
    }

    async fn prepare_lock(
        &self,
        terms: &NeutralTerms,
        adaptor_point: &AdaptorPointBytes,
    ) -> Result<OpaqueArtifact, AdapterError> {
        self.capabilities().require(LockMechanism::ConditionLock)?;
        if terms.amount == 0 || terms.deadline == 0 {
            return Err(AdapterError::PreconditionUnsatisfied);
        }
        let bytes = self
            .backend
            .prepare_initialize(terms, adaptor_point)
            .await?;
        if bytes.is_empty() {
            return Err(AdapterError::EvidenceInvalid);
        }
        Ok(OpaqueArtifact {
            chain: self.chain_id,
            adapter_version: self.version,
            bytes,
        })
    }

    async fn observe(
        &self,
        cursor: &ChainCursor,
        max: usize,
    ) -> Result<(Vec<ObservedEvent>, ChainCursor), AdapterError> {
        if max > MAX_EVENTS_PER_OBSERVE {
            return Err(AdapterError::BoundsExceeded);
        }
        let (events, next) = self.backend.observe(&cursor.0, max).await?;
        if events.len() > max {
            return Err(AdapterError::BoundsExceeded);
        }
        Ok((events, ChainCursor(next)))
    }

    async fn verify_evidence(&self, evidence: &[u8]) -> Result<VerifiedOutcome, AdapterError> {
        let envelope = SolanaEvidenceEnvelopeV1::decode(evidence)
            .map_err(|_| AdapterError::EvidenceInvalid)?;
        match envelope.body {
            SolanaEvidenceBodyV1::Funding(value) => {
                Ok(VerifiedOutcome::Funded { height: value.slot })
            }
            SolanaEvidenceBodyV1::Claim(value) => Ok(VerifiedOutcome::Claimed {
                revealed: RevealedSecretBytes::new(value.revealed_secret_be),
                height: value.slot,
            }),
            SolanaEvidenceBodyV1::Refund(value) => {
                Ok(VerifiedOutcome::Refunded { height: value.slot })
            }
        }
    }
}

//! Drives quorum-backed Monero observations into the durable Kaystra feed.

#![forbid(unsafe_code)]

use kaystra_core::types::ChainId;
use sha2::{Digest, Sha256};
use xmr_delivery::{DeliveryError, DeliveryState, DeliveryStore};
use xmr_evidence::{XmrFundingEvidenceV2, XmrSpendEvidenceV2};
use xmr_kaystra_source::{VerifiedXmrEvent, VerifiedXmrEventKind, VerifiedXmrFeed, XmrBlockAnchor};
use xmr_live_sidecar_api::{SecretScalarBytes, VerifyFundingRequestV2, API_VERSION_V2};
use xmr_observation_store::{ObservationStoreError, SqliteVerifiedXmrFeed};
use xmr_observer::{
    confirmation_status, CanonicalTip, XmrObserverError, XmrRpc, XmrRpcPool, XmrTransactionStatus,
};
use xmr_secret_store::{SecretMaterialStore, SecretStoreError};
use xmr_setup_profile::ValidatedXmrSetup;
use xmr_spend_port::{FundingVerifyPort, SpendPortError};

/// Maximum headers replaced in one invocation.
pub const MAX_HEADER_REFRESH: u64 = 4096;

/// Immutable observation plan derived from validated setup and frozen policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmrObservationPlan {
    /// Registry chain id.
    pub chain_id: ChainId,
    /// Settlement id.
    pub settlement_id: [u8; 32],
    /// Frozen terms hash.
    pub terms_hash: [u8; 32],
    /// Funding transaction.
    pub funding_tx_hash: [u8; 32],
    /// Exact expected amount.
    pub expected_amount_piconero: u64,
    /// Combined public spend key.
    pub combined_spend_public_key: [u8; 32],
    /// Confirmation target.
    pub min_confirmations: u32,
    /// Maximum reorg depth.
    pub max_reorg_depth: u32,
    /// First height that may contain relevant evidence.
    pub restore_height: u64,
}

impl XmrObservationPlan {
    /// Creates a plan from validated setup and explicit frozen policy.
    pub fn from_setup(
        setup: &ValidatedXmrSetup,
        chain_id: ChainId,
        min_confirmations: u32,
        max_reorg_depth: u32,
        restore_height: u64,
    ) -> Result<Self, PumpError> {
        if chain_id.0 == [0; 32] || min_confirmations == 0 || max_reorg_depth < min_confirmations {
            return Err(PumpError::InvalidPlan);
        }
        Ok(Self {
            chain_id,
            settlement_id: setup.settlement_id(),
            terms_hash: setup.terms_hash(),
            funding_tx_hash: setup.funding_tx_hash(),
            expected_amount_piconero: setup.expected_amount_piconero(),
            combined_spend_public_key: setup.combined_spend_public_key(),
            min_confirmations,
            max_reorg_depth,
            restore_height,
        })
    }
}

/// Observation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationProgress {
    /// Transaction is not yet final.
    Pending { confirmations: u64 },
    /// Funding record was inserted idempotently.
    FundingFinal { evidence_id: [u8; 32] },
    /// Spend/claim record was inserted and delivery marked confirmed.
    SpendFinal { evidence_id: [u8; 32] },
}

/// Pump failures, all fail closed.
#[derive(Debug, thiserror::Error)]
pub enum PumpError {
    /// Frozen inputs are invalid.
    #[error("invalid XMR observation plan")]
    InvalidPlan,
    /// RPC quorum failed.
    #[error("XMR observer: {0}")]
    Observer(#[from] XmrObserverError),
    /// Verified feed failed.
    #[error("XMR observation store: {0}")]
    Store(#[from] ObservationStoreError),
    /// Secret material failed.
    #[error("XMR secret material: {0}")]
    Secret(#[from] SecretStoreError),
    /// Funding verification sidecar failed.
    #[error("XMR funding verifier failed: {0}")]
    FundingPort(#[from] SpendPortError),
    /// Delivery state is absent/inconsistent.
    #[error("XMR delivery state: {0}")]
    Delivery(#[from] DeliveryError),
    /// Reorg exceeds frozen policy.
    #[error("XMR reorg exceeds frozen depth")]
    ReorgTooDeep,
    /// A count/height cannot be represented.
    #[error("XMR observation bound exceeded")]
    BoundsExceeded,
}

/// Quorum-backed observation driver.
pub struct XmrObservationPump<R, V, S> {
    pool: XmrRpcPool<R>,
    verifier: V,
    secrets: S,
    feed: SqliteVerifiedXmrFeed,
    plan: XmrObservationPlan,
}

impl<R, V, S> core::fmt::Debug for XmrObservationPump<R, V, S> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrObservationPump")
            .field("plan", &self.plan)
            .field("pool", &"<quorum-pool>")
            .field("verifier", &"<authenticated-sidecar>")
            .field("secrets", &"<encrypted-store>")
            .finish_non_exhaustive()
    }
}

impl<R, V, S> XmrObservationPump<R, V, S>
where
    R: XmrRpc,
    V: FundingVerifyPort,
    S: SecretMaterialStore,
{
    /// Binds the ports and persistent feed.
    pub fn new(
        pool: XmrRpcPool<R>,
        verifier: V,
        secrets: S,
        feed: SqliteVerifiedXmrFeed,
        plan: XmrObservationPlan,
    ) -> Self {
        Self {
            pool,
            verifier,
            secrets,
            feed,
            plan,
        }
    }

    /// Returns the feed after pumping, for construction of `XmrKaystraSource`.
    pub fn into_parts(self) -> (SqliteVerifiedXmrFeed, V, S) {
        (self.feed, self.verifier, self.secrets)
    }

    /// Reconciles the durable canonical header suffix with quorum RPCs.
    pub async fn refresh_canonical_headers(&self) -> Result<CanonicalTip, PumpError> {
        let remote_tip = self.pool.canonical_tip().await?;
        if remote_tip.height < self.plan.restore_height {
            return Err(PumpError::InvalidPlan);
        }
        let local_tip = self.feed.tip().map_err(map_feed_error)?;
        let replacement_from = match local_tip {
            None => self.plan.restore_height,
            Some(local) => {
                let comparison_height = local.height.min(remote_tip.height);
                let floor = comparison_height
                    .saturating_sub(u64::from(self.plan.max_reorg_depth))
                    .max(self.plan.restore_height);
                let mut common = None;
                let mut height = comparison_height;
                loop {
                    let local_hash = self.feed.block_hash(height).map_err(map_feed_error)?;
                    let remote_hash = self.pool.block_hash(height).await?;
                    if local_hash == Some(remote_hash) {
                        common = Some(height);
                        break;
                    }
                    if height == floor {
                        break;
                    }
                    height -= 1;
                }
                match common {
                    Some(height)
                        if height == remote_tip.height && local.height == remote_tip.height =>
                    {
                        return Ok(remote_tip);
                    }
                    Some(height) => height.checked_add(1).ok_or(PumpError::BoundsExceeded)?,
                    None if local.height < self.plan.restore_height => self.plan.restore_height,
                    None => return Err(PumpError::ReorgTooDeep),
                }
            }
        };
        if replacement_from > remote_tip.height {
            return Ok(remote_tip);
        }
        let count = remote_tip.height - replacement_from + 1;
        if count > MAX_HEADER_REFRESH {
            return Err(PumpError::BoundsExceeded);
        }
        let mut blocks =
            Vec::with_capacity(usize::try_from(count).map_err(|_| PumpError::BoundsExceeded)?);
        for height in replacement_from..=remote_tip.height {
            blocks.push(XmrBlockAnchor {
                height,
                hash: self.pool.block_hash(height).await?,
            });
        }
        self.feed
            .replace_canonical_suffix(replacement_from, &blocks)?;
        Ok(remote_tip)
    }

    /// Verifies and inserts final funding evidence.
    pub async fn observe_funding(&mut self) -> Result<ObservationProgress, PumpError> {
        self.refresh_canonical_headers().await?;
        let status = confirmation_status(&self.pool, self.plan.funding_tx_hash).await?;
        if !status.is_final(u64::from(self.plan.min_confirmations)) {
            return Ok(ObservationProgress::Pending {
                confirmations: status.confirmations,
            });
        }
        let block_height = match status.status {
            XmrTransactionStatus::InBlock { block_height } => block_height,
            _ => return Ok(ObservationProgress::Pending { confirmations: 0 }),
        };
        let block_hash = status.inclusion_block_hash.ok_or(PumpError::InvalidPlan)?;
        let request_nonce = observation_nonce(
            b"FUNDING",
            self.plan.settlement_id,
            self.plan.funding_tx_hash,
            block_hash,
        );
        let material = self
            .secrets
            .load(&self.plan.settlement_id, &self.plan.terms_hash)?;
        let response = material.expose(|_, view| {
            self.verifier.verify_funding(VerifyFundingRequestV2 {
                api_version: API_VERSION_V2,
                request_nonce,
                settlement_id: self.plan.settlement_id,
                funding_tx_hash: self.plan.funding_tx_hash,
                expected_amount_piconero: self.plan.expected_amount_piconero,
                expected_spend_public_key: self.plan.combined_spend_public_key,
                view_scalar: SecretScalarBytes::new(*view),
                auth_tag: [0; 32],
            })
        })?;
        let confirmations =
            u32::try_from(status.confirmations).map_err(|_| PumpError::BoundsExceeded)?;
        let evidence = XmrFundingEvidenceV2 {
            settlement_id: self.plan.settlement_id,
            terms_hash: self.plan.terms_hash,
            tx_hash: self.plan.funding_tx_hash,
            output_index: response.event_index,
            amount_piconero: response.received_amount_piconero,
            block_height,
            block_hash,
            confirmations,
            destination_commitment: self.plan.combined_spend_public_key,
        };
        evidence
            .validate(self.plan.min_confirmations)
            .map_err(|_| PumpError::InvalidPlan)?;
        self.feed.insert_event(&VerifiedXmrEvent {
            settlement_id: self.plan.settlement_id,
            terms_hash: self.plan.terms_hash,
            kind: VerifiedXmrEventKind::Funding,
            evidence: kaystra_core::state::EvidenceRefV1 {
                chain_id: self.plan.chain_id,
                tx_id: evidence.tx_hash,
                event_index: evidence.output_index,
                block_height: evidence.block_height,
                block_anchor: evidence.block_hash,
            },
        })?;
        Ok(ObservationProgress::FundingFinal {
            evidence_id: evidence.evidence_id(),
        })
    }

    /// Confirms the exact delivered sweep and inserts a Kaystra claim record.
    pub async fn observe_submitted_spend<D: DeliveryStore>(
        &self,
        delivery: &D,
    ) -> Result<ObservationProgress, PumpError> {
        self.refresh_canonical_headers().await?;
        let record = delivery
            .load(&self.plan.settlement_id)?
            .ok_or(DeliveryError::NotFound)?;
        if !matches!(
            record.state,
            DeliveryState::Submitted | DeliveryState::Confirmed
        ) {
            return Ok(ObservationProgress::Pending { confirmations: 0 });
        }
        let status = confirmation_status(&self.pool, record.tx_hash).await?;
        if !status.is_final(u64::from(self.plan.min_confirmations)) {
            return Ok(ObservationProgress::Pending {
                confirmations: status.confirmations,
            });
        }
        let block_height = match status.status {
            XmrTransactionStatus::InBlock { block_height } => block_height,
            _ => return Ok(ObservationProgress::Pending { confirmations: 0 }),
        };
        let block_hash = status.inclusion_block_hash.ok_or(PumpError::InvalidPlan)?;
        let confirmations =
            u32::try_from(status.confirmations).map_err(|_| PumpError::BoundsExceeded)?;
        let evidence = XmrSpendEvidenceV2 {
            settlement_id: self.plan.settlement_id,
            terms_hash: self.plan.terms_hash,
            spending_tx_hash: record.tx_hash,
            funding_tx_hash: self.plan.funding_tx_hash,
            block_height,
            block_hash,
            confirmations,
        };
        evidence
            .validate(
                &self.plan.settlement_id,
                &self.plan.terms_hash,
                &self.plan.funding_tx_hash,
                self.plan.min_confirmations,
            )
            .map_err(|_| PumpError::InvalidPlan)?;
        self.feed.insert_event(&VerifiedXmrEvent {
            settlement_id: self.plan.settlement_id,
            terms_hash: self.plan.terms_hash,
            kind: VerifiedXmrEventKind::Claim,
            evidence: kaystra_core::state::EvidenceRefV1 {
                chain_id: self.plan.chain_id,
                tx_id: evidence.spending_tx_hash,
                event_index: 0,
                block_height: evidence.block_height,
                block_anchor: evidence.block_hash,
            },
        })?;
        delivery.mark_confirmed(&self.plan.settlement_id)?;
        Ok(ObservationProgress::SpendFinal {
            evidence_id: evidence.evidence_id(),
        })
    }
}

fn observation_nonce(
    kind: &[u8],
    settlement_id: [u8; 32],
    transaction: [u8; 32],
    block_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-INTEROP/XMR-OBSERVATION-NONCE/V2\0");
    hasher.update(kind);
    hasher.update(settlement_id);
    hasher.update(transaction);
    hasher.update(block_hash);
    hasher.finalize().into()
}

fn map_feed_error(error: xmr_kaystra_source::VerifiedFeedError) -> PumpError {
    match error {
        xmr_kaystra_source::VerifiedFeedError::Unavailable => {
            PumpError::Store(ObservationStoreError::Unavailable)
        }
        xmr_kaystra_source::VerifiedFeedError::InvalidEvidence => {
            PumpError::Store(ObservationStoreError::Invalid)
        }
        xmr_kaystra_source::VerifiedFeedError::BoundsExceeded => PumpError::BoundsExceeded,
    }
}

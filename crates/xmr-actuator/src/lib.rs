//! Durable Monero sweep actuator for DOM interoperability.
//!
//! This crate owns no signing key, no wallet and no daemon credential. It
//! retains exact signed sweep bytes before any daemon sees them, submits
//! them byte-identically through the exact-broadcast port, promotes stages
//! only on verified inclusion at the profile's confirmation depth, and
//! records the one absence statement Monero offers a takeover — txid absent
//! with the sweep's own key image unspent. Every mutation is idempotent by
//! attempt id and fenced by epoch.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod model;
pub mod store;

pub use model::{
    Digest32, XmrActuatorErrorV1, XmrActuatorLeaseV1, XmrFinalityFactsV1, XmrOperationKindV1,
    XmrOperationLocatorV1, XmrOperationViewV1, XmrReconciliationKindV1, XmrTxStageV1,
};
pub use store::{custody_digest_v1, XmrOperationStoreV1, MAX_RAW_TX_BYTES_V1};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use store::{StageTransitionV1, MUTATION_BROADCAST, MUTATION_OBSERVE, MUTATION_RECONCILE};
use xmr_spend_port::{BroadcastAcceptance, ExactBroadcastPort};

/// Fail-closed actuator result.
pub type Result<T> = core::result::Result<T, XmrActuatorErrorV1>;

const FINAL_EVIDENCE_DOMAIN_V1: &[u8] = b"DOM-INTEROP/XMR-ACTUATOR/FINAL-EVIDENCE/V1\0";

/// One verified transaction inclusion reading at the observation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmrTxInclusionV1 {
    /// Height the transaction is included at.
    pub height: u64,
    /// Canonical block hash at that height.
    pub block_hash: Digest32,
    /// Confirmations at the reading, including the inclusion block.
    pub confirmations: u64,
}

/// Read-only Monero observation boundary consumed by the actuator.
///
/// Implementations are expected to answer from a quorum of independent
/// daemons, refusing (`ObservationUnavailable`) rather than answering from
/// one node's view. The actuator treats every answer as already verified.
pub trait XmrObservationPortV1 {
    /// Inclusion facts for an exact txid, `None` when absent everywhere.
    fn transaction_inclusion(&mut self, tx_hash: Digest32) -> Result<Option<XmrTxInclusionV1>>;

    /// Whether the exact key image is spent anywhere the quorum can see.
    fn key_image_spent(&mut self, key_image: Digest32) -> Result<bool>;
}

/// Outcome of one broadcast fan-out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmrBroadcastOutcomeV1 {
    /// Durable view after the attempt was recorded.
    pub view: XmrOperationViewV1,
    /// Whether at least one daemon accepted or already knew the bytes.
    pub accepted: bool,
}

/// Outcome of one takeover reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmrReconcileOutcomeV1 {
    /// Durable view after reconciliation (unchanged when `Unknown`).
    pub view: XmrOperationViewV1,
    /// What the evidence proved.
    pub kind: XmrReconciliationKindV1,
}

/// Durable Monero actuator: retained bytes, fenced mutations, verified depth.
#[derive(Debug)]
pub struct DurableXmrActuatorV1 {
    store: XmrOperationStoreV1,
}

const fn stage_rank(stage: XmrTxStageV1) -> u8 {
    match stage {
        XmrTxStageV1::Signed => 1,
        XmrTxStageV1::SendAttempted => 2,
        XmrTxStageV1::Observed => 3,
        XmrTxStageV1::Final => 4,
        XmrTxStageV1::Reconciled => 5,
        XmrTxStageV1::FinalityInvalidated => 6,
    }
}

fn final_evidence_digest_v1(tx_hash: Digest32, inclusion: &XmrTxInclusionV1) -> Result<Digest32> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    hasher.update(FINAL_EVIDENCE_DOMAIN_V1);
    for part in [
        tx_hash.as_slice(),
        &inclusion.height.to_be_bytes(),
        inclusion.block_hash.as_slice(),
        &inclusion.confirmations.to_be_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut out = [0; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    if out == [0; 32] {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    Ok(out)
}

impl DurableXmrActuatorV1 {
    /// Wraps an open durable store.
    pub const fn new(store: XmrOperationStoreV1) -> Self {
        Self { store }
    }

    /// Retains exact signed sweep bytes exactly once; idempotent on
    /// identical replay.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_signed(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        tx_hash: Digest32,
        key_image: Digest32,
        raw_transaction: &[u8],
        now_unix_ms: u64,
    ) -> Result<XmrOperationViewV1> {
        self.store.prepare_signed(
            lease,
            locator,
            tx_hash,
            key_image,
            raw_transaction,
            now_unix_ms,
        )
    }

    /// Current durable projection.
    pub fn view(&self, locator: XmrOperationLocatorV1) -> Result<XmrOperationViewV1> {
        self.store.view(locator)
    }

    /// The exact retained bytes, for byte-identical revalidation and
    /// retransmission only.
    pub fn retained(&self, locator: XmrOperationLocatorV1) -> Result<Vec<u8>> {
        self.store.retained_transaction(locator)
    }

    /// Submits the retained exact bytes through the exact-broadcast port.
    ///
    /// The durable stage moves to `SendAttempted` **before** the port sees a
    /// byte. `AlreadyKnown` counts as acceptance: the bytes are in a pool or
    /// chain somewhere, which is exactly what a retransmission wants.
    pub fn broadcast_current(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        port: &mut dyn ExactBroadcastPort,
        now_unix_ms: u64,
    ) -> Result<XmrBroadcastOutcomeV1> {
        let view = self.store.view(locator)?;
        match view.stage {
            XmrTxStageV1::Signed | XmrTxStageV1::SendAttempted => {}
            _ => return Err(XmrActuatorErrorV1::Conflict),
        }
        let raw = self.store.retained_transaction(locator)?;
        if custody_digest_v1(&raw)? != view.custody_digest {
            return Err(XmrActuatorErrorV1::Corrupt);
        }
        let view = self.store.apply_mutation(
            lease,
            locator,
            attempt_id,
            MUTATION_BROADCAST,
            now_unix_ms,
            |current| match current.stage {
                XmrTxStageV1::Signed | XmrTxStageV1::SendAttempted => Ok(StageTransitionV1 {
                    stage: XmrTxStageV1::SendAttempted,
                    finality: None,
                    reconciliation: None,
                }),
                _ => Err(XmrActuatorErrorV1::Conflict),
            },
        )?;
        let accepted = matches!(
            port.submit_exact(view.tx_hash, &raw),
            Ok(BroadcastAcceptance::Accepted) | Ok(BroadcastAcceptance::AlreadyKnown)
        );
        Ok(XmrBroadcastOutcomeV1 { view, accepted })
    }

    /// Promotes the stage from verified inclusion of the exact txid.
    pub fn observe_current(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        port: &mut dyn XmrObservationPortV1,
        min_confirmations: u64,
        now_unix_ms: u64,
    ) -> Result<XmrOperationViewV1> {
        if min_confirmations == 0 {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        let view = self.store.view(locator)?;
        let Some(inclusion) = port.transaction_inclusion(view.tx_hash)? else {
            return Ok(view);
        };
        if inclusion.block_hash == [0; 32] || inclusion.confirmations == 0 {
            return Err(XmrActuatorErrorV1::ObservationUnavailable);
        }
        if inclusion.confirmations >= min_confirmations {
            let facts = XmrFinalityFactsV1 {
                final_height: inclusion.height,
                final_block_hash: inclusion.block_hash,
                final_evidence_digest: final_evidence_digest_v1(view.tx_hash, &inclusion)?,
            };
            return self.promote_final(
                lease,
                locator,
                attempt_id,
                MUTATION_OBSERVE,
                facts,
                None,
                now_unix_ms,
            );
        }
        self.store.apply_mutation(
            lease,
            locator,
            attempt_id,
            MUTATION_OBSERVE,
            now_unix_ms,
            |current| {
                if stage_rank(current.stage) >= stage_rank(XmrTxStageV1::Observed) {
                    return Err(XmrActuatorErrorV1::Conflict);
                }
                Ok(StageTransitionV1 {
                    stage: XmrTxStageV1::Observed,
                    finality: None,
                    reconciliation: None,
                })
            },
        )
    }

    /// Reconciles an operation taken over after a crash, under a newer fence.
    ///
    /// Inclusion promotes exactly like observation. Absence is recorded as
    /// `KeyImageUnspentAbsent` only when the sweep's own key image is also
    /// unspent at the boundary — the strongest absence statement Monero
    /// offers, and a **point-in-time** one (the retained bytes stay valid):
    /// the caller decides what economic weight it carries, per
    /// `docs/interop/engine/CHILD_SOCKETS_DESIGN.md` §5. A spent key image
    /// with the txid absent is a conflicting spend and stays `Unknown`,
    /// written nowhere.
    pub fn reconcile_takeover(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        port: &mut dyn XmrObservationPortV1,
        min_confirmations: u64,
        now_unix_ms: u64,
    ) -> Result<XmrReconcileOutcomeV1> {
        if min_confirmations == 0 {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        let view = self.store.view(locator)?;
        match port.transaction_inclusion(view.tx_hash)? {
            Some(inclusion) if inclusion.confirmations >= min_confirmations => {
                let facts = XmrFinalityFactsV1 {
                    final_height: inclusion.height,
                    final_block_hash: inclusion.block_hash,
                    final_evidence_digest: final_evidence_digest_v1(view.tx_hash, &inclusion)?,
                };
                let view = self.promote_final(
                    lease,
                    locator,
                    attempt_id,
                    MUTATION_RECONCILE,
                    facts,
                    Some(XmrReconciliationKindV1::Final),
                    now_unix_ms,
                )?;
                Ok(XmrReconcileOutcomeV1 {
                    view,
                    kind: XmrReconciliationKindV1::Final,
                })
            }
            Some(_) => {
                let view = self.store.apply_mutation(
                    lease,
                    locator,
                    attempt_id,
                    MUTATION_RECONCILE,
                    now_unix_ms,
                    |current| {
                        if stage_rank(current.stage) > stage_rank(XmrTxStageV1::Observed) {
                            return Err(XmrActuatorErrorV1::Conflict);
                        }
                        Ok(StageTransitionV1 {
                            stage: XmrTxStageV1::Observed,
                            finality: None,
                            reconciliation: Some(XmrReconciliationKindV1::Observed),
                        })
                    },
                )?;
                Ok(XmrReconcileOutcomeV1 {
                    view,
                    kind: XmrReconciliationKindV1::Observed,
                })
            }
            None => {
                if port.key_image_spent(view.key_image)? {
                    // Conflicting spend of the shared output: nothing this
                    // authority can conclude or authorize.
                    return Ok(XmrReconcileOutcomeV1 {
                        view,
                        kind: XmrReconciliationKindV1::Unknown,
                    });
                }
                let view = self.store.apply_mutation(
                    lease,
                    locator,
                    attempt_id,
                    MUTATION_RECONCILE,
                    now_unix_ms,
                    |current| {
                        if stage_rank(current.stage) > stage_rank(XmrTxStageV1::SendAttempted) {
                            return Err(XmrActuatorErrorV1::Conflict);
                        }
                        Ok(StageTransitionV1 {
                            stage: XmrTxStageV1::Reconciled,
                            finality: None,
                            reconciliation: Some(XmrReconciliationKindV1::KeyImageUnspentAbsent),
                        })
                    },
                )?;
                Ok(XmrReconcileOutcomeV1 {
                    view,
                    kind: XmrReconciliationKindV1::KeyImageUnspentAbsent,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_final(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        mutation_kind: u8,
        facts: XmrFinalityFactsV1,
        reconciliation: Option<XmrReconciliationKindV1>,
        now_unix_ms: u64,
    ) -> Result<XmrOperationViewV1> {
        self.store.apply_mutation(
            lease,
            locator,
            attempt_id,
            mutation_kind,
            now_unix_ms,
            |current| {
                if let Some(existing) = current.finality {
                    if existing != facts {
                        return Err(XmrActuatorErrorV1::Conflict);
                    }
                }
                match current.stage {
                    XmrTxStageV1::FinalityInvalidated => Err(XmrActuatorErrorV1::Conflict),
                    _ => Ok(StageTransitionV1 {
                        stage: XmrTxStageV1::Final,
                        finality: Some(facts),
                        reconciliation,
                    }),
                }
            },
        )
    }
}

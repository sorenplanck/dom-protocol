//! Durable Solana operation actuator for DOM interoperability.
//!
//! This crate owns no signing key and no endpoint credential. It retains
//! exact signed bytes before any node sees them, fans broadcasts out to a
//! fixed RPC set, promotes stages only on quorum evidence, and turns legacy
//! blockhash expiry into the positive proof that retained bytes can never
//! land. Every mutation is idempotent by attempt id and fenced by epoch, so
//! a crashed owner and its successor converge on one durable outcome.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod model;
pub mod store;

pub use model::{
    Digest32, SolanaActuatorErrorV1, SolanaActuatorLeaseV1, SolanaFinalityFactsV1,
    SolanaOperationKindV1, SolanaOperationLocatorV1, SolanaOperationViewV1,
    SolanaReconciliationKindV1, SolanaTxStageV1,
};
pub use store::{custody_digest_v1, SolanaOperationStoreV1};

use solana_rpc::SolanaRpc;
use solana_rpc_pool::SolanaRpcPool;
use solana_types::{Commitment, SolanaHash, SolanaSignature};
use store::{StageTransitionV1, MUTATION_BROADCAST, MUTATION_OBSERVE, MUTATION_RECONCILE};

/// Fail-closed actuator result.
pub type Result<T> = core::result::Result<T, SolanaActuatorErrorV1>;

/// Maximum finalized block-height spread tolerated inside one quorum vote.
///
/// Wider than this and the "expired" proof would rest on nodes that do not
/// agree where the chain is.
pub const MAX_QUORUM_HEIGHT_SPREAD_V1: u64 = 64;

/// Outcome of one broadcast fan-out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastOutcomeV1 {
    /// Durable view after the attempt was recorded.
    pub view: SolanaOperationViewV1,
    /// Nodes that accepted the exact bytes and echoed the exact signature.
    pub accepted: usize,
    /// Nodes contacted.
    pub contacted: usize,
}

/// Outcome of one takeover reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileOutcomeV1 {
    /// Durable view after reconciliation (unchanged when `Unknown`).
    pub view: SolanaOperationViewV1,
    /// What the quorum evidence proved.
    pub kind: SolanaReconciliationKindV1,
}

/// Durable Solana actuator: retained bytes, fenced mutations, quorum promotion.
#[derive(Debug)]
pub struct DurableSolanaActuatorV1 {
    store: SolanaOperationStoreV1,
}

const fn stage_rank(stage: SolanaTxStageV1) -> u8 {
    match stage {
        SolanaTxStageV1::Signed => 1,
        SolanaTxStageV1::SendAttempted => 2,
        SolanaTxStageV1::Observed => 3,
        SolanaTxStageV1::Final => 4,
        SolanaTxStageV1::Reconciled => 5,
        SolanaTxStageV1::FinalityInvalidated => 6,
    }
}

impl DurableSolanaActuatorV1 {
    /// Wraps an open durable store.
    pub const fn new(store: SolanaOperationStoreV1) -> Self {
        Self { store }
    }

    /// Retains exact signed bytes exactly once; idempotent on identical replay.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_signed(
        &self,
        lease: &SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        signature: SolanaSignature,
        raw_transaction: &[u8],
        recent_blockhash: SolanaHash,
        last_valid_block_height: u64,
        now_unix_ms: u64,
    ) -> Result<SolanaOperationViewV1> {
        self.store.prepare_signed(
            lease,
            locator,
            signature,
            raw_transaction,
            recent_blockhash,
            last_valid_block_height,
            now_unix_ms,
        )
    }

    /// Current durable projection.
    pub fn view(&self, locator: SolanaOperationLocatorV1) -> Result<SolanaOperationViewV1> {
        self.store.view(locator)
    }

    /// The exact retained bytes, for byte-identical revalidation and
    /// retransmission only.
    pub fn retained(&self, locator: SolanaOperationLocatorV1) -> Result<Vec<u8>> {
        self.store.retained_transaction(locator)
    }

    /// Broadcasts the retained exact bytes to every configured node.
    ///
    /// The durable stage moves to `SendAttempted` **before** any node sees a
    /// byte: after a crash mid-send the row already admits the cluster may
    /// hold the transaction, so nothing double-spends its ambiguity. Only a
    /// node that echoes the retained signature counts as an accept.
    pub fn broadcast_current<R: SolanaRpc>(
        &self,
        lease: &SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        attempt_id: Digest32,
        pool: &SolanaRpcPool<R>,
        now_unix_ms: u64,
    ) -> Result<BroadcastOutcomeV1> {
        let view = self.store.view(locator)?;
        match view.stage {
            SolanaTxStageV1::Signed | SolanaTxStageV1::SendAttempted => {}
            _ => return Err(SolanaActuatorErrorV1::Conflict),
        }
        let raw = self.store.retained_transaction(locator)?;
        if custody_digest_v1(&raw)? != view.custody_digest {
            return Err(SolanaActuatorErrorV1::Corrupt);
        }
        let view = self.store.apply_mutation(
            lease,
            locator,
            attempt_id,
            MUTATION_BROADCAST,
            now_unix_ms,
            |current| match current.stage {
                SolanaTxStageV1::Signed | SolanaTxStageV1::SendAttempted => Ok(StageTransitionV1 {
                    stage: SolanaTxStageV1::SendAttempted,
                    finality: None,
                    reconciliation: None,
                }),
                _ => Err(SolanaActuatorErrorV1::Conflict),
            },
        )?;
        let mut accepted = 0usize;
        for node in pool.nodes() {
            if let Ok(echoed) = node.send_transaction(&raw) {
                if echoed == view.signature {
                    accepted += 1;
                }
            }
        }
        Ok(BroadcastOutcomeV1 {
            view,
            accepted,
            contacted: pool.nodes().len(),
        })
    }

    /// Promotes the stage from quorum observation of the exact signature.
    ///
    /// `Finalized` evidence is only accepted together with a quorum-agreed
    /// transaction record and block anchor, all naming the retained signature
    /// and blockhash; anything less promotes at most to `Observed`.
    pub fn observe_current<R: SolanaRpc>(
        &self,
        lease: &SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        attempt_id: Digest32,
        pool: &SolanaRpcPool<R>,
        now_unix_ms: u64,
    ) -> Result<SolanaOperationViewV1> {
        let view = self.store.view(locator)?;
        let Some(status) = pool
            .signature_status(view.signature)
            .map_err(|_| SolanaActuatorErrorV1::QuorumUnavailable)?
        else {
            return Ok(view);
        };
        if status.failed {
            return self.store.apply_mutation(
                lease,
                locator,
                attempt_id,
                MUTATION_OBSERVE,
                now_unix_ms,
                |current| {
                    // Publicity is monotone: a transaction that landed and
                    // failed still published its instruction data.
                    match current.stage {
                        SolanaTxStageV1::FinalityInvalidated => {
                            Err(SolanaActuatorErrorV1::Conflict)
                        }
                        _ => Ok(StageTransitionV1 {
                            stage: SolanaTxStageV1::FinalityInvalidated,
                            finality: None,
                            reconciliation: None,
                        }),
                    }
                },
            );
        }
        if status.confirmation == Commitment::Finalized {
            let facts = self.finality_facts(pool, &view)?;
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
                if stage_rank(current.stage) >= stage_rank(SolanaTxStageV1::Observed) {
                    return Err(SolanaActuatorErrorV1::Conflict);
                }
                Ok(StageTransitionV1 {
                    stage: SolanaTxStageV1::Observed,
                    finality: None,
                    reconciliation: None,
                })
            },
        )
    }

    /// Reconciles an operation taken over after a crash, under a newer fence.
    ///
    /// Evidence found promotes exactly like observation. Evidence absent is
    /// only conclusive once the retained blockhash has expired at the quorum
    /// floor — then, and only then, the bytes are proven never to have
    /// landed. Absence before expiry stays `Unknown` and writes nothing: it
    /// cannot authorize a retry.
    pub fn reconcile_takeover<R: SolanaRpc>(
        &self,
        lease: &SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        attempt_id: Digest32,
        pool: &SolanaRpcPool<R>,
        now_unix_ms: u64,
    ) -> Result<ReconcileOutcomeV1> {
        let view = self.store.view(locator)?;
        match pool
            .signature_status(view.signature)
            .map_err(|_| SolanaActuatorErrorV1::QuorumUnavailable)?
        {
            Some(status) if !status.failed && status.confirmation == Commitment::Finalized => {
                let facts = self.finality_facts(pool, &view)?;
                let view = self.promote_final(
                    lease,
                    locator,
                    attempt_id,
                    MUTATION_RECONCILE,
                    facts,
                    Some(SolanaReconciliationKindV1::Final),
                    now_unix_ms,
                )?;
                Ok(ReconcileOutcomeV1 {
                    view,
                    kind: SolanaReconciliationKindV1::Final,
                })
            }
            Some(status) if !status.failed => {
                let view = self.store.apply_mutation(
                    lease,
                    locator,
                    attempt_id,
                    MUTATION_RECONCILE,
                    now_unix_ms,
                    |current| {
                        if stage_rank(current.stage) > stage_rank(SolanaTxStageV1::Observed) {
                            return Err(SolanaActuatorErrorV1::Conflict);
                        }
                        Ok(StageTransitionV1 {
                            stage: SolanaTxStageV1::Observed,
                            finality: None,
                            reconciliation: Some(SolanaReconciliationKindV1::Observed),
                        })
                    },
                )?;
                Ok(ReconcileOutcomeV1 {
                    view,
                    kind: SolanaReconciliationKindV1::Observed,
                })
            }
            Some(_) => {
                // Landed and failed: same terminal statement as observation.
                let view = self.store.apply_mutation(
                    lease,
                    locator,
                    attempt_id,
                    MUTATION_RECONCILE,
                    now_unix_ms,
                    |current| match current.stage {
                        SolanaTxStageV1::FinalityInvalidated => {
                            Err(SolanaActuatorErrorV1::Conflict)
                        }
                        _ => Ok(StageTransitionV1 {
                            stage: SolanaTxStageV1::FinalityInvalidated,
                            finality: None,
                            reconciliation: None,
                        }),
                    },
                )?;
                Ok(ReconcileOutcomeV1 {
                    view,
                    kind: SolanaReconciliationKindV1::Unknown,
                })
            }
            None => {
                let floor = pool
                    .finalized_block_height_floor(MAX_QUORUM_HEIGHT_SPREAD_V1)
                    .map_err(|_| SolanaActuatorErrorV1::QuorumUnavailable)?;
                if floor <= view.last_valid_block_height {
                    // Still inside the blockhash window: absence is ambiguous.
                    return Ok(ReconcileOutcomeV1 {
                        view,
                        kind: SolanaReconciliationKindV1::Unknown,
                    });
                }
                let view = self.store.apply_mutation(
                    lease,
                    locator,
                    attempt_id,
                    MUTATION_RECONCILE,
                    now_unix_ms,
                    |current| {
                        if stage_rank(current.stage) > stage_rank(SolanaTxStageV1::SendAttempted) {
                            // Evidence already recorded beats a later absence.
                            return Err(SolanaActuatorErrorV1::Conflict);
                        }
                        Ok(StageTransitionV1 {
                            stage: SolanaTxStageV1::Reconciled,
                            finality: None,
                            reconciliation: Some(SolanaReconciliationKindV1::ExpiredNeverLanded),
                        })
                    },
                )?;
                Ok(ReconcileOutcomeV1 {
                    view,
                    kind: SolanaReconciliationKindV1::ExpiredNeverLanded,
                })
            }
        }
    }

    /// Quorum-verified finality facts for the retained signature.
    fn finality_facts<R: SolanaRpc>(
        &self,
        pool: &SolanaRpcPool<R>,
        view: &SolanaOperationViewV1,
    ) -> Result<SolanaFinalityFactsV1> {
        let record = pool
            .transaction(view.signature, Commitment::Finalized)
            .map_err(|_| SolanaActuatorErrorV1::QuorumUnavailable)?
            .ok_or(SolanaActuatorErrorV1::QuorumUnavailable)?;
        if record.signature != view.signature
            || record.recent_blockhash != view.recent_blockhash
            || !record.success
        {
            return Err(SolanaActuatorErrorV1::Corrupt);
        }
        let anchor = pool
            .block_anchor(record.slot)
            .map_err(|_| SolanaActuatorErrorV1::QuorumUnavailable)?;
        if anchor.slot != record.slot {
            return Err(SolanaActuatorErrorV1::Corrupt);
        }
        Ok(SolanaFinalityFactsV1 {
            final_slot: record.slot,
            final_blockhash: anchor.blockhash,
            final_evidence_digest: record.commitment_hash(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_final(
        &self,
        lease: &SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        attempt_id: Digest32,
        mutation_kind: u8,
        facts: SolanaFinalityFactsV1,
        reconciliation: Option<SolanaReconciliationKindV1>,
        now_unix_ms: u64,
    ) -> Result<SolanaOperationViewV1> {
        self.store.apply_mutation(
            lease,
            locator,
            attempt_id,
            mutation_kind,
            now_unix_ms,
            |current| {
                if let Some(existing) = current.finality {
                    // Finality facts are write-once.
                    if existing != facts {
                        return Err(SolanaActuatorErrorV1::Conflict);
                    }
                }
                match current.stage {
                    SolanaTxStageV1::FinalityInvalidated => Err(SolanaActuatorErrorV1::Conflict),
                    _ => Ok(StageTransitionV1 {
                        stage: SolanaTxStageV1::Final,
                        finality: Some(facts),
                        reconciliation,
                    }),
                }
            },
        )
    }
}

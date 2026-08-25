//! Merit privilege — INTENT_BOOK_DESIGN.md, "mérito, não capital".
//!
//! Two objective metrics, no curation:
//!
//! 1. phase-1 mean response time under the threshold (maintenance);
//! 2. minimum executed volume inside the window (entry and permanence).
//!
//! Both must hold; losing either loses the privilege, automatically and
//! reconquerably ("Cumpriu as duas, tem o privilégio; deixou de cumprir,
//! perde — automático e reconquistável").
//!
//! Design notes this module encodes literally:
//!
//! - **the entry ladder**: a newcomer has no phase-1 history, so the
//!   maintenance metric cannot yet judge it; executions from ANY phase
//!   count toward volume ("operações executadas contam de QUALQUER fase"),
//!   and once the volume floor is met the solver enters phase 1 and the
//!   response mean starts to apply for maintenance;
//! - **volume, not count** ("Mínimo em VOLUME, não em contagem"): the
//!   ledger records executed value, never a number of operations;
//! - **the bond is NOT the privilege criterion** ("O bond NÃO é o critério
//!   do privilégio"): nothing here reads a bond. Capital grants the right
//!   to quote (admissibility, `rfq`); performance grants priority.

use crate::config::MeritPolicyV1;
use kaystra_core::types::ParticipantId;
use std::collections::BTreeMap;

/// One recorded phase-1 response, in milliseconds from publication to the
/// arrival of that solver's quote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResponseSample {
    /// Elapsed milliseconds.
    pub millis: u64,
}

/// One executed settlement, provable by receipt (the design's
/// "execução é provável por recibo").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExecutionRecord {
    /// Executed value in the measurement asset's smallest unit.
    pub volume: u128,
    /// UNIX seconds at which the execution became durable.
    pub executed_at_seconds: u64,
}

/// Per-solver measured history. Public and auditable by construction: the
/// board publishes the rule and the statistics ("Medição publicada e
/// auditável"), so nothing here is hidden state.
#[derive(Clone, Default, Debug)]
pub struct SolverRecord {
    responses: Vec<ResponseSample>,
    executions: Vec<ExecutionRecord>,
}

impl SolverRecord {
    /// Record a phase-1 response time.
    pub fn record_response(&mut self, millis: u64) {
        self.responses.push(ResponseSample { millis });
    }

    /// Record an execution. Executions from ANY phase count.
    pub fn record_execution(&mut self, volume: u128, executed_at_seconds: u64) {
        self.executions.push(ExecutionRecord {
            volume,
            executed_at_seconds,
        });
    }

    /// Mean phase-1 response in milliseconds, or `None` when the solver has
    /// no phase-1 history yet (the entry-ladder case).
    pub fn mean_response_millis(&self) -> Option<u64> {
        if self.responses.is_empty() {
            return None;
        }
        let total: u128 = self.responses.iter().map(|s| s.millis as u128).sum();
        // Integer mean; the count is bounded by the samples actually taken.
        Some((total / self.responses.len() as u128) as u64)
    }

    /// Executed volume inside `[now - window, now]`.
    ///
    /// Saturating addition: a ledger overflow must not panic and must not
    /// wrap into a small number that silently revokes a privilege.
    pub fn volume_in_window(&self, now_seconds: u64, window_seconds: u64) -> u128 {
        let floor = now_seconds.saturating_sub(window_seconds);
        self.executions
            .iter()
            .filter(|record| record.executed_at_seconds >= floor)
            .fold(0u128, |acc, record| acc.saturating_add(record.volume))
    }
}

/// Why a solver does not hold the phase-1 privilege.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrivilegeRefusal {
    /// Executed volume inside the window is below the floor.
    VolumeBelowFloor,
    /// The phase-1 mean response is above the threshold.
    ResponseAboveThreshold,
}

/// The measured verdict for one solver, with the numbers that produced it.
///
/// Returning the inputs alongside the verdict is what makes the privilege
/// list verifiable rather than a black box.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrivilegeVerdict {
    /// Whether the solver is notified in phase 1.
    pub privileged: bool,
    /// The measured window volume.
    pub volume_in_window: u128,
    /// The measured mean response, absent for a solver with no phase-1
    /// history.
    pub mean_response_millis: Option<u64>,
    /// Why not, when not privileged.
    pub refusal: Option<PrivilegeRefusal>,
}

/// The auditable merit ledger.
#[derive(Clone, Debug)]
pub struct MeritLedger {
    policy: MeritPolicyV1,
    records: BTreeMap<ParticipantId, SolverRecord>,
}

impl MeritLedger {
    /// Build a ledger over an explicit operator policy.
    pub fn new(policy: MeritPolicyV1) -> Self {
        Self {
            policy,
            records: BTreeMap::new(),
        }
    }

    /// The policy in force, so a verifier can reproduce every verdict.
    pub fn policy(&self) -> MeritPolicyV1 {
        self.policy
    }

    /// Record a phase-1 response time for a solver.
    pub fn record_response(&mut self, solver: ParticipantId, millis: u64) {
        self.records
            .entry(solver)
            .or_default()
            .record_response(millis);
    }

    /// Record an executed settlement for a solver, from any phase.
    pub fn record_execution(
        &mut self,
        solver: ParticipantId,
        volume: u128,
        executed_at_seconds: u64,
    ) {
        self.records
            .entry(solver)
            .or_default()
            .record_execution(volume, executed_at_seconds);
    }

    /// Evaluate the privilege for one solver at `now_seconds`.
    ///
    /// Order of evaluation follows the entry ladder: volume is the entry
    /// gate, so it is checked first; the response mean is the maintenance
    /// gate and only applies once phase-1 history exists.
    pub fn verdict(&self, solver: &ParticipantId, now_seconds: u64) -> PrivilegeVerdict {
        let record = self.records.get(solver);
        let volume = record
            .map(|r| r.volume_in_window(now_seconds, self.policy.volume_window_seconds()))
            .unwrap_or(0);
        let mean = record.and_then(|r| r.mean_response_millis());

        if volume < self.policy.volume_floor() {
            return PrivilegeVerdict {
                privileged: false,
                volume_in_window: volume,
                mean_response_millis: mean,
                refusal: Some(PrivilegeRefusal::VolumeBelowFloor),
            };
        }
        if let Some(mean) = mean {
            if mean > self.policy.response_threshold_millis() {
                return PrivilegeVerdict {
                    privileged: false,
                    volume_in_window: volume,
                    mean_response_millis: Some(mean),
                    refusal: Some(PrivilegeRefusal::ResponseAboveThreshold),
                };
            }
        }
        PrivilegeVerdict {
            privileged: true,
            volume_in_window: volume,
            mean_response_millis: mean,
            refusal: None,
        }
    }

    /// The privileged set at `now_seconds`, in canonical participant order.
    pub fn privileged_at(&self, now_seconds: u64) -> Vec<ParticipantId> {
        self.records
            .keys()
            .filter(|solver| self.verdict(solver, now_seconds).privileged)
            .copied()
            .collect()
    }
}

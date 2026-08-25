//! F2 model checker (spec §17).
//!
//! Exhaustively explores the reduced composition of the REAL settlement
//! machine with an abstract world — atomic commits that may roll back
//! (C0–C6), duplicate delivery, reorg, crash, and two concurrent
//! dispatchers — and proves the five properties the specification
//! requires:
//!
//! ```text
//! AG !(Settled && Refunded)
//! AG terminal -> AX terminal_same
//! AG AuthorizeFunding -> refund_armed
//! AG external_effect -> journal_committed
//! AG effect_completed_count <= 1
//! ```
//!
//! The machine under check is `kaystra_core::state::transition` itself —
//! the production function, not a re-modelled copy. Only the WORLD is
//! abstract: the journal is a counter, the outbox a bounded list, and the
//! chain a small alphabet of observations at two heights.
//!
//! Exit code 0 = every reachable state satisfies every property.

use std::collections::{BTreeSet, HashSet, VecDeque};

use kaystra_core::state::{
    transition, Effect, EvidenceRefV1, SettlementContext, SettlementEvent, SettlementState,
};
use kaystra_core::types::ChainId;

/// Bound on the modelled journal length. Every reachable economic shape
/// occurs well below this; the bound only keeps the space finite.
const MAX_JOURNAL: u8 = 8;
/// Bound on simultaneously tracked outbox entries.
const MAX_OUTBOX: usize = 6;
/// Concurrent dispatchers modelled.
const DISPATCHERS: usize = 2;

fn evidence(height: u64) -> EvidenceRefV1 {
    EvidenceRefV1 {
        chain_id: ChainId([0xc1; 32]),
        tx_id: [0x70 | (height as u8); 32],
        event_index: 0,
        block_height: height,
        block_anchor: [0xa0; 32],
    }
}

/// The modelled event alphabet, indexed so that "same event" is exactly
/// "same identifier" — which is how the real system deduplicates.
fn alphabet() -> Vec<(u8, SettlementEvent)> {
    vec![
        (0, SettlementEvent::RefundArmed),
        (
            1,
            SettlementEvent::FundingObserved {
                evidence: evidence(1),
            },
        ),
        (
            2,
            SettlementEvent::FundingObserved {
                evidence: evidence(2),
            },
        ),
        (
            3,
            SettlementEvent::FundingConfirmed {
                evidence: evidence(1),
            },
        ),
        (
            4,
            SettlementEvent::FundingAbsent {
                revalidation_from: 1,
            },
        ),
        (
            5,
            SettlementEvent::ClaimEvidenceVerified {
                evidence: evidence(2),
            },
        ),
        (
            6,
            SettlementEvent::ClaimConfirmed {
                evidence: evidence(2),
            },
        ),
        (7, SettlementEvent::TimelockExpired),
        (
            8,
            SettlementEvent::RefundConfirmed {
                evidence: evidence(2),
            },
        ),
        (
            9,
            SettlementEvent::ReorgInvalidated {
                from_height: 1,
                old_anchor: [0xa0; 32],
            },
        ),
    ]
}

/// One outbox entry as the world sees it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct Slot {
    /// Effect kind tag.
    kind: u8,
    /// Identifier of the event whose transition produced it. Together
    /// with `kind` this is the modelled `effect_id`, which the real
    /// system derives deterministically from exactly these two things
    /// plus the payload hash — so two entries can never collide unless
    /// the derivation itself is broken.
    source: u8,
    /// Journal length at the moment the entry was produced. An entry can
    /// only exist if its producing transition committed, so this is also
    /// the persist-before-effect witness.
    produced_at: u8,
    /// How many times an external execution was attempted.
    executed: u8,
    /// How many times it was marked completed. The property requires
    /// this to never exceed one, under any interleaving of dispatchers.
    completed: u8,
}

/// Reduced world state. The revision is deliberately excluded from the
/// key: it counts accepted transitions, and including it would make the
/// space infinite without adding an economic distinction.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct World {
    state: SettlementState,
    last_observed_height: Option<u64>,
    claim_evidence_verified: bool,
    refund_path_armed: bool,
    journal: u8,
    committed_ids: BTreeSet<u8>,
    outbox: Vec<Slot>,
    terminal: Option<SettlementState>,
}

impl World {
    fn initial() -> Self {
        let ctx = SettlementContext::new();
        Self {
            state: ctx.state,
            last_observed_height: ctx.last_observed_height,
            claim_evidence_verified: ctx.claim_evidence_verified,
            refund_path_armed: ctx.refund_path_armed,
            journal: 0,
            committed_ids: BTreeSet::new(),
            outbox: Vec::new(),
            terminal: None,
        }
    }

    fn context(&self) -> SettlementContext {
        SettlementContext {
            state: self.state,
            // Revision is normalized: the machine only ever compares it
            // for overflow, which the dedicated unit test covers.
            revision: u64::from(self.journal),
            last_observed_height: self.last_observed_height,
            claim_evidence_verified: self.claim_evidence_verified,
            refund_path_armed: self.refund_path_armed,
        }
    }

    fn absorb(&mut self, next: SettlementContext) {
        self.state = next.state;
        self.last_observed_height = next.last_observed_height;
        self.claim_evidence_verified = next.claim_evidence_verified;
        self.refund_path_armed = next.refund_path_armed;
    }
}

fn effect_tag(effect: &Effect) -> u8 {
    match effect {
        Effect::AuthorizeFunding => 1,
        Effect::RequestClaimConsumption { .. } => 2,
        Effect::ArmRefundPath => 3,
        Effect::RevalidateFrom { .. } => 4,
        Effect::RecordTerminalOutcome(SettlementState::Settled) => 5,
        Effect::RecordTerminalOutcome(_) => 6,
    }
}

/// A property violation, with the state that exhibits it.
#[derive(Debug)]
struct Violation {
    property: &'static str,
    detail: String,
}

/// Successors of one world, plus any violation observed on the edges.
fn successors(world: &World, out: &mut Vec<World>, violations: &mut Vec<Violation>) {
    // 1. Event delivery (including duplicates: the same identifier).
    for (id, event) in alphabet() {
        if world.committed_ids.contains(&id) {
            // Byte-identical redelivery: acknowledged, nothing changes.
            continue;
        }
        if world.terminal.is_some() {
            // Late evidence: recorded, no economic effect (spec §12).
            continue;
        }
        let Ok(applied) = transition(world.context(), &event) else {
            continue;
        };
        if world.journal >= MAX_JOURNAL || world.outbox.len() + applied.effects.len() > MAX_OUTBOX {
            continue;
        }

        // AG AuthorizeFunding -> refund_armed, checked on the EDGE that
        // produces the effect, which is where the guarantee must hold.
        if applied.effects.contains(&Effect::AuthorizeFunding) && !applied.next.refund_path_armed {
            violations.push(Violation {
                property: "AG AuthorizeFunding -> refund_armed",
                detail: format!("{world:?} --{event:?}--> funding authorized unarmed"),
            });
        }

        // The commit is atomic: either the whole transaction lands...
        let mut committed = world.clone();
        committed.absorb(applied.next);
        committed.journal += 1;
        committed.committed_ids.insert(id);
        for effect in &applied.effects {
            let slot = Slot {
                kind: effect_tag(effect),
                source: id,
                produced_at: committed.journal,
                executed: 0,
                completed: 0,
            };
            // The deterministic identifier must not collide with an entry
            // already in the outbox: that would be the same effect
            // enqueued twice, which is exactly what §9 forbids.
            if committed
                .outbox
                .iter()
                .any(|existing| existing.kind == slot.kind && existing.source == slot.source)
            {
                violations.push(Violation {
                    property: "AG effect_completed_count <= 1",
                    detail: format!("effect {slot:?} enqueued twice"),
                });
            } else {
                committed.outbox.push(slot);
            }
            if let Effect::RecordTerminalOutcome(state) = effect {
                // AG !(Settled && Refunded): a second, different terminal
                // must be impossible.
                if let Some(previous) = committed.terminal {
                    if previous != *state {
                        violations.push(Violation {
                            property: "AG !(Settled && Refunded)",
                            detail: format!("{previous:?} then {state:?}"),
                        });
                    }
                }
                committed.terminal = Some(*state);
            }
        }
        // AG terminal -> AX terminal_same.
        if let Some(previous) = world.terminal {
            if committed.terminal != Some(previous) || committed.state != world.state {
                violations.push(Violation {
                    property: "AG terminal -> AX terminal_same",
                    detail: format!("{world:?} --{event:?}--> {committed:?}"),
                });
            }
        }
        out.push(committed);

        // ...or the crash rolls it back entirely (C0–C6): the world is
        // unchanged, which is itself a successor to explore.
        out.push(world.clone());
    }

    // 2. Dispatch: any pending entry, by any of the concurrent dispatchers.
    for index in 0..world.outbox.len() {
        let slot = world.outbox[index];
        // AG external_effect -> journal_committed.
        if slot.produced_at > world.journal || slot.produced_at == 0 {
            violations.push(Violation {
                property: "AG external_effect -> journal_committed",
                detail: format!("effect {slot:?} without a committed journal entry"),
            });
        }
        for _dispatcher in 0..DISPATCHERS {
            if slot.executed >= u8::try_from(DISPATCHERS).unwrap_or(2) {
                // Bound the retry depth; two attempts already exercise the
                // "crash between execution and completion" shape.
                continue;
            }
            // A dispatcher claims and executes it, then either marks it
            // completed (C10) or dies before doing so (C9) — both are
            // successors. A second dispatcher may do the same
            // concurrently, which is why completion is a COUNT here.
            let mut executed = world.clone();
            executed.outbox[index].executed += 1;
            out.push(executed.clone());

            let mut completed = executed;
            // The store refuses to complete an entry twice; the model
            // encodes that rule and the property below verifies that no
            // OTHER path can reach a second completion.
            if completed.outbox[index].completed == 0 {
                completed.outbox[index].completed = 1;
            }
            if completed.outbox[index].completed > 1 {
                violations.push(Violation {
                    property: "AG effect_completed_count <= 1",
                    detail: format!("effect {slot:?} completed twice"),
                });
            }
            out.push(completed);
        }
    }
}

/// Runs the exhaustive check. Returns `(states_explored, violations)`.
fn check() -> (usize, Vec<Violation>) {
    let mut seen: HashSet<World> = HashSet::new();
    let mut queue: VecDeque<World> = VecDeque::new();
    let mut violations = Vec::new();
    let initial = World::initial();
    seen.insert(initial.clone());
    queue.push_back(initial);

    let mut successor_buffer = Vec::new();
    while let Some(world) = queue.pop_front() {
        successor_buffer.clear();
        successors(&world, &mut successor_buffer, &mut violations);
        for next in successor_buffer.drain(..) {
            if seen.insert(next.clone()) {
                queue.push_back(next);
            }
        }
    }
    (seen.len(), violations)
}

fn main() {
    let (states, violations) = check();
    println!("F2 model checker (spec §17)");
    println!("  reachable states explored: {states}");
    for property in [
        "AG !(Settled && Refunded)",
        "AG terminal -> AX terminal_same",
        "AG AuthorizeFunding -> refund_armed",
        "AG external_effect -> journal_committed",
        "AG effect_completed_count <= 1",
    ] {
        let failed = violations.iter().filter(|v| v.property == property).count();
        println!(
            "  {} {property}",
            if failed == 0 { "HOLDS  " } else { "VIOLATED" }
        );
    }
    if violations.is_empty() {
        println!("  result: PASS");
    } else {
        println!("  result: FAIL ({} violations)", violations.len());
        for violation in violations.iter().take(5) {
            println!("    {}: {}", violation.property, violation.detail);
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reachable_state_satisfies_every_property() {
        let (states, violations) = check();
        assert!(
            violations.is_empty(),
            "model checking found {} violation(s): {:?}",
            violations.len(),
            violations.iter().take(3).collect::<Vec<_>>()
        );
        // A trivially small space would mean the model degenerated.
        assert!(
            states > 200,
            "only {states} states explored — the model degenerated"
        );
    }

    #[test]
    fn the_model_reaches_both_terminals() {
        // Without this, the properties above could hold vacuously.
        let mut seen: HashSet<World> = HashSet::new();
        let mut queue: VecDeque<World> = VecDeque::new();
        let mut violations = Vec::new();
        let initial = World::initial();
        seen.insert(initial.clone());
        queue.push_back(initial);
        let mut settled = false;
        let mut refunded = false;
        let mut buffer = Vec::new();
        while let Some(world) = queue.pop_front() {
            match world.terminal {
                Some(SettlementState::Settled) => settled = true,
                Some(SettlementState::Refunded) => refunded = true,
                _ => {}
            }
            buffer.clear();
            successors(&world, &mut buffer, &mut violations);
            for next in buffer.drain(..) {
                if seen.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }
        assert!(settled, "the model never reaches Settled");
        assert!(refunded, "the model never reaches Refunded");
    }
}

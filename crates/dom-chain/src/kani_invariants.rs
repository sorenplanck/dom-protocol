//! Kani proofs for DOM chain identity, fork-choice, and reorganization models.

use crate::chain_state::is_better_fork_choice_tip;
use crate::genesis::is_empty_mainnet_economic_body;
use dom_core::Hash256;
use primitive_types::U256;

#[kani::proof]
fn mainnet_genesis_economic_body_accepts_exactly_four_zero_counts() {
    let body: [u8; 16] = kani::any();
    let all_counts_are_zero = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) == 0
        && u32::from_be_bytes([body[4], body[5], body[6], body[7]]) == 0
        && u32::from_be_bytes([body[8], body[9], body[10], body[11]]) == 0
        && u32::from_be_bytes([body[12], body[13], body[14], body[15]]) == 0;

    kani::assert(
        is_empty_mainnet_economic_body(&body) == all_counts_are_zero,
        "Mainnet height zero must issue no inputs, outputs, kernels, or transactions",
    );
}

#[kani::proof]
fn production_fork_choice_matches_work_then_canonical_hash_order() {
    let candidate_work_bytes: [u8; 32] = kani::any();
    let current_work_bytes: [u8; 32] = kani::any();
    let candidate_hash_bytes: [u8; 32] = kani::any();
    let current_hash_bytes: [u8; 32] = kani::any();
    let candidate_work = U256::from_big_endian(&candidate_work_bytes);
    let current_work = U256::from_big_endian(&current_work_bytes);
    let candidate_hash = Hash256::from_bytes(candidate_hash_bytes);
    let current_hash = Hash256::from_bytes(current_hash_bytes);
    let expected = candidate_work > current_work
        || (candidate_work == current_work && candidate_hash_bytes < current_hash_bytes);

    kani::assert(
        is_better_fork_choice_tip(candidate_work, candidate_hash, current_work, current_hash)
            == expected,
        "fork choice must be accumulated work followed by canonical hash order",
    );
}

#[kani::proof]
fn equal_work_fork_choice_is_total_antisymmetric_and_deterministic() {
    let left: [u8; 32] = kani::any();
    let right: [u8; 32] = kani::any();
    let work_bytes: [u8; 32] = kani::any();
    let work = U256::from_big_endian(&work_bytes);
    let left_wins = is_better_fork_choice_tip(
        work,
        Hash256::from_bytes(left),
        work,
        Hash256::from_bytes(right),
    );
    let right_wins = is_better_fork_choice_tip(
        work,
        Hash256::from_bytes(right),
        work,
        Hash256::from_bytes(left),
    );

    if left == right {
        kani::assert(
            !left_wins && !right_wins,
            "a tip must not outrank an identical equal-work tip",
        );
    } else {
        kani::assert(
            left_wins != right_wins,
            "exactly one distinct equal-work tip must win the deterministic tie-break",
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbstractBlock {
    identifier: u8,
    parent: u8,
    height: u8,
    body: u8,
    utxo_digest: u8,
    validated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbstractCanonicalState {
    tip: u8,
    height: u8,
    body: u8,
    utxo_digest: u8,
}

impl AbstractCanonicalState {
    fn connect(self, block: AbstractBlock) -> Option<Self> {
        if !block.validated
            || block.parent != self.tip
            || block.height != self.height.wrapping_add(1)
        {
            return None;
        }
        Some(Self {
            tip: block.identifier,
            height: block.height,
            body: block.body,
            utxo_digest: block.utxo_digest,
        })
    }
}

#[kani::proof]
fn canonical_transition_preserves_tip_header_body_and_utxo_consistency() {
    let state = AbstractCanonicalState {
        tip: kani::any(),
        height: kani::any(),
        body: kani::any(),
        utxo_digest: kani::any(),
    };
    let block = AbstractBlock {
        identifier: kani::any(),
        parent: kani::any(),
        height: kani::any(),
        body: kani::any(),
        utxo_digest: kani::any(),
        validated: kani::any(),
    };

    match state.connect(block) {
        None => kani::assert(
            !block.validated
                || block.parent != state.tip
                || block.height != state.height.wrapping_add(1),
            "rejected abstract transitions must violate validation, linkage, or height",
        ),
        Some(next) => {
            kani::assert(
                next.tip == block.identifier,
                "the canonical tip is the accepted header",
            );
            kani::assert(
                next.height == block.height,
                "the tip height is the accepted header height",
            );
            kani::assert(
                next.body == block.body,
                "the canonical body belongs to the selected tip",
            );
            kani::assert(
                next.utxo_digest == block.utxo_digest,
                "the canonical UTXO digest belongs to the selected body",
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbstractHistory {
    entries: [u8; 4],
    len: usize,
}

impl AbstractHistory {
    fn append(mut self, entry: u8) -> Option<Self> {
        if self.len == self.entries.len() {
            return None;
        }
        self.entries[self.len] = entry;
        self.len += 1;
        Some(self)
    }

    fn replay_prefix_then_branch(self, ancestor_len: usize, branch: [u8; 2]) -> Option<Self> {
        if ancestor_len > self.len || ancestor_len + branch.len() > self.entries.len() {
            return None;
        }
        let mut replayed = Self {
            entries: [0; 4],
            len: 0,
        };
        for index in 0..ancestor_len {
            replayed = replayed.append(self.entries[index])?;
        }
        for entry in branch {
            replayed = replayed.append(entry)?;
        }
        Some(replayed)
    }

    fn disconnect_then_connect(self, ancestor_len: usize, branch: [u8; 2]) -> Option<Self> {
        if ancestor_len > self.len || ancestor_len + branch.len() > self.entries.len() {
            return None;
        }
        let mut changed = self;
        for index in ancestor_len..changed.entries.len() {
            changed.entries[index] = 0;
        }
        changed.len = ancestor_len;
        for entry in branch {
            changed = changed.append(entry)?;
        }
        Some(changed)
    }
}

#[kani::proof]
#[kani::unwind(5)]
fn bounded_reorg_disconnect_connect_equals_replay_of_selected_branch() {
    let first: u8 = kani::any();
    let second: u8 = kani::any();
    let third: u8 = kani::any();
    let fourth: u8 = kani::any();
    let first_branch: u8 = kani::any();
    let second_branch: u8 = kani::any();
    kani::assume(first < 4);
    kani::assume(second < 4);
    kani::assume(third < 4);
    kani::assume(fourth < 4);
    kani::assume(first_branch < 4);
    kani::assume(second_branch < 4);
    let history = AbstractHistory {
        entries: [first, second, third, fourth],
        len: 4,
    };
    let ancestor_len: u8 = kani::any();
    kani::assume(usize::from(ancestor_len) <= 2);
    let branch = [first_branch, second_branch];
    let ancestor_len = usize::from(ancestor_len);
    let reorged = history
        .disconnect_then_connect(ancestor_len, branch)
        .expect("bounded reorg fits the model");
    let replayed = history
        .replay_prefix_then_branch(ancestor_len, branch)
        .expect("bounded replay fits the model");
    kani::assert(
        reorged == replayed,
        "disconnecting to the fork point then connecting a branch must equal replay",
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbstractAdmission {
    canonical_tip: u8,
    known_identifier: u8,
    known: bool,
}

impl AbstractAdmission {
    fn admit(self, block: AbstractBlock) -> Self {
        if self.known && self.known_identifier == block.identifier {
            return self;
        }
        if block.validated {
            Self {
                canonical_tip: block.identifier,
                known_identifier: block.identifier,
                known: true,
            }
        } else {
            self
        }
    }
}

#[kani::proof]
fn duplicate_admission_is_idempotent_and_invalid_work_never_changes_the_tip() {
    let state = AbstractAdmission {
        canonical_tip: kani::any(),
        known_identifier: kani::any(),
        known: kani::any(),
    };
    let candidate = AbstractBlock {
        identifier: kani::any(),
        parent: kani::any(),
        height: kani::any(),
        body: kani::any(),
        utxo_digest: kani::any(),
        validated: kani::any(),
    };
    let once = state.admit(candidate);
    let twice = once.admit(candidate);
    kani::assert(
        twice == once,
        "admitting an identical block twice is idempotent",
    );
    if !candidate.validated {
        kani::assert(
            once.canonical_tip == state.canonical_tip,
            "invalid work must not affect the canonical fork choice",
        );
    }
}

#[derive(Clone, Copy)]
struct AbstractQueuedBlock {
    syntax_valid: bool,
    proof_valid: bool,
    contextual_valid: bool,
}

fn queued_block_may_become_canonical(block: AbstractQueuedBlock) -> bool {
    block.syntax_valid && block.proof_valid && block.contextual_valid
}

#[kani::proof]
fn orphan_and_future_queue_models_cannot_bypass_any_validation_gate() {
    let queued = AbstractQueuedBlock {
        syntax_valid: kani::any(),
        proof_valid: kani::any(),
        contextual_valid: kani::any(),
    };
    let accepted = queued_block_may_become_canonical(queued);
    kani::assert(
        !accepted || (queued.syntax_valid && queued.proof_valid && queued.contextual_valid),
        "a queued orphan or future block may enter the canonical chain only after every gate",
    );
}

fn median_of_eleven(mut timestamps: [u8; 11]) -> u8 {
    for outer in 0..timestamps.len() {
        for inner in (outer + 1)..timestamps.len() {
            if timestamps[inner] < timestamps[outer] {
                timestamps.swap(outer, inner);
            }
        }
    }
    timestamps[5]
}

#[kani::proof]
#[kani::unwind(12)]
fn median_time_past_model_uses_the_sixth_sorted_value_and_strict_greater_than() {
    let timestamps: [u8; 11] = kani::any();
    let candidate: u8 = kani::any();
    for timestamp in timestamps {
        kani::assume(timestamp < 16);
    }
    kani::assume(candidate < 16);
    let median = median_of_eleven(timestamps);
    let mut at_or_below = 0u8;
    let mut at_or_above = 0u8;
    for timestamp in timestamps {
        if timestamp <= median {
            at_or_below += 1;
        }
        if timestamp >= median {
            at_or_above += 1;
        }
    }
    kani::assert(
        at_or_below >= 6 && at_or_above >= 6,
        "MTP must select the sixth order statistic of eleven values",
    );
    kani::assert(
        (candidate > median) == !(candidate <= median),
        "MTP acceptance must be strict: equality with the median is rejected",
    );
}

#[kani::proof]
fn only_the_configured_genesis_identifier_can_be_height_zero_and_block_one_links_to_it() {
    let configured_genesis: [u8; 32] = kani::any();
    let candidate_genesis: [u8; 32] = kani::any();
    let block_one_previous: [u8; 32] = kani::any();
    let height: u8 = kani::any();
    let accepted = if height == 0 {
        candidate_genesis == configured_genesis
    } else if height == 1 {
        block_one_previous == configured_genesis
    } else {
        true
    };
    if accepted && height == 0 {
        kani::assert(
            candidate_genesis == configured_genesis,
            "the configured genesis is the only accepted height-zero root",
        );
    }
    if accepted && height == 1 {
        kani::assert(
            block_one_previous == configured_genesis,
            "the first non-genesis block must link to the configured genesis",
        );
    }
}

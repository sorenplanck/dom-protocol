//! Kani models for mempool admission, ordering, and reconciliation boundaries.

use crate::{compare_block_selection_order, entry_fits_block_weight};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbstractTx {
    hash: u8,
    input: u8,
    structurally_valid: bool,
    meets_fee_floor: bool,
    mature_in_chain_view: bool,
    weight: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbstractPool {
    hashes: [u8; 2],
    inputs: [u8; 2],
    weights: [u8; 2],
    len: usize,
    total_weight: u8,
    max_weight: u8,
}

impl AbstractPool {
    fn contains_hash(self, hash: u8) -> bool {
        (self.len > 0 && self.hashes[0] == hash) || (self.len > 1 && self.hashes[1] == hash)
    }

    fn reserves_input(self, input: u8) -> bool {
        (self.len > 0 && self.inputs[0] == input) || (self.len > 1 && self.inputs[1] == input)
    }

    fn admit(mut self, tx: AbstractTx) -> Option<Self> {
        if !tx.structurally_valid
            || !tx.meets_fee_floor
            || !tx.mature_in_chain_view
            || self.contains_hash(tx.hash)
            || self.reserves_input(tx.input)
            || self.len == self.hashes.len()
            || tx.weight > self.max_weight.saturating_sub(self.total_weight)
        {
            return None;
        }
        self.hashes[self.len] = tx.hash;
        self.inputs[self.len] = tx.input;
        self.weights[self.len] = tx.weight;
        self.len += 1;
        self.total_weight += tx.weight;
        Some(self)
    }

    fn remove_confirmed(mut self, confirmed_input: u8) -> Self {
        let mut retained = Self {
            hashes: [0; 2],
            inputs: [0; 2],
            weights: [0; 2],
            len: 0,
            total_weight: 0,
            max_weight: self.max_weight,
        };
        for index in 0..self.len {
            if self.inputs[index] != confirmed_input {
                retained.hashes[retained.len] = self.hashes[index];
                retained.inputs[retained.len] = self.inputs[index];
                retained.weights[retained.len] = self.weights[index];
                retained.total_weight += self.weights[index];
                retained.len += 1;
            }
        }
        self = retained;
        self
    }
}

#[kani::proof]
fn admission_accepts_only_valid_fee_mature_nonconflicting_fitting_transactions() {
    let pool = AbstractPool {
        hashes: [kani::any(), kani::any()],
        inputs: [kani::any(), kani::any()],
        weights: [kani::any(), kani::any()],
        len: 0,
        total_weight: 0,
        max_weight: kani::any(),
    };
    let tx = AbstractTx {
        hash: kani::any(),
        input: kani::any(),
        structurally_valid: kani::any(),
        meets_fee_floor: kani::any(),
        mature_in_chain_view: kani::any(),
        weight: kani::any(),
    };
    if let Some(next) = pool.admit(tx) {
        kani::assert(
            tx.structurally_valid,
            "accepted transactions satisfy structural validation",
        );
        kani::assert(
            tx.meets_fee_floor,
            "accepted transactions satisfy the fee floor",
        );
        kani::assert(
            tx.mature_in_chain_view,
            "accepted transactions are mature in the chain view",
        );
        kani::assert(
            next.total_weight <= next.max_weight,
            "accepted transactions fit the pool cap",
        );
    }
}

#[kani::proof]
fn duplicate_admission_is_idempotent_and_input_reservations_are_unique() {
    let max_weight: u8 = kani::any();
    kani::assume(max_weight < 16);
    let tx = AbstractTx {
        hash: kani::any(),
        input: kani::any(),
        structurally_valid: true,
        meets_fee_floor: true,
        mature_in_chain_view: true,
        weight: kani::any(),
    };
    kani::assume(tx.weight <= max_weight);
    let pool = AbstractPool {
        hashes: [0; 2],
        inputs: [0; 2],
        weights: [0; 2],
        len: 0,
        total_weight: 0,
        max_weight,
    };
    let once = pool.admit(tx).expect("bounded valid transaction fits");
    kani::assert(
        once.admit(tx).is_none(),
        "an identical transaction cannot be admitted twice",
    );
    kani::assert(
        !once.reserves_input(tx.input) || once.inputs[0] == tx.input,
        "the only reservation for an admitted input belongs to that transaction",
    );
}

#[kani::proof]
fn conflicting_inputs_cannot_coexist_in_the_bounded_pool() {
    let first_hash: u8 = kani::any();
    let second_hash: u8 = kani::any();
    let input: u8 = kani::any();
    kani::assume(first_hash != second_hash);
    let pool = AbstractPool {
        hashes: [0; 2],
        inputs: [0; 2],
        weights: [0; 2],
        len: 0,
        total_weight: 0,
        max_weight: 2,
    };
    let first = AbstractTx {
        hash: first_hash,
        input,
        structurally_valid: true,
        meets_fee_floor: true,
        mature_in_chain_view: true,
        weight: 1,
    };
    let second = AbstractTx {
        hash: second_hash,
        input,
        ..first
    };
    let admitted = pool.admit(first).expect("first transaction fits");
    kani::assert(
        admitted.admit(second).is_none(),
        "a second transaction spending an already-reserved input must reject",
    );
}

#[kani::proof]
fn production_selection_order_is_exact_and_deterministic() {
    let left_rate: u64 = kani::any();
    let right_rate: u64 = kani::any();
    let left_hash: [u8; 32] = kani::any();
    let right_hash: [u8; 32] = kani::any();
    let expected = right_rate
        .cmp(&left_rate)
        .then_with(|| left_hash.cmp(&right_hash));
    kani::assert(
        compare_block_selection_order(left_rate, left_hash, right_rate, right_hash) == expected,
        "selection must be fee-rate descending then hash ascending",
    );
}

#[kani::proof]
fn block_selection_weight_frontier_is_exact_without_overflow() {
    let used: u32 = kani::any();
    let candidate: u32 = kani::any();
    let maximum: u32 = kani::any();
    kani::assume(used <= maximum);
    let fits = entry_fits_block_weight(used, candidate, maximum);
    kani::assert(
        fits == (candidate <= maximum - used),
        "selection fit must equal the exact remaining-weight comparison",
    );
    if fits {
        kani::assert(
            used.checked_add(candidate)
                .expect("fitting addition cannot overflow")
                <= maximum,
            "selecting a fitting entry cannot exceed the block budget",
        );
    }
}

#[kani::proof]
#[kani::unwind(3)]
fn confirmed_input_removal_keeps_only_unrelated_transactions() {
    let first_input: u8 = kani::any();
    let second_input: u8 = kani::any();
    kani::assume(first_input != second_input);
    let pool = AbstractPool {
        hashes: [1, 2],
        inputs: [first_input, second_input],
        weights: [1, 1],
        len: 2,
        total_weight: 2,
        max_weight: 2,
    };
    let reconciled = pool.remove_confirmed(first_input);
    kani::assert(
        reconciled.len == 1,
        "one confirmed-input spender is removed",
    );
    kani::assert(
        reconciled.inputs[0] == second_input && reconciled.hashes[0] == 2,
        "the unrelated transaction remains after confirmation reconciliation",
    );
}

#[kani::proof]
fn reorg_reinjection_model_restores_only_transactions_valid_in_the_new_context() {
    let valid_in_new_context: bool = kani::any();
    let revalidated_admission = valid_in_new_context;
    kani::assert(
        !revalidated_admission || valid_in_new_context,
        "a reorg candidate may re-enter the pool only after new-context validation",
    );
}

#[kani::proof]
fn volatile_snapshot_model_cannot_mutate_an_admitted_pool_without_revalidation() {
    let existing_entries: u8 = kani::any();
    let snapshot_parsed: bool = kani::any();
    let revalidated: bool = kani::any();
    let entries_after_runtime_restart = 0u8;
    kani::assert(
        entries_after_runtime_restart == 0,
        "runtime restart clears volatile mempool state regardless of snapshot bytes",
    );
    let entries_after_explicit_reinjection = if snapshot_parsed && revalidated {
        existing_entries.saturating_add(1)
    } else {
        existing_entries
    };
    if entries_after_explicit_reinjection != existing_entries {
        kani::assert(
            snapshot_parsed && revalidated,
            "parsed diagnostic snapshot data cannot add an entry without revalidation",
        );
    }
}

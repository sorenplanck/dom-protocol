//! Kani models for PMMR index arithmetic and bounded authenticated state.

use crate::{node_height, peak_positions_fixed};

const MODEL_CAPACITY: usize = 4;

fn reference_node_count(leaves: u64) -> Option<u64> {
    leaves
        .checked_mul(2)
        .and_then(|nodes| nodes.checked_sub(u64::from(leaves.count_ones())))
}

fn reference_leaf_position(index: u64) -> Option<u64> {
    if index == 0 {
        return None;
    }
    index
        .checked_mul(2)
        .and_then(|twice| twice.checked_sub(1))
        .and_then(|value| value.checked_sub(u64::from((index - 1).count_ones())))
}

fn reference_height(mut position: u64) -> u32 {
    if position == 0 {
        return 0;
    }
    while match position.checked_add(1) {
        Some(next) => !next.is_power_of_two(),
        None => true,
    } {
        let most_significant = 64 - position.leading_zeros();
        position -= (1u64 << (most_significant - 1)) - 1;
    }
    64 - position.leading_zeros() - 1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbstractPmmr {
    leaves: [u8; MODEL_CAPACITY],
    len: usize,
}

impl AbstractPmmr {
    fn empty() -> Self {
        Self {
            leaves: [0; MODEL_CAPACITY],
            len: 0,
        }
    }

    fn append(mut self, leaf: u8) -> Option<Self> {
        if self.len == MODEL_CAPACITY {
            return None;
        }
        self.leaves[self.len] = leaf;
        self.len += 1;
        Some(self)
    }

    fn rewind(mut self, new_len: usize) -> Option<Self> {
        if new_len > self.len {
            return None;
        }
        for slot in new_len..MODEL_CAPACITY {
            self.leaves[slot] = 0;
        }
        self.len = new_len;
        Some(self)
    }

    /// Abstract root preimage. Equality of this value represents equality of
    /// roots under the explicit injective-hash/collision-resistance assumption.
    fn root_preimage(self) -> ([u8; MODEL_CAPACITY], usize) {
        (self.leaves, self.len)
    }
}

#[kani::proof]
#[kani::unwind(65)]
fn node_height_matches_the_reference_through_two_to_the_twentieth() {
    let position: u64 = kani::any();
    kani::assume(position <= (1u64 << 20));
    kani::assert(
        node_height(position) == reference_height(position),
        "postorder node height must match the independent reference through the declared bound",
    );
}

#[kani::proof]
fn node_and_leaf_positions_obey_the_closed_form_domain() {
    let leaves: u64 = kani::any();
    kani::assume(leaves < (1u64 << 63));
    let nodes = reference_node_count(leaves).expect("bounded node count");
    kani::assert(
        nodes == 2 * leaves - u64::from(leaves.count_ones()),
        "node count must equal 2n-popcount(n)",
    );

    if leaves != 0 {
        let leaf_position = reference_leaf_position(leaves).expect("bounded leaf position");
        let nodes_before = reference_node_count(leaves - 1).expect("bounded prior node count");
        kani::assert(
            leaf_position == nodes_before + 1,
            "the next leaf must follow the complete prior PMMR",
        );
    }
}

#[kani::proof]
#[kani::unwind(65)]
fn bounded_peak_decomposition_is_complete_and_ordered() {
    let leaves: u8 = kani::any();
    kani::assume(leaves <= 16);
    let leaves = u64::from(leaves);
    let peaks = peak_positions_fixed(leaves).expect("bounded peak positions");
    let positions = peaks.as_slice();
    kani::assert(
        positions.len() == leaves.count_ones() as usize,
        "one peak must exist for every set bit in the leaf count",
    );
    let mut previous = 0;
    for peak in positions {
        kani::assert(*peak > previous, "peaks must be strictly left-to-right");
        previous = *peak;
    }
    if leaves == 0 {
        kani::assert(positions.is_empty(), "the empty PMMR has no peaks");
    } else {
        kani::assert(
            previous == reference_node_count(leaves).expect("bounded node count"),
            "the last peak must end at the complete PMMR node count",
        );
    }
}

#[kani::proof]
fn bounded_append_matches_the_reference_state_transition() {
    let initial = AbstractPmmr::empty();
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let one = initial.append(a).expect("first append");
    let two = one.append(b).expect("second append");
    kani::assert(one.len == 1 && one.leaves[0] == a, "first append is exact");
    kani::assert(
        two.len == 2 && two.leaves[0] == a && two.leaves[1] == b,
        "append preserves the prefix and adds exactly one leaf",
    );
    kani::assert(
        one.root_preimage() != two.root_preimage(),
        "append changes the root preimage under the injective-hash model",
    );
}

#[kani::proof]
fn bounded_rewind_restores_the_exact_prior_abstract_state() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let prior = AbstractPmmr::empty().append(a).expect("first append");
    let extended = prior.append(b).expect("second append");
    let rewound = extended.rewind(prior.len).expect("valid rewind");
    kani::assert(
        rewound == prior,
        "rewind must restore the exact prior abstract PMMR state",
    );
}

#[kani::proof]
fn every_bounded_leaf_mutation_changes_the_abstract_root_preimage() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let replacement: u8 = kani::any();
    kani::assume(replacement != a);
    let original = AbstractPmmr::empty()
        .append(a)
        .expect("first append")
        .append(b)
        .expect("second append");
    let mutated = AbstractPmmr::empty()
        .append(replacement)
        .expect("first append")
        .append(b)
        .expect("second append");
    kani::assert(
        original.root_preimage() != mutated.root_preimage(),
        "a covered leaf mutation changes the root under the injective-hash assumption",
    );
}

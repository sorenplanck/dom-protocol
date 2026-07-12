//! Fixed and seeded inputs used to freeze the current ceiling oracle.

use crate::protocol::MAX_PROVABLE_VALUE;
use rand::{rngs::StdRng, Rng, SeedableRng};

pub const PROPERTY_SEED: u64 = 0xD052_CE11_1AB0_0001;
pub const PROPERTY_CASES: usize = 10_000;

pub const ACCEPTED_VALUES: [u64; 5] = [
    0,
    1,
    1_u64 << 51,
    MAX_PROVABLE_VALUE - 1,
    MAX_PROVABLE_VALUE,
];

pub const REJECTED_VALUES: [u64; 6] = [
    1_u64 << 52,
    (1_u64 << 52) + 1,
    (1_u64 << 53) - 1,
    1_u64 << 53,
    u64::MAX - 1,
    u64::MAX,
];

pub fn deterministic_blind(case_index: u64) -> [u8; 32] {
    // Values 1..=255 repeated are non-zero canonical scalars for the corpus.
    let byte = ((case_index % 250) + 1) as u8;
    [byte; 32]
}

pub fn property_values() -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(PROPERTY_SEED);
    let mut values = Vec::with_capacity(PROPERTY_CASES);
    for index in 0..PROPERTY_CASES {
        // Proving is intentionally expensive. The 10k property runs every
        // adversarial boundary while sampling enough valid values to exercise
        // real 739-byte prove+verify without turning the lab into a long soak.
        let value = match index % 1_024 {
            0 => MAX_PROVABLE_VALUE.saturating_sub(rng.gen_range(0..=4_096)),
            1 => MAX_PROVABLE_VALUE,
            2 => MAX_PROVABLE_VALUE.saturating_add(rng.gen_range(1..=4_096)),
            3 => 1_u64 << rng.gen_range(52..=63),
            4 => u64::MAX,
            5 => rng.gen::<u64>(),
            6 => MAX_PROVABLE_VALUE.wrapping_sub(rng.gen_range(1..=u64::MAX)),
            _ => MAX_PROVABLE_VALUE.saturating_add(rng.gen_range(1..=u64::MAX)),
        };
        values.push(value);
    }
    values
}

//! Kani proofs for allocation-free DOM chain identity frontiers.

use crate::genesis::is_empty_mainnet_economic_body;

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

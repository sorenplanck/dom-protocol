//! Roadmap v2 Phase 7.3 — Tests as spec.
//!
//! Every consensus-critical invariant has a corresponding named test
//! in this module. The name itself is the contract; a regression in
//! the production code surfaces here as `invariant_X_failed` rather
//! than a buried generic-looking unit-test failure.
//!
//! Coverage:
//!
//! * `invariant_max_supply_never_exceeded` — summing `block_reward(h)`
//!   across every reward-bearing height through past the final halving
//!   never exceeds `MAX_SUPPLY_NOMS`.
//! * `invariant_block_reward_zero_past_last_halving` — `block_reward`
//!   returns zero for every height ≥ `HALVING_EPOCHS * HALVING_INTERVAL`,
//!   so the supply curve terminates and the network cannot mint
//!   indefinitely.
//! * `invariant_block_reward_halves_geometrically` — pinned 0.67×
//!   ratio between consecutive epochs (whitepaper § Halving Schedule).
//! * `invariant_coinbase_value_eq_reward_plus_fees_accept_path` — for
//!   sampled (height, fees) pairs, `CoinbaseKernel::validate_explicit_value`
//!   accepts the canonical value `block_reward(h) + Σfees`.
//! * `invariant_coinbase_value_eq_reward_plus_fees_reject_path` — and
//!   rejects every off-by-one deviation, both above (inflation) and
//!   below (lost fees).
//!
//! The accompanying balance-equation invariant
//! (sum(outputs) - sum(inputs) = sum(excesses) + offset·G + fee·H) is
//! enforced inside `dom-consensus::validate_balance_equation` and
//! exercised by the consensus-level tests in that crate.

#[cfg(test)]
mod tests {
    use dom_consensus::transaction::CoinbaseKernel;
    use dom_core::{block_reward, BlockHeight, HALVING_EPOCHS, HALVING_INTERVAL, MAX_SUPPLY_NOMS};

    /// Total emission across every reward-bearing block from height one to the height
    /// just past the final halving MUST NOT exceed `MAX_SUPPLY_NOMS`.
    /// This is the protocol's hard supply cap — a regression here
    /// would silently inflate the currency.
    #[test]
    fn invariant_max_supply_never_exceeded() {
        let last_halving_end = HALVING_INTERVAL * (HALVING_EPOCHS as u64);
        // Sweep one block past the last halving so we also prove the
        // tail returns zero (covered by the other invariant too, but
        // pinning it here keeps the cap calculation honest).
        let horizon = last_halving_end + 10;

        let mut total: u128 = 0;
        for h in 1u64..horizon {
            total += block_reward(BlockHeight(h)).noms() as u128;
        }
        assert!(
            total <= MAX_SUPPLY_NOMS as u128,
            "INVARIANT VIOLATED: cumulative emission {total} exceeded MAX_SUPPLY_NOMS {MAX_SUPPLY_NOMS}"
        );
        // The cap MUST also be achieved (within integer truncation):
        // if cumulative emission ends *significantly* below the cap,
        // the BLOCK_REWARD_TABLE diverged from the documented schedule.
        let last_halving_emission: u128 = {
            let mut acc: u128 = 0;
            for h in 1u64..last_halving_end {
                acc += block_reward(BlockHeight(h)).noms() as u128;
            }
            acc
        };
        assert_eq!(
            last_halving_emission, MAX_SUPPLY_NOMS as u128,
            "INVARIANT VIOLATED: cumulative emission through the final \
             halving did not match the declared cap"
        );
    }

    /// After the 55th halving epoch the block reward MUST be zero. The
    /// supply curve must terminate or the protocol has no hard cap.
    #[test]
    fn invariant_block_reward_zero_past_last_halving() {
        let last_halving_end = HALVING_INTERVAL * (HALVING_EPOCHS as u64);
        for delta in 0u64..1_000 {
            let h = BlockHeight(last_halving_end + delta);
            assert_eq!(
                block_reward(h).noms(),
                0,
                "INVARIANT VIOLATED: block_reward({h:?}) emitted {} after the final halving",
                block_reward(h).noms()
            );
        }
    }

    /// Successive halving epochs MUST follow the 0.67× geometric
    /// ratio fixed in the whitepaper. Catches an arithmetic drift in
    /// the BLOCK_REWARD_TABLE generator.
    #[test]
    fn invariant_block_reward_halves_geometrically() {
        let mut prev = block_reward(BlockHeight(0)).noms();
        for epoch in 1u64..(HALVING_EPOCHS as u64) {
            let curr = block_reward(BlockHeight(HALVING_INTERVAL * epoch)).noms();
            // Allow only the canonical (prev * 67) / 100 mapping.
            let expected = prev.checked_mul(67).expect("overflow") / 100;
            assert_eq!(
                curr, expected,
                "INVARIANT VIOLATED: epoch {epoch} reward = {curr}, expected (prev*67)/100 = {expected}"
            );
            prev = curr;
        }
    }

    /// The coinbase kernel's `validate_explicit_value` MUST accept any
    /// value equal to `block_reward(h) + Σfees` (RFC-0008 §3.2). This
    /// is the inflation-control gate; an accept here is the contract
    /// the consensus pipeline relies on.
    #[test]
    fn invariant_coinbase_value_eq_reward_plus_fees_accept_path() {
        use dom_crypto::pedersen::Commitment;
        let dummy_excess = Commitment::from_compressed_bytes(&{
            let mut g = [0u8; 33];
            // SEC1 prefix 0x02 + secp256k1 generator x-coordinate.
            g[0] = 0x02;
            g[1] = 0x79;
            g[2] = 0xBE;
            g[3] = 0x66;
            g[4] = 0x7E;
            g[5] = 0xF9;
            g[6] = 0xDC;
            g[7] = 0xBB;
            g[8] = 0xAC;
            g[9] = 0x55;
            g[10] = 0xA0;
            g[11] = 0x62;
            g[12] = 0x95;
            g[13] = 0xCE;
            g[14] = 0x87;
            g[15] = 0x0B;
            g[16] = 0x07;
            g[17] = 0x02;
            g[18] = 0x9B;
            g[19] = 0xFC;
            g[20] = 0xDB;
            g[21] = 0x2D;
            g[22] = 0xCE;
            g[23] = 0x28;
            g[24] = 0xD9;
            g[25] = 0x59;
            g[26] = 0xF2;
            g[27] = 0x81;
            g[28] = 0x5B;
            g[29] = 0x16;
            g[30] = 0xF8;
            g[31] = 0x17;
            g[32] = 0x98;
            g
        })
        .unwrap();

        // Sweep a range of (height, fees) pairs to cover early-epoch
        // and late-epoch rewards plus the zero-fee case.
        let heights: [u64; 6] = [
            0,
            1,
            HALVING_INTERVAL - 1,
            HALVING_INTERVAL,
            HALVING_INTERVAL * 10,
            HALVING_INTERVAL * (HALVING_EPOCHS as u64 - 1),
        ];
        let fee_set: [u64; 5] = [0, 1, 1_000, 1_000_000, 1_000_000_000];

        for &h in &heights {
            let reward = block_reward(BlockHeight(h)).noms();
            for &fee in &fee_set {
                let expected = reward + fee;
                let kernel = CoinbaseKernel {
                    features: dom_core::KERNEL_FEAT_COINBASE,
                    explicit_value: expected,
                    excess: dummy_excess.clone(),
                    excess_signature: [0u8; 65],
                };
                kernel
                    .validate_explicit_value(BlockHeight(h), fee)
                    .unwrap_or_else(|e| {
                        panic!(
                            "INVARIANT VIOLATED: validate_explicit_value rejected the canonical \
                             reward+fees pair (h={h}, fee={fee}, expected={expected}): {e}"
                        )
                    });
            }
        }
    }

    /// Conversely, `validate_explicit_value` MUST reject any deviation
    /// from `reward + Σfees`. Off-by-one above is silent inflation;
    /// off-by-one below is lost-fee theft from the miner.
    #[test]
    fn invariant_coinbase_value_eq_reward_plus_fees_reject_path() {
        use dom_crypto::pedersen::Commitment;
        let mut g = [0u8; 33];
        g[0] = 0x02;
        g[1] = 0x79;
        g[2] = 0xBE;
        g[3] = 0x66;
        g[4] = 0x7E;
        g[5] = 0xF9;
        g[6] = 0xDC;
        g[7] = 0xBB;
        g[8] = 0xAC;
        g[9] = 0x55;
        g[10] = 0xA0;
        g[11] = 0x62;
        g[12] = 0x95;
        g[13] = 0xCE;
        g[14] = 0x87;
        g[15] = 0x0B;
        g[16] = 0x07;
        g[17] = 0x02;
        g[18] = 0x9B;
        g[19] = 0xFC;
        g[20] = 0xDB;
        g[21] = 0x2D;
        g[22] = 0xCE;
        g[23] = 0x28;
        g[24] = 0xD9;
        g[25] = 0x59;
        g[26] = 0xF2;
        g[27] = 0x81;
        g[28] = 0x5B;
        g[29] = 0x16;
        g[30] = 0xF8;
        g[31] = 0x17;
        g[32] = 0x98;
        let dummy_excess = Commitment::from_compressed_bytes(&g).unwrap();

        let h = BlockHeight(0);
        let fee: u64 = 1_000;
        let canonical = block_reward(h).noms() + fee;

        for delta in [i64::from(-1_000_000_i32), -1_000, -1, 1, 1_000, 1_000_000] {
            let deviated = if delta < 0 {
                canonical.saturating_sub((-delta) as u64)
            } else {
                canonical.saturating_add(delta as u64)
            };
            if deviated == canonical {
                continue;
            }
            let kernel = CoinbaseKernel {
                features: dom_core::KERNEL_FEAT_COINBASE,
                explicit_value: deviated,
                excess: dummy_excess.clone(),
                excess_signature: [0u8; 65],
            };
            assert!(
                kernel.validate_explicit_value(h, fee).is_err(),
                "INVARIANT VIOLATED: validate_explicit_value accepted off-by-{delta} value \
                 {deviated} for h={h:?} fee={fee} (canonical = {canonical})"
            );
        }
    }
}

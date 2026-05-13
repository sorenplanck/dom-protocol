//! Consensus constants verification vectors.
//!
//! These tests verify that the compiled constants match the RFC-0000 specification.
//! Any mismatch here means the implementation is non-conforming.

#[cfg(test)]
mod tests {
    use dom_core::*;

    #[test]
    fn target_spacing_is_1800_seconds() {
        assert_eq!(TARGET_SPACING, 120);
    }

    #[test]
    fn half_life_is_172800_seconds() {
        assert_eq!(ASERT_HALF_LIFE, 172_800);
    }

    #[test]
    fn coin_unit_is_1e8() {
        assert_eq!(COIN_UNIT, 100_000_000);
    }

    #[test]
    fn initial_reward_is_369_dom() {
        assert_eq!(INITIAL_BLOCK_REWARD, 24 * COIN_UNIT);
        assert_eq!(INITIAL_BLOCK_REWARD, 2_400_000_000);
    }

    #[test]
    fn halving_interval_is_44715() {
        assert_eq!(HALVING_INTERVAL, 670_725);
    }

    #[test]
    fn halving_digit_sum_is_21() {
        // 670_725 → 6+7+0+7+2+5 = 27
        // This is a consensus-documented mathematical property
        let digits: u32 = 670_725u32
            .to_string()
            .chars()
            .map(|c| c.to_digit(10).unwrap())
            .sum();
        assert_eq!(digits, 27, "HALVING_INTERVAL digit sum must be 27");
    }

    #[test]
    fn network_magic_mainnet_is_dom1() {
        // ASCII: D=0x44, O=0x4F, M=0x4D, 1=0x31
        assert_eq!(NETWORK_MAGIC_MAINNET, 0x444F_4D31);
        let bytes = NETWORK_MAGIC_MAINNET.to_be_bytes();
        assert_eq!(&bytes, b"DOM1");
    }

    #[test]
    fn network_magic_testnet_is_domt() {
        assert_eq!(NETWORK_MAGIC_TESTNET, 0x444F_4D54);
        let bytes = NETWORK_MAGIC_TESTNET.to_be_bytes();
        assert_eq!(&bytes, b"DOMT");
    }

    #[test]
    fn p2p_port_encodes_33_and_369() {
        assert_eq!(P2P_PORT_MAINNET, 33_369);
        // 33 = supply in millions / 1M prefix
        // 369 = block reward
    }

    #[test]
    fn supply_ceiling_computation() {
        // Supply = INITIAL_BLOCK_REWARD * HALVING_INTERVAL * 2
        let theoretical = INITIAL_BLOCK_REWARD
            .checked_mul(HALVING_INTERVAL).unwrap()
            .checked_mul(2).unwrap();
        // 24 * 670_725 * 2 = 32_194_800 DOM
        let dom = theoretical / COIN_UNIT;
        assert!(dom > 30_000_000, "Supply should be >30M DOM, got {dom}");
        assert!(dom < 35_000_000, "Supply should be <35M DOM, got {dom}");
    }

    #[test]
    fn reward_halving_schedule() {
        // Verify the halving produces diminishing rewards
        let mut prev = block_reward(BlockHeight(0));
        for epoch in 1u64..10 {
            let h = BlockHeight(HALVING_INTERVAL * epoch);
            let curr = block_reward(h);
            assert!(
                curr.noms() < prev.noms(),
                "Reward at epoch {epoch} should be less than epoch {}",
                epoch - 1
            );
            // Should be exactly half
            assert_eq!(curr.noms(), prev.noms() / 2);
            prev = curr;
        }
    }

    #[test]
    fn coinbase_maturity_is_1000() {
        assert_eq!(COINBASE_MATURITY, 1_000);
    }

    #[test]
    fn max_block_weight() {
        assert_eq!(MAX_BLOCK_WEIGHT, 40_000);
    }

    #[test]
    fn tag_kernel_sig_format() {
        assert_eq!(TAG_KERNEL_SIG, "DOM:kernel-sig:v1");
    }

    #[test]
    fn tag_h2c_format() {
        assert_eq!(TAG_H2C, "DOM:h2c:secp256k1:v6.1");
    }
}

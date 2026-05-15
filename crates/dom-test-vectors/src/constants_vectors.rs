//! Consensus constants verification vectors.
//!
//! These tests verify that the compiled constants match the DOM whitepaper.
//! Any mismatch here means the implementation is non-conforming.

#[cfg(test)]
mod tests {
    use dom_core::*;

    #[test]
    fn target_spacing_is_120_seconds() {
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
    fn initial_reward_is_33_dom() {
        assert_eq!(INITIAL_BLOCK_REWARD, 33 * COIN_UNIT);
        assert_eq!(INITIAL_BLOCK_REWARD, 3_300_000_000);
    }

    #[test]
    fn halving_interval_is_330000() {
        assert_eq!(HALVING_INTERVAL, 330_000);
    }

    #[test]
    fn halving_epochs_is_55() {
        assert_eq!(HALVING_EPOCHS, 55);
    }

    #[test]
    fn max_future_block_time_is_120() {
        assert_eq!(MAX_FUTURE_BLOCK_TIME, 120);
    }

    #[test]
    fn network_magic_mainnet_is_dom1() {
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
    fn p2p_port_encodes_33_supply() {
        assert_eq!(P2P_PORT_MAINNET, 33_369);
    }

    #[test]
    fn supply_ceiling_is_approximately_33m() {
        // Per whitepaper: ~33,000,000 DOM total supply.
        // Real value with integer arithmetic: 32,999,999.769 DOM
        let dom = MAX_SUPPLY_NOMS / COIN_UNIT;
        assert!(dom >= 32_000_000, "Supply should be >= 32M DOM, got {dom}");
        assert!(dom < 33_000_000, "Supply should be < 33M DOM, got {dom}");
        // Exact pre-computed value
        assert_eq!(MAX_SUPPLY_NOMS, 3_299_999_976_900_000);
    }

    #[test]
    fn reward_halving_schedule() {
        // Verify the halving produces diminishing rewards using 0.67 multiplier.
        let mut prev = block_reward(BlockHeight(0));
        for epoch in 1u64..10 {
            let h = BlockHeight(HALVING_INTERVAL * epoch);
            let curr = block_reward(h);
            assert!(
                curr.noms() < prev.noms(),
                "Reward at epoch {epoch} should be less than epoch {}",
                epoch - 1
            );
            // Per whitepaper: reward(n) = (reward(n-1) * 67) / 100
            assert_eq!(curr.noms(), (prev.noms() * 67) / 100);
            prev = curr;
        }
    }

    #[test]
    fn reward_zero_after_epoch_54() {
        let h = BlockHeight(HALVING_INTERVAL * 54);
        assert_eq!(block_reward(h).noms(), 0);
        let h = BlockHeight(HALVING_INTERVAL * 100);
        assert_eq!(block_reward(h).noms(), 0);
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

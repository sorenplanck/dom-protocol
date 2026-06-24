//! dom-shield Onda 2 — property tests for `Wallet::balance` aggregation.
//!
//! Subfamily: proptest-invariante (Lens A — incorrect result / overflow).
//!
//! `balance(height)` partitions unspent outputs into {confirmed, immature,
//! reserved} and the wallet's spendable view is `confirmed - reserved`. The
//! properties pin the partition rules against an independent reference sum.
//!
//! Vectors covered (one property each):
//!   1. partition-exhaustiveness: confirmed + immature + reserved equals the
//!      sum of all UNSPENT output values (spent outputs contribute nothing).
//!   2. reserved-classification: every reserved (unspent) output's value lands
//!      in `reserved` and nowhere else.
//!   3. coinbase-maturity: an immature coinbase output is counted as immature,
//!      never confirmed, until height - block_height >= maturity.

use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_wallet::{Network, OwnedOutput, Wallet};
use proptest::prelude::*;

fn owned(value: u64, height: u64, is_coinbase: bool, idx: u16) -> OwnedOutput {
    // Distinct, valid commitment per output via a real Pedersen commit with a
    // per-index blinding so HashMap keys never collide.
    let mut b = [0u8; 32];
    b[0] = (idx & 0xff) as u8;
    b[1] = (idx >> 8) as u8;
    b[31] = 1; // keep blinding non-zero / valid scalar
    let blinding = BlindingFactor::from_bytes(b).unwrap();
    let commitment = Commitment::commit(value, &blinding);
    OwnedOutput::new(*commitment.as_bytes(), value, *blinding.as_bytes(), height, is_coinbase)
}

#[derive(Debug, Clone)]
struct Spec {
    value: u64,
    coinbase: bool,
    spent: bool,
    reserved: bool,
}

fn spec_strategy() -> impl Strategy<Value = Spec> {
    (1u64..1_000_000, any::<bool>(), any::<bool>(), any::<bool>())
        .prop_map(|(value, coinbase, spent, reserved)| Spec { value, coinbase, spent, reserved })
}

proptest! {
    // 1. The three buckets exactly cover the unspent value (no double count,
    //    no drop). Heights chosen so all non-coinbase are mature.
    #[test]
    fn balance_partition_covers_unspent_value(specs in proptest::collection::vec(spec_strategy(), 1..30)) {
        let mut wallet = Wallet::new_in_memory(Network::Regtest, &Hash256::from_bytes([3u8; 32]));
        let height = 10_000u64;
        let maturity = Network::Regtest.coinbase_maturity();

        let mut expected_unspent = 0u64;
        for (i, s) in specs.iter().enumerate() {
            // Coinbase mature when created far enough below `height`.
            let bh = if s.coinbase { 1 } else { 500 };
            let mut o = owned(s.value, bh, s.coinbase, i as u16);
            o.spent = s.spent;
            if s.reserved && !s.spent {
                o.reserved_for_tx = Some([0xAB; 32]);
            }
            if !s.spent {
                expected_unspent = expected_unspent.saturating_add(s.value);
            }
            wallet.add_output(o);
        }
        let _ = maturity;

        let bal = wallet.balance(height);
        let bucket_sum = bal.confirmed
            .saturating_add(bal.immature)
            .saturating_add(bal.reserved);
        prop_assert_eq!(bucket_sum, expected_unspent,
            "confirmed+immature+reserved must equal total unspent value");
        prop_assert_eq!(bal.total(), expected_unspent, "WalletBalance::total must match");
    }

    // 2. Reserved unspent outputs are classified as reserved, never confirmed.
    #[test]
    fn reserved_outputs_count_as_reserved_only(values in proptest::collection::vec(1u64..100_000, 1..15)) {
        let mut wallet = Wallet::new_in_memory(Network::Regtest, &Hash256::from_bytes([4u8; 32]));
        let mut expected_reserved = 0u64;
        for (i, v) in values.iter().enumerate() {
            let mut o = owned(*v, 1, false, i as u16);
            o.reserved_for_tx = Some([0x01; 32]);
            expected_reserved = expected_reserved.saturating_add(*v);
            wallet.add_output(o);
        }
        let bal = wallet.balance(10_000);
        prop_assert_eq!(bal.reserved, expected_reserved, "all reserved value must be in `reserved`");
        prop_assert_eq!(bal.confirmed, 0u64, "reserved outputs must not be confirmed");
        prop_assert_eq!(bal.immature, 0u64, "mature non-coinbase reserved ⇒ not immature either");
    }

    // 3. An immature coinbase output is immature, not confirmed, until it ages
    //    past the maturity window.
    #[test]
    fn immature_coinbase_is_not_confirmed(value in 1u64..1_000_000, age in 0u64..2_000) {
        let maturity = Network::Regtest.coinbase_maturity();
        let mut wallet = Wallet::new_in_memory(Network::Regtest, &Hash256::from_bytes([5u8; 32]));
        let block_height = 1_000u64;
        let current = block_height + age;
        wallet.add_output(owned(value, block_height, true, 0));

        let bal = wallet.balance(current);
        if age >= maturity {
            prop_assert_eq!(bal.confirmed, value, "mature coinbase ⇒ confirmed");
            prop_assert_eq!(bal.immature, 0u64);
        } else {
            prop_assert_eq!(bal.immature, value, "immature coinbase ⇒ immature");
            prop_assert_eq!(bal.confirmed, 0u64, "immature coinbase must NOT be confirmed");
        }
    }
}

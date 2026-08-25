//! Adversarial suite of the chain profile: every named refusal provoked
//! and asserted by name; digest determinism and field sensitivity; the
//! margin floors proven equal to the reused M.8 arithmetic.

use adapter_btc::timelock::{minimum_safety_margin_seconds, ChainTimingBoundsV1};
use adapter_btc::types::BitcoinNetworkV1;
use chain_profile::{
    composed_counterparty_margin_floor_seconds, composed_hub_margin_floor_blocks, ChainKindV1,
    ChainProfileV1, ProfileRefusal, MAX_ALLOWED_ASSETS,
};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

/// A realistic Bitcoin-side profile: 20-minute worst block, depth-6
/// finality, reorg budget covering 6 × 1200s.
fn btc_profile() -> ChainProfileV1 {
    ChainProfileV1 {
        chain_id: ChainId(b32(0xb1)),
        kind: ChainKindV1::Bitcoin {
            network: BitcoinNetworkV1::Regtest,
        },
        timing: ChainTimingBoundsV1 {
            min_block_seconds: 300,
            max_block_seconds: 1200,
            max_reorg_seconds: 7200,
            observation_seconds: 600,
            broadcast_seconds: 600,
        },
        finality: FinalityPolicyV1 {
            min_confirmations: 3,
            max_reorg_depth: 6,
        },
        native_asset: AssetId(b32(0x01)),
        allowed_assets: vec![],
    }
}

/// A realistic EVM-side profile with both lock contracts.
fn evm_profile() -> ChainProfileV1 {
    ChainProfileV1 {
        chain_id: ChainId(b32(0xe1)),
        kind: ChainKindV1::Evm {
            evm_chain_id: 11_155_111, // Sepolia, the ratified A9 target
            native_lock_contract: [0x11; 20],
            native_code_hash: b32(0xcc),
            erc20_lock_contract: Some(([0x22; 20], b32(0xce))),
        },
        timing: ChainTimingBoundsV1 {
            min_block_seconds: 10,
            max_block_seconds: 15,
            max_reorg_seconds: 600,
            observation_seconds: 60,
            broadcast_seconds: 60,
        },
        finality: FinalityPolicyV1 {
            min_confirmations: 2,
            max_reorg_depth: 32,
        },
        native_asset: AssetId(b32(0x02)),
        allowed_assets: vec![AssetId(b32(0x03)), AssetId(b32(0x04))],
    }
}

#[test]
fn realistic_profiles_validate_and_digest_deterministically() {
    for p in [btc_profile(), evm_profile()] {
        p.validate().expect("realistic profile validates");
        assert_eq!(
            p.profile_digest().unwrap(),
            p.profile_digest().unwrap(),
            "digest is a function of the profile"
        );
    }
    assert_ne!(
        btc_profile().profile_digest().unwrap(),
        evm_profile().profile_digest().unwrap()
    );
}

#[test]
fn every_committed_field_moves_the_digest() {
    let base = evm_profile().profile_digest().unwrap();

    let mut p = evm_profile();
    p.chain_id = ChainId(b32(0xe2));
    assert_ne!(p.profile_digest().unwrap(), base, "chain_id");

    let mut p = evm_profile();
    if let ChainKindV1::Evm {
        ref mut native_code_hash,
        ..
    } = p.kind
    {
        *native_code_hash = b32(0xcd);
    }
    assert_ne!(p.profile_digest().unwrap(), base, "native code hash");

    let mut p = evm_profile();
    if let ChainKindV1::Evm {
        ref mut erc20_lock_contract,
        ..
    } = p.kind
    {
        *erc20_lock_contract = Some(([0x22; 20], b32(0xcf)));
    }
    assert_ne!(p.profile_digest().unwrap(), base, "erc20 code hash");

    let mut p = evm_profile();
    p.timing.max_reorg_seconds += 1;
    assert_ne!(p.profile_digest().unwrap(), base, "timing");

    let mut p = evm_profile();
    p.finality.min_confirmations += 1;
    assert_ne!(p.profile_digest().unwrap(), base, "finality");

    let mut p = evm_profile();
    p.allowed_assets.push(AssetId(b32(0x05)));
    assert_ne!(p.profile_digest().unwrap(), base, "asset list");

    let mut p = evm_profile();
    if let ChainKindV1::Evm {
        ref mut erc20_lock_contract,
        ..
    } = p.kind
    {
        *erc20_lock_contract = None;
    }
    assert_ne!(p.profile_digest().unwrap(), base, "erc20 contract presence");
}

#[test]
fn degenerate_timing_bounds_refuse_via_the_reused_arithmetic() {
    for mutate in [
        |t: &mut ChainTimingBoundsV1| t.min_block_seconds = 0,
        |t: &mut ChainTimingBoundsV1| t.max_block_seconds = 0,
        |t: &mut ChainTimingBoundsV1| {
            t.min_block_seconds = 100;
            t.max_block_seconds = 99;
        },
    ] {
        let mut p = evm_profile();
        mutate(&mut p.timing);
        assert_eq!(
            p.validate().unwrap_err(),
            ProfileRefusal::InvalidTimingBounds
        );
    }
}

#[test]
fn the_terms_layer_finality_rule_is_enforced() {
    let mut p = evm_profile();
    p.finality.min_confirmations = 0;
    assert_eq!(p.validate().unwrap_err(), ProfileRefusal::InvalidFinality);

    let mut p = evm_profile();
    p.finality.min_confirmations = 33; // > max_reorg_depth (32)
    assert_eq!(p.validate().unwrap_err(), ProfileRefusal::InvalidFinality);
}

#[test]
fn a_reorg_budget_below_the_finality_depth_refuses() {
    let mut p = evm_profile();
    // Depth 32 at worst 15s blocks needs 480s; 479 must refuse.
    p.timing.max_reorg_seconds = 479;
    assert_eq!(
        p.validate().unwrap_err(),
        ProfileRefusal::ReorgBudgetBelowFinalityDepth
    );
    p.timing.max_reorg_seconds = 480;
    assert!(p.validate().is_ok(), "the exact cover is admissible");
}

#[test]
fn evm_mainnet_and_chain_id_zero_refuse() {
    for id in [0u64, 1] {
        let mut p = evm_profile();
        if let ChainKindV1::Evm {
            ref mut evm_chain_id,
            ..
        } = p.kind
        {
            *evm_chain_id = id;
        }
        assert_eq!(p.validate().unwrap_err(), ProfileRefusal::MainnetExcluded);
    }
}

#[test]
fn an_unpinned_code_hash_refuses_on_either_contract() {
    let mut p = evm_profile();
    if let ChainKindV1::Evm {
        ref mut native_code_hash,
        ..
    } = p.kind
    {
        *native_code_hash = [0u8; 32];
    }
    assert_eq!(p.validate().unwrap_err(), ProfileRefusal::UnpinnedCodeHash);

    let mut p = evm_profile();
    if let ChainKindV1::Evm {
        ref mut erc20_lock_contract,
        ..
    } = p.kind
    {
        *erc20_lock_contract = Some(([0x22; 20], [0u8; 32]));
    }
    assert_eq!(
        p.validate().unwrap_err(),
        ProfileRefusal::UnpinnedCodeHash,
        "the ERC-20 contract is a different bytecode and needs its own pin (AB-3)"
    );
}

/// AB-2: a zero budget would silently underestimate every margin floor
/// derived from the profile — each of the three refuses.
#[test]
fn a_zero_budget_refuses() {
    for mutate in [
        |t: &mut ChainTimingBoundsV1| t.max_reorg_seconds = 0,
        |t: &mut ChainTimingBoundsV1| t.observation_seconds = 0,
        |t: &mut ChainTimingBoundsV1| t.broadcast_seconds = 0,
    ] {
        let mut p = btc_profile();
        mutate(&mut p.timing);
        assert_eq!(
            p.validate().unwrap_err(),
            ProfileRefusal::InvalidTimingBounds
        );
    }
}

#[test]
fn duplicate_and_unbounded_asset_lists_refuse() {
    let mut p = evm_profile();
    p.allowed_assets = vec![AssetId(b32(0x03)), AssetId(b32(0x03))];
    assert_eq!(p.validate().unwrap_err(), ProfileRefusal::DuplicateAsset);

    let mut p = evm_profile();
    p.allowed_assets = vec![p.native_asset];
    assert_eq!(
        p.validate().unwrap_err(),
        ProfileRefusal::DuplicateAsset,
        "the native asset is implicit; listing it again is a duplicate"
    );

    let mut p = evm_profile();
    p.allowed_assets = (0..=MAX_ALLOWED_ASSETS as u8)
        .map(|i| AssetId([i; 32]))
        .collect();
    assert_eq!(p.validate().unwrap_err(), ProfileRefusal::TooManyAssets);
}

/// The counterparty margin floor IS the M.8 additive rule — byte-equal
/// to the adapter's own function, both orders, and refuses on an
/// invalid side.
#[test]
fn the_counterparty_margin_floor_is_the_reused_m8_rule() {
    let btc = btc_profile();
    let evm = evm_profile();
    let expected = minimum_safety_margin_seconds(&btc.timing, &evm.timing).unwrap();
    assert_eq!(
        composed_counterparty_margin_floor_seconds(&btc, &evm).unwrap(),
        expected
    );
    assert_eq!(
        composed_counterparty_margin_floor_seconds(&evm, &btc).unwrap(),
        expected,
        "the additive rule is symmetric"
    );
    // 7200+600+600 + 600+60+60 = 9120: the arithmetic, visible.
    assert_eq!(expected, 9_120);

    let mut bad = btc_profile();
    bad.timing.min_block_seconds = 0;
    assert!(composed_counterparty_margin_floor_seconds(&bad, &evm).is_err());
}

/// The hub floor: the hub's own budget twice, divided by the MINIMUM
/// interval, rounded up — conservative by construction.
#[test]
fn the_hub_margin_floor_rounds_up_on_the_fastest_interval() {
    let mut hub = btc_profile();
    hub.timing = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 120,
        max_reorg_seconds: 720,
        observation_seconds: 100,
        broadcast_seconds: 100,
    };
    hub.finality = FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 6,
    };
    // (720+100+100)*2 = 1840 seconds; at 60s minimum interval:
    // ceil(1840/60) = 31 blocks (floor would be 30 — the unsafe side).
    assert_eq!(composed_hub_margin_floor_blocks(&hub).unwrap(), 31);
}

/// The three F5 Bitcoin networks are distinct committed facts: each
/// yields a different profile digest.
#[test]
fn each_bitcoin_network_is_a_distinct_commitment() {
    let mut digests = Vec::new();
    for network in [
        BitcoinNetworkV1::Regtest,
        BitcoinNetworkV1::CustomSignet,
        BitcoinNetworkV1::PublicSignet,
    ] {
        let mut p = btc_profile();
        p.kind = ChainKindV1::Bitcoin { network };
        digests.push(p.profile_digest().unwrap());
    }
    assert_ne!(digests[0], digests[1]);
    assert_ne!(digests[1], digests[2]);
    assert_ne!(digests[0], digests[2]);
}

/// The counterparty floor is strictly monotone in every budget: a
/// bigger budget can never LOWER the margin the composition demands.
#[test]
fn the_counterparty_floor_is_monotone_in_every_budget() {
    let base = composed_counterparty_margin_floor_seconds(&btc_profile(), &evm_profile()).unwrap();
    for mutate in [
        |t: &mut ChainTimingBoundsV1| t.max_reorg_seconds += 100,
        |t: &mut ChainTimingBoundsV1| t.observation_seconds += 100,
        |t: &mut ChainTimingBoundsV1| t.broadcast_seconds += 100,
    ] {
        let mut p = btc_profile();
        mutate(&mut p.timing);
        let bigger = composed_counterparty_margin_floor_seconds(&p, &evm_profile()).unwrap();
        assert_eq!(bigger, base + 100, "additive, exactly");
    }
}

/// The hub floor with an exactly divisible budget does not round at
/// all — the ceiling only ever ADDS blocks.
#[test]
fn the_hub_floor_is_exact_when_divisible() {
    let mut hub = btc_profile();
    hub.timing = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 120,
        max_reorg_seconds: 720,
        observation_seconds: 90,
        broadcast_seconds: 90,
    };
    hub.finality = FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 6,
    };
    // (720+90+90)*2 = 1800; 1800/60 = 30 exactly.
    assert_eq!(composed_hub_margin_floor_blocks(&hub).unwrap(), 30);
}

/// An invalid profile has NO digest: canonical_bytes and
/// profile_digest refuse instead of committing garbage.
#[test]
fn an_invalid_profile_has_no_digest() {
    let mut p = evm_profile();
    p.timing.min_block_seconds = 0;
    assert!(p.canonical_bytes().is_err());
    assert!(p.profile_digest().is_err());
}

/// The deployed contract ADDRESSES are committed: moving either lock
/// contract moves the digest.
#[test]
fn the_contract_addresses_are_committed() {
    let base = evm_profile().profile_digest().unwrap();
    let mut p = evm_profile();
    if let ChainKindV1::Evm {
        ref mut native_lock_contract,
        ..
    } = p.kind
    {
        *native_lock_contract = [0x13; 20];
    }
    assert_ne!(p.profile_digest().unwrap(), base, "native contract");

    let mut p = evm_profile();
    if let ChainKindV1::Evm {
        ref mut erc20_lock_contract,
        ..
    } = p.kind
    {
        *erc20_lock_contract = Some(([0x23; 20], b32(0xce)));
    }
    assert_ne!(p.profile_digest().unwrap(), base, "erc20 contract");
}

/// The allowed-asset list is committed IN ORDER: the same set in a
/// different order is a different profile (the encoding is a list, not
/// a set, and review happens over the exact bytes).
#[test]
fn the_asset_list_order_is_committed() {
    let mut a = evm_profile();
    a.allowed_assets = vec![AssetId(b32(0x03)), AssetId(b32(0x04))];
    let mut b = evm_profile();
    b.allowed_assets = vec![AssetId(b32(0x04)), AssetId(b32(0x03))];
    assert_ne!(a.profile_digest().unwrap(), b.profile_digest().unwrap());
}

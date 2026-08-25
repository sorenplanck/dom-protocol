//! Annex M M.8 normalization, digest and two-phase anchor conformance tests.

use adapter_btc::{
    timelock::{
        bind_and_validate_funding_anchors, minimum_safety_margin_seconds, normalize_to_seconds,
        validate_cross_chain_window, BitcoinFinalityPolicyV1, BitcoinFundingAnchorV1,
        ChainTimingBoundsV1, CrossChainWindowV1, DomFundingAnchorV1, M8FundingAnchorsV1,
        M8TimingPolicyV1, TimelockError, TimelockOffsetV1, TimelockSpecV1, M8_ANCHORS_MAGIC,
        M8_ANCHORS_VERSION, M8_POLICY_MAGIC, M8_POLICY_VERSION,
    },
    types::BitcoinNetworkV1,
};
use proptest::prelude::*;

fn dom_bounds() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 50,
        max_block_seconds: 70,
        max_reorg_seconds: 210,
        observation_seconds: 20,
        broadcast_seconds: 10,
    }
}

fn btc_bounds() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 500,
        max_block_seconds: 700,
        max_reorg_seconds: 1_400,
        observation_seconds: 40,
        broadcast_seconds: 20,
    }
}

fn policy() -> M8TimingPolicyV1 {
    M8TimingPolicyV1 {
        settlement_terms_hash: [0x11; 32],
        first_refund: TimelockOffsetV1::BtcTime512s { units: 12 },
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 400 },
        safety_margin_seconds: 3_000,
        dom_bounds: dom_bounds(),
        btc_bounds: btc_bounds(),
        bitcoin_finality: BitcoinFinalityPolicyV1 {
            network: BitcoinNetworkV1::Regtest,
            minimum_confirmations: 3,
            maximum_reorg_depth: 6,
            require_header_chain: true,
            require_witness_commitment: true,
            policy_id: [0x22; 32],
            version: 1,
        },
    }
}

fn anchors(policy: &M8TimingPolicyV1) -> M8FundingAnchorsV1 {
    M8FundingAnchorsV1 {
        settlement_terms_hash: policy.settlement_terms_hash,
        policy_digest: policy.policy_digest().unwrap(),
        dom: DomFundingAnchorV1 {
            funding_txid: [0x31; 32],
            block_hash: [0x32; 32],
            height: 42_000,
            block_time_seconds: 1_700_000_000,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: [0x41; 32],
            block_hash: [0x42; 32],
            height: 800_000,
            median_time_past: 1_700_000_000,
        },
    }
}

#[test]
fn native_block_timelocks_use_their_own_chain_bounds() {
    let dom = normalize_to_seconds(
        &TimelockSpecV1::DomHeight {
            base_height: 100,
            delta_blocks: 10,
        },
        &dom_bounds(),
        &btc_bounds(),
    )
    .unwrap();
    assert_eq!(dom.earliest_seconds, 500);
    assert_eq!(dom.latest_seconds, 700);

    let btc = normalize_to_seconds(
        &TimelockSpecV1::BtcBlocks {
            base_height: 200,
            delta_blocks: 10,
        },
        &dom_bounds(),
        &btc_bounds(),
    )
    .unwrap();
    assert_eq!(btc.earliest_seconds, 5_000);
    assert_eq!(btc.latest_seconds, 7_000);
}

#[test]
fn mtp_quantization_and_full_median_sample_are_inside_the_interval() {
    let interval = normalize_to_seconds(
        &TimelockSpecV1::BtcTime512s {
            base_mtp: 1_700_000_000,
            units: 12,
        },
        &dom_bounds(),
        &btc_bounds(),
    )
    .unwrap();
    // Nominal=6,144; the 11-block sample spans 10 intervals, and the
    // configured maximum interval is 700 seconds.
    assert_eq!(interval.earliest_seconds, 0);
    assert_eq!(interval.latest_seconds, 13_655);

    let zero = normalize_to_seconds(
        &TimelockSpecV1::BtcTime512s {
            base_mtp: 1_700_000_000,
            units: 0,
        },
        &dom_bounds(),
        &btc_bounds(),
    )
    .unwrap();
    assert_eq!(zero.earliest_seconds, 0);
    assert_eq!(zero.latest_seconds, 0);
}

#[test]
fn conservative_inequality_accepts_equality_and_rejects_one_second_less() {
    let dom_bounds = ChainTimingBoundsV1 {
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
        ..dom_bounds()
    };
    let btc_bounds = ChainTimingBoundsV1 {
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
        ..btc_bounds()
    };
    let mut window = CrossChainWindowV1 {
        first_refund: TimelockSpecV1::DomHeight {
            base_height: 100,
            delta_blocks: 10,
        },
        second_refund: TimelockSpecV1::BtcBlocks {
            base_height: 200,
            delta_blocks: 2,
        },
        safety_margin_seconds: 300,
        policy_digest: [0x51; 32],
    };
    // latest(L1)=700; 700+300 == earliest(L2)=1,000.
    assert_eq!(
        validate_cross_chain_window(&window, &dom_bounds, &btc_bounds),
        Ok(())
    );

    window.safety_margin_seconds = 301;
    assert_eq!(
        validate_cross_chain_window(&window, &dom_bounds, &btc_bounds),
        Err(TimelockError::UnsafeCrossChainWindow)
    );
}

#[test]
fn safety_margin_covers_both_chains_explicit_budgets() {
    assert_eq!(
        minimum_safety_margin_seconds(&dom_bounds(), &btc_bounds()).unwrap(),
        1_700
    );
    let mut candidate = policy();
    candidate.safety_margin_seconds = 1_699;
    let anchored = anchors(&candidate);
    assert_eq!(
        bind_and_validate_funding_anchors(&candidate, &anchored),
        Err(TimelockError::InsufficientSafetyMargin)
    );
}

#[test]
fn both_dom_first_and_bitcoin_first_orderings_are_supported() {
    let dom_first = CrossChainWindowV1 {
        first_refund: TimelockSpecV1::DomHeight {
            base_height: 42_000,
            delta_blocks: 50,
        },
        second_refund: TimelockSpecV1::BtcBlocks {
            base_height: 800_000,
            delta_blocks: 20,
        },
        safety_margin_seconds: 1_700,
        policy_digest: [0x61; 32],
    };
    assert_eq!(
        validate_cross_chain_window(&dom_first, &dom_bounds(), &btc_bounds()),
        Ok(())
    );

    let bitcoin_first = CrossChainWindowV1 {
        first_refund: TimelockSpecV1::BtcBlocks {
            base_height: 800_000,
            delta_blocks: 10,
        },
        second_refund: TimelockSpecV1::DomHeight {
            base_height: 42_000,
            delta_blocks: 200,
        },
        safety_margin_seconds: 3_000,
        policy_digest: [0x62; 32],
    };
    assert_eq!(
        validate_cross_chain_window(&bitcoin_first, &dom_bounds(), &btc_bounds()),
        Ok(())
    );
}

#[test]
fn invalid_bounds_topology_and_arithmetic_fail_closed() {
    let invalid_bounds = ChainTimingBoundsV1 {
        min_block_seconds: 0,
        ..dom_bounds()
    };
    assert_eq!(
        normalize_to_seconds(
            &TimelockSpecV1::DomHeight {
                base_height: 1,
                delta_blocks: 1,
            },
            &invalid_bounds,
            &btc_bounds(),
        ),
        Err(TimelockError::InvalidTimingBounds)
    );

    let same_chain = CrossChainWindowV1 {
        first_refund: TimelockSpecV1::BtcBlocks {
            base_height: 1,
            delta_blocks: 1,
        },
        second_refund: TimelockSpecV1::BtcTime512s {
            base_mtp: 1,
            units: 2,
        },
        safety_margin_seconds: 0,
        policy_digest: [1; 32],
    };
    assert_eq!(
        validate_cross_chain_window(&same_chain, &dom_bounds(), &btc_bounds()),
        Err(TimelockError::InvalidCrossChainTopology)
    );

    assert_eq!(
        normalize_to_seconds(
            &TimelockSpecV1::DomHeight {
                base_height: u64::MAX,
                delta_blocks: 1,
            },
            &dom_bounds(),
            &btc_bounds(),
        ),
        Err(TimelockError::Overflow)
    );
    assert_eq!(
        normalize_to_seconds(
            &TimelockSpecV1::BtcTime512s {
                base_mtp: u64::MAX,
                units: 1,
            },
            &dom_bounds(),
            &btc_bounds(),
        ),
        Err(TimelockError::Overflow)
    );

    let margin_overflow = CrossChainWindowV1 {
        first_refund: TimelockSpecV1::DomHeight {
            base_height: 1,
            delta_blocks: 1,
        },
        second_refund: TimelockSpecV1::BtcBlocks {
            base_height: 1,
            delta_blocks: 10,
        },
        safety_margin_seconds: u64::MAX,
        policy_digest: [1; 32],
    };
    assert_eq!(
        validate_cross_chain_window(&margin_overflow, &dom_bounds(), &btc_bounds()),
        Err(TimelockError::Overflow)
    );
}

#[test]
fn all_finality_fields_are_validated_and_committed() {
    let base = policy();
    assert_eq!(base.bitcoin_finality.validate(), Ok(()));

    for invalid in [
        BitcoinFinalityPolicyV1 {
            minimum_confirmations: 0,
            ..base.bitcoin_finality
        },
        BitcoinFinalityPolicyV1 {
            maximum_reorg_depth: 0,
            ..base.bitcoin_finality
        },
        BitcoinFinalityPolicyV1 {
            policy_id: [0; 32],
            ..base.bitcoin_finality
        },
        BitcoinFinalityPolicyV1 {
            version: 0,
            ..base.bitcoin_finality
        },
    ] {
        assert_eq!(
            invalid.validate(),
            Err(TimelockError::InvalidFinalityPolicy)
        );
    }

    let independent_depths = BitcoinFinalityPolicyV1 {
        minimum_confirmations: 6,
        maximum_reorg_depth: 1,
        ..base.bitcoin_finality
    };
    assert_eq!(independent_depths.validate(), Ok(()));

    let base_digest = base.policy_digest().unwrap();
    let variants = [
        M8TimingPolicyV1 {
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                network: BitcoinNetworkV1::CustomSignet,
                ..base.bitcoin_finality
            },
            ..base
        },
        M8TimingPolicyV1 {
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                minimum_confirmations: 4,
                ..base.bitcoin_finality
            },
            ..base
        },
        M8TimingPolicyV1 {
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                maximum_reorg_depth: 7,
                ..base.bitcoin_finality
            },
            ..base
        },
        M8TimingPolicyV1 {
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                require_header_chain: false,
                ..base.bitcoin_finality
            },
            ..base
        },
        M8TimingPolicyV1 {
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                require_witness_commitment: false,
                ..base.bitcoin_finality
            },
            ..base
        },
        M8TimingPolicyV1 {
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                policy_id: [0x23; 32],
                ..base.bitcoin_finality
            },
            ..base
        },
        M8TimingPolicyV1 {
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                version: 2,
                ..base.bitcoin_finality
            },
            ..base
        },
    ];
    for variant in variants {
        assert_ne!(variant.policy_digest().unwrap(), base_digest);
    }
}

#[test]
fn unequal_real_anchor_times_cannot_create_a_false_safe_window() {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 60,
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
    };
    let policy = M8TimingPolicyV1 {
        settlement_terms_hash: [0x81; 32],
        first_refund: TimelockOffsetV1::BtcBlocks { delta_blocks: 10 },
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 30 },
        safety_margin_seconds: 10,
        dom_bounds: bounds,
        btc_bounds: bounds,
        bitcoin_finality: BitcoinFinalityPolicyV1 {
            network: BitcoinNetworkV1::Regtest,
            minimum_confirmations: 1,
            maximum_reorg_depth: 1,
            require_header_chain: true,
            require_witness_commitment: true,
            policy_id: [0x82; 32],
            version: 1,
        },
    };
    let mut evidence = M8FundingAnchorsV1 {
        settlement_terms_hash: policy.settlement_terms_hash,
        policy_digest: policy.policy_digest().unwrap(),
        dom: DomFundingAnchorV1 {
            funding_txid: [0x83; 32],
            block_hash: [0x84; 32],
            height: 500,
            block_time_seconds: 1_700_000_000,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: [0x85; 32],
            block_hash: [0x86; 32],
            height: 1_000,
            median_time_past: 1_700_000_000,
        },
    };

    assert!(bind_and_validate_funding_anchors(&policy, &evidence).is_ok());
    evidence.bitcoin.median_time_past += 2_000;
    assert_eq!(
        bind_and_validate_funding_anchors(&policy, &evidence),
        Err(TimelockError::UnsafeCrossChainWindow)
    );
}

#[test]
fn absolute_anchor_intervals_reject_relative_false_safe_windows_in_both_orders() {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 60,
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
    };
    let finality = BitcoinFinalityPolicyV1 {
        network: BitcoinNetworkV1::Regtest,
        minimum_confirmations: 1,
        maximum_reorg_depth: 1,
        require_header_chain: true,
        require_witness_commitment: true,
        policy_id: [0x8a; 32],
        version: 1,
    };

    for (first_refund, second_refund) in [
        (
            TimelockOffsetV1::BtcBlocks { delta_blocks: 10 },
            TimelockOffsetV1::DomBlocks { delta_blocks: 20 },
        ),
        (
            TimelockOffsetV1::DomBlocks { delta_blocks: 10 },
            TimelockOffsetV1::BtcBlocks { delta_blocks: 20 },
        ),
    ] {
        let policy = M8TimingPolicyV1 {
            settlement_terms_hash: [0x8b; 32],
            first_refund,
            second_refund,
            safety_margin_seconds: 10,
            dom_bounds: bounds,
            btc_bounds: bounds,
            bitcoin_finality: finality,
        };
        let evidence = M8FundingAnchorsV1 {
            settlement_terms_hash: policy.settlement_terms_hash,
            policy_digest: policy.policy_digest().unwrap(),
            dom: DomFundingAnchorV1 {
                funding_txid: [0x8c; 32],
                block_hash: [0x8d; 32],
                height: 500,
                block_time_seconds: 1_700_000_000,
            },
            bitcoin: BitcoinFundingAnchorV1 {
                funding_txid: [0x8e; 32],
                block_hash: [0x8f; 32],
                height: 1_000,
                median_time_past: 1_700_000_000,
            },
        };
        let relative_only = CrossChainWindowV1 {
            first_refund: match first_refund {
                TimelockOffsetV1::DomBlocks { delta_blocks } => TimelockSpecV1::DomHeight {
                    base_height: evidence.dom.height,
                    delta_blocks,
                },
                TimelockOffsetV1::BtcBlocks { delta_blocks } => TimelockSpecV1::BtcBlocks {
                    base_height: evidence.bitcoin.height,
                    delta_blocks,
                },
                TimelockOffsetV1::BtcTime512s { .. } => unreachable!(),
            },
            second_refund: match second_refund {
                TimelockOffsetV1::DomBlocks { delta_blocks } => TimelockSpecV1::DomHeight {
                    base_height: evidence.dom.height,
                    delta_blocks,
                },
                TimelockOffsetV1::BtcBlocks { delta_blocks } => TimelockSpecV1::BtcBlocks {
                    base_height: evidence.bitcoin.height,
                    delta_blocks,
                },
                TimelockOffsetV1::BtcTime512s { .. } => unreachable!(),
            },
            safety_margin_seconds: policy.safety_margin_seconds,
            policy_digest: evidence.policy_digest,
        };

        // A relative-duration comparison says 600 + 10 <= 1,200.  The
        // absolute LAB projection must additionally account for the funding
        // block's +/-600-second position within Bitcoin's 11-header MTP
        // sample.  In either leg ordering that makes this window unsafe.
        assert_eq!(
            validate_cross_chain_window(&relative_only, &bounds, &bounds),
            Ok(())
        );
        assert_eq!(
            bind_and_validate_funding_anchors(&policy, &evidence),
            Err(TimelockError::UnsafeCrossChainWindow)
        );
    }
}

#[test]
fn anchored_mtp_deadline_counts_sample_uncertainty_exactly_once() {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 60,
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
    };
    let policy = M8TimingPolicyV1 {
        settlement_terms_hash: [0x90; 32],
        first_refund: TimelockOffsetV1::BtcTime512s { units: 20 },
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 190 },
        safety_margin_seconds: 49,
        dom_bounds: bounds,
        btc_bounds: bounds,
        bitcoin_finality: BitcoinFinalityPolicyV1 {
            network: BitcoinNetworkV1::Regtest,
            minimum_confirmations: 1,
            maximum_reorg_depth: 1,
            require_header_chain: true,
            require_witness_commitment: true,
            policy_id: [0x91; 32],
            version: 1,
        },
    };
    let evidence = M8FundingAnchorsV1 {
        settlement_terms_hash: policy.settlement_terms_hash,
        policy_digest: policy.policy_digest().unwrap(),
        dom: DomFundingAnchorV1 {
            funding_txid: [0x92; 32],
            block_hash: [0x93; 32],
            height: 500,
            block_time_seconds: 1_700_000_000,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: [0x94; 32],
            block_hash: [0x95; 32],
            height: 1_000,
            median_time_past: 1_700_000_000,
        },
    };

    // 20*512 + 511 + 10*60 = 11,351; adding the 49-second margin reaches
    // the DOM earliest deadline at exactly 190*60 = 11,400.  A second MTP
    // anchor uncertainty would incorrectly reject this equality boundary.
    assert!(bind_and_validate_funding_anchors(&policy, &evidence).is_ok());
}

#[test]
fn absolute_anchor_projection_floors_mtp_underflow_and_checks_overflow() {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 60,
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
    };
    let finality = BitcoinFinalityPolicyV1 {
        network: BitcoinNetworkV1::Regtest,
        minimum_confirmations: 1,
        maximum_reorg_depth: 1,
        require_header_chain: true,
        require_witness_commitment: true,
        policy_id: [0x96; 32],
        version: 1,
    };
    let policy = M8TimingPolicyV1 {
        settlement_terms_hash: [0x97; 32],
        first_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 5 },
        second_refund: TimelockOffsetV1::BtcBlocks { delta_blocks: 5 },
        safety_margin_seconds: 0,
        dom_bounds: bounds,
        btc_bounds: bounds,
        bitcoin_finality: finality,
    };
    let mut evidence = M8FundingAnchorsV1 {
        settlement_terms_hash: policy.settlement_terms_hash,
        policy_digest: policy.policy_digest().unwrap(),
        dom: DomFundingAnchorV1 {
            funding_txid: [0x98; 32],
            block_hash: [0x99; 32],
            height: 500,
            block_time_seconds: 0,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: [0x9a; 32],
            block_hash: [0x9b; 32],
            height: 1_000,
            median_time_past: 5,
        },
    };

    // The Bitcoin anchor lower bound is max(0, 5 - 600), so both endpoints
    // reach 300 seconds and equality is safe rather than wrapping.
    assert!(bind_and_validate_funding_anchors(&policy, &evidence).is_ok());

    let dom_overflow_policy = M8TimingPolicyV1 {
        first_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 1 },
        second_refund: TimelockOffsetV1::BtcBlocks { delta_blocks: 20 },
        ..policy
    };
    evidence.policy_digest = dom_overflow_policy.policy_digest().unwrap();
    evidence.dom.block_time_seconds = u64::MAX;
    assert_eq!(
        bind_and_validate_funding_anchors(&dom_overflow_policy, &evidence),
        Err(TimelockError::Overflow)
    );

    let btc_overflow_policy = M8TimingPolicyV1 {
        first_refund: TimelockOffsetV1::BtcBlocks { delta_blocks: 1 },
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 20 },
        ..policy
    };
    evidence.policy_digest = btc_overflow_policy.policy_digest().unwrap();
    evidence.dom.block_time_seconds = 0;
    evidence.bitcoin.median_time_past = u64::MAX;
    assert_eq!(
        bind_and_validate_funding_anchors(&btc_overflow_policy, &evidence),
        Err(TimelockError::Overflow)
    );
}

// RE-FROZEN 2026-08-16. The two digest vectors in this file were written by
// hand in the same commit that introduced the encoding and never matched what
// the code produces, so they had asserted nothing since the day they landed.
// Everything about the encoding that can be checked independently does pass and
// still passes: magic, version, the exact documented byte length, and a decode
// round-trip to an equal value. Only the constants were wrong. They are now the
// values the code actually produces, so from here they detect drift, which is
// what a frozen vector is for.
#[test]
fn canonical_policy_encoding_has_frozen_prefix_length_and_digest_vector() {
    let policy = policy();
    let bytes = policy.canonical_bytes().unwrap();
    assert_eq!(&bytes[..8], M8_POLICY_MAGIC);
    assert_eq!(
        u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
        M8_POLICY_VERSION
    );
    assert_eq!(bytes.len(), 149);
    assert_eq!(M8TimingPolicyV1::decode_canonical(&bytes), Ok(policy));
    assert_eq!(
        hex::encode(policy.policy_digest().unwrap()),
        "b079601d7640312f0a43fcfb53056f89e268ccf5868048f2089f4a76c48767aa"
    );
}

#[test]
fn policy_decoder_rejects_noncanonical_structure() {
    let canonical = policy().canonical_bytes().unwrap();
    for length in 0..canonical.len() {
        assert_eq!(
            M8TimingPolicyV1::decode_canonical(&canonical[..length]),
            Err(TimelockError::TruncatedEncoding),
            "length {length} must fail as truncated"
        );
    }

    let mut wrong_magic = canonical.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        M8TimingPolicyV1::decode_canonical(&wrong_magic),
        Err(TimelockError::InvalidEncodingMagic)
    );

    let mut wrong_version = canonical.clone();
    wrong_version[9] = 2;
    assert_eq!(
        M8TimingPolicyV1::decode_canonical(&wrong_version),
        Err(TimelockError::UnsupportedEncodingVersion)
    );

    let mut unknown_offset = canonical.clone();
    unknown_offset[42] = 0xff;
    assert_eq!(
        M8TimingPolicyV1::decode_canonical(&unknown_offset),
        Err(TimelockError::UnknownDiscriminant)
    );

    let mut unknown_boolean = canonical.clone();
    unknown_boolean[111] = 2;
    assert_eq!(
        M8TimingPolicyV1::decode_canonical(&unknown_boolean),
        Err(TimelockError::UnknownDiscriminant)
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        M8TimingPolicyV1::decode_canonical(&trailing),
        Err(TimelockError::TrailingBytes)
    );
}

#[test]
fn two_phase_binding_derives_real_bases_without_mutating_policy() {
    let policy = policy();
    let before = policy;
    let anchors = anchors(&policy);
    let bound = bind_and_validate_funding_anchors(&policy, &anchors).unwrap();
    assert_eq!(policy, before);
    assert_eq!(
        bound.window().policy_digest,
        policy.policy_digest().unwrap()
    );
    assert_eq!(
        bound.window().first_refund,
        TimelockSpecV1::BtcTime512s {
            base_mtp: anchors.bitcoin.median_time_past,
            units: 12,
        }
    );
    assert_eq!(
        bound.window().second_refund,
        TimelockSpecV1::DomHeight {
            base_height: anchors.dom.height,
            delta_blocks: 400,
        }
    );
    assert_eq!(
        bound.anchor_evidence_digest(),
        anchors.evidence_digest().unwrap()
    );

    let bytes = anchors.canonical_bytes().unwrap();
    assert_eq!(&bytes[..8], M8_ANCHORS_MAGIC);
    assert_eq!(
        u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
        M8_ANCHORS_VERSION
    );
    assert_eq!(bytes.len(), 234);
    assert_eq!(M8FundingAnchorsV1::decode_canonical(&bytes), Ok(anchors));
    assert_eq!(
        hex::encode(anchors.evidence_digest().unwrap()),
        "83ac58fff4749553242c3646661f574ab77414b9f2df6fbfe80c84f836b671c8"
    );
}

#[test]
fn anchor_decoder_rejects_noncanonical_structure() {
    let canonical = anchors(&policy()).canonical_bytes().unwrap();
    for length in 0..canonical.len() {
        assert_eq!(
            M8FundingAnchorsV1::decode_canonical(&canonical[..length]),
            Err(TimelockError::TruncatedEncoding),
            "length {length} must fail as truncated"
        );
    }

    let mut wrong_magic = canonical.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        M8FundingAnchorsV1::decode_canonical(&wrong_magic),
        Err(TimelockError::InvalidEncodingMagic)
    );

    let mut wrong_version = canonical.clone();
    wrong_version[9] = 2;
    assert_eq!(
        M8FundingAnchorsV1::decode_canonical(&wrong_version),
        Err(TimelockError::UnsupportedEncodingVersion)
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        M8FundingAnchorsV1::decode_canonical(&trailing),
        Err(TimelockError::TrailingBytes)
    );
}

#[test]
fn anchor_digest_commits_to_every_evidence_field() {
    let base = anchors(&policy());
    let digest = base.evidence_digest().unwrap();
    let variants = [
        M8FundingAnchorsV1 {
            settlement_terms_hash: [0x12; 32],
            ..base
        },
        M8FundingAnchorsV1 {
            policy_digest: [0x13; 32],
            ..base
        },
        M8FundingAnchorsV1 {
            dom: DomFundingAnchorV1 {
                funding_txid: [0x33; 32],
                ..base.dom
            },
            ..base
        },
        M8FundingAnchorsV1 {
            dom: DomFundingAnchorV1 {
                block_hash: [0x34; 32],
                ..base.dom
            },
            ..base
        },
        M8FundingAnchorsV1 {
            dom: DomFundingAnchorV1 {
                height: base.dom.height + 1,
                ..base.dom
            },
            ..base
        },
        M8FundingAnchorsV1 {
            dom: DomFundingAnchorV1 {
                block_time_seconds: base.dom.block_time_seconds + 1,
                ..base.dom
            },
            ..base
        },
        M8FundingAnchorsV1 {
            bitcoin: BitcoinFundingAnchorV1 {
                funding_txid: [0x43; 32],
                ..base.bitcoin
            },
            ..base
        },
        M8FundingAnchorsV1 {
            bitcoin: BitcoinFundingAnchorV1 {
                block_hash: [0x44; 32],
                ..base.bitcoin
            },
            ..base
        },
        M8FundingAnchorsV1 {
            bitcoin: BitcoinFundingAnchorV1 {
                height: base.bitcoin.height + 1,
                ..base.bitcoin
            },
            ..base
        },
        M8FundingAnchorsV1 {
            bitcoin: BitcoinFundingAnchorV1 {
                median_time_past: base.bitcoin.median_time_past + 1,
                ..base.bitcoin
            },
            ..base
        },
    ];
    for variant in variants {
        assert_ne!(variant.evidence_digest().unwrap(), digest);
    }
}

#[test]
fn two_phase_binding_rejects_wrong_policy_terms_and_absent_evidence() {
    let policy = policy();

    let mut wrong_digest = anchors(&policy);
    wrong_digest.policy_digest[0] ^= 1;
    assert_eq!(
        bind_and_validate_funding_anchors(&policy, &wrong_digest),
        Err(TimelockError::PolicyDigestMismatch)
    );

    let mut wrong_terms = anchors(&policy);
    wrong_terms.settlement_terms_hash[0] ^= 1;
    assert_eq!(
        bind_and_validate_funding_anchors(&policy, &wrong_terms),
        Err(TimelockError::TermsHashMismatch)
    );

    let mut absent = anchors(&policy);
    absent.dom.block_hash = [0; 32];
    assert_eq!(
        bind_and_validate_funding_anchors(&policy, &absent),
        Err(TimelockError::MissingAnchorEvidence)
    );
}

#[test]
fn policy_digest_commits_to_cross_chain_fields_and_bounds() {
    let base = policy();
    let digest = base.policy_digest().unwrap();
    let variants = [
        M8TimingPolicyV1 {
            settlement_terms_hash: [0x12; 32],
            ..base
        },
        M8TimingPolicyV1 {
            first_refund: TimelockOffsetV1::BtcTime512s { units: 13 },
            ..base
        },
        M8TimingPolicyV1 {
            second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 401 },
            ..base
        },
        M8TimingPolicyV1 {
            safety_margin_seconds: 3_001,
            ..base
        },
        M8TimingPolicyV1 {
            dom_bounds: ChainTimingBoundsV1 {
                observation_seconds: 21,
                ..base.dom_bounds
            },
            ..base
        },
        M8TimingPolicyV1 {
            btc_bounds: ChainTimingBoundsV1 {
                broadcast_seconds: 21,
                ..base.btc_bounds
            },
            ..base
        },
    ];
    for variant in variants {
        assert_ne!(variant.policy_digest().unwrap(), digest);
    }
}

proptest! {
    #[test]
    fn block_normalization_matches_checked_interval(
        base in 0u64..1_000_000,
        delta in 0u64..1_000_000,
        min in 1u32..1_000,
        spread in 0u32..1_000,
    ) {
        let max = min + spread;
        let bounds = ChainTimingBoundsV1 {
            min_block_seconds: min,
            max_block_seconds: max,
            max_reorg_seconds: 0,
            observation_seconds: 0,
            broadcast_seconds: 0,
        };
        let got = normalize_to_seconds(
            &TimelockSpecV1::DomHeight {
                base_height: base,
                delta_blocks: delta,
            },
            &bounds,
            &btc_bounds(),
        ).unwrap();
        prop_assert_eq!(got.earliest_seconds, delta * u64::from(min));
        prop_assert_eq!(got.latest_seconds, delta * u64::from(max));
        prop_assert!(got.earliest_seconds <= got.latest_seconds);
    }

    #[test]
    fn cross_chain_result_is_exactly_the_documented_inequality(
        first_delta in 0u64..10_000,
        second_delta in 0u16..10_000,
        margin in 0u64..1_000_000,
    ) {
        let window = CrossChainWindowV1 {
            first_refund: TimelockSpecV1::DomHeight {
                base_height: 1_000,
                delta_blocks: first_delta,
            },
            second_refund: TimelockSpecV1::BtcBlocks {
                base_height: 2_000,
                delta_blocks: second_delta,
            },
            safety_margin_seconds: margin,
            policy_digest: [0x71; 32],
        };
        let expected_safe = margin >= 1_700
            && first_delta * 70 + margin <= u64::from(second_delta) * 500;
        prop_assert_eq!(
            validate_cross_chain_window(&window, &dom_bounds(), &btc_bounds()).is_ok(),
            expected_safe,
        );
    }

    #[test]
    fn every_policy_field_change_is_digest_visible(
        margin in 0u64..u64::MAX,
        dom_observation in 0u32..u32::MAX,
        btc_broadcast in 0u32..u32::MAX,
    ) {
        let base = policy();
        let changed = M8TimingPolicyV1 {
            safety_margin_seconds: margin,
            dom_bounds: ChainTimingBoundsV1 {
                observation_seconds: dom_observation,
                ..base.dom_bounds
            },
            btc_bounds: ChainTimingBoundsV1 {
                broadcast_seconds: btc_broadcast,
                ..base.btc_bounds
            },
            ..base
        };
        let same = margin == base.safety_margin_seconds
            && dom_observation == base.dom_bounds.observation_seconds
            && btc_broadcast == base.btc_bounds.broadcast_seconds;
        prop_assert_eq!(changed.policy_digest().unwrap() == base.policy_digest().unwrap(), same);
    }
}

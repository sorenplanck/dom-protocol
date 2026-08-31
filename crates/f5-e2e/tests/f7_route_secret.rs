//! F7 route-binding proof for the Bitcoin adaptor claim.
//!
//! The claim uses the same externally supplied `(t, T)` pair as the DOM leg,
//! enters nonce generation only through the M.8 gate, and exports `t` only
//! after receiving the byte-exact confirmed transaction.

use std::path::PathBuf;

use adapter_btc::timelock::{
    bind_and_validate_funding_anchors, BitcoinFinalityPolicyV1, BitcoinFundingAnchorV1,
    ChainTimingBoundsV1, DomFundingAnchorV1, M8FundingAnchorsV1, M8TimingPolicyV1,
    TimelockOffsetV1,
};
use adapter_btc::types::BitcoinNetworkV1;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use btc_vault::BitcoinNonceSealKeyV1;
use counterparty_api::{AdaptorPointBytes, RevealedSecretBytes};
use f5_e2e::{
    adapt_prepared_route_claim, build_regtest_route_claim_durable_after_m8,
    extract_revealed_secret_from_confirmed_claim, prepare_regtest_route_claim_durable_after_m8,
    restore_route_claim_artifacts_from_durable_continuation, verify_claim_witness, FundingRef,
};

fn seal_key(value: u8) -> BitcoinNonceSealKeyV1 {
    BitcoinNonceSealKeyV1::new([value; 32]).unwrap()
}

fn temporary_vault(label: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "f7-route-{label}-{}-{nonce}.sqlite",
        std::process::id()
    ))
}

fn remove_vault(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

fn assert_secret_not_persisted(path: &std::path::Path, secret: &[u8; 32]) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if let Ok(bytes) = std::fs::read(&candidate) {
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "route secret was persisted in {}",
                candidate.display()
            );
        }
    }
}

fn authorization(terms_hash: [u8; 32]) -> adapter_btc::timelock::AnchoredCrossChainWindowV1 {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 60,
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
    };
    let policy = M8TimingPolicyV1 {
        settlement_terms_hash: terms_hash,
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
            policy_id: [0x15; 32],
            version: 1,
        },
    };
    let anchors = M8FundingAnchorsV1 {
        settlement_terms_hash: terms_hash,
        policy_digest: policy.policy_digest().unwrap(),
        dom: DomFundingAnchorV1 {
            funding_txid: [0x16; 32],
            block_hash: [0x17; 32],
            height: 500,
            block_time_seconds: 1_700_000_000,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: [0x18; 32],
            block_hash: [0x19; 32],
            height: 1_000,
            median_time_past: 1_700_000_000,
        },
    };
    bind_and_validate_funding_anchors(&policy, &anchors).unwrap()
}

fn point(secret: &RevealedSecretBytes) -> AdaptorPointBytes {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&secret.expose_scalar_bytes()).unwrap();
    AdaptorPointBytes(PublicKey::from_secret_key(&secp, &key).serialize())
}

#[test]
fn same_route_secret_crosses_the_m8_gated_claim_and_delayed_extraction() {
    let terms_hash = [0x13; 32];
    let revealed = RevealedSecretBytes::new([0x2b; 32]);
    let adaptor_point = point(&revealed);
    let funding = FundingRef {
        txid: [0x91; 32],
        vout: 0,
        amount_sat: 50_000_000,
    };
    let mut destination = vec![0x00, 0x14];
    destination.extend_from_slice(&[0xcd; 20]);
    let vault_one = temporary_vault("one");
    let vault_two = temporary_vault("two");
    let seal_one = seal_key(0x61);
    let seal_two = seal_key(0x62);
    let prepared = prepare_regtest_route_claim_durable_after_m8(
        &funding,
        &destination,
        1_000,
        [0x10; 32],
        [0x11; 32],
        terms_hash,
        &adaptor_point,
        [authorization(terms_hash), authorization(terms_hash)],
        &seal_one,
        &seal_two,
        &vault_one,
        &vault_two,
    )
    .unwrap();
    assert_eq!(prepared.adaptor_point(), adaptor_point);
    let continuation = prepared.durable_continuation_bytes().unwrap();
    let prepared = f5_e2e::PreparedBitcoinRouteClaimV1::from_durable_continuation_bytes(
        &continuation,
        [0x10; 32],
        [0x11; 32],
        terms_hash,
        &adaptor_point,
    )
    .unwrap();
    let result = adapt_prepared_route_claim(prepared, &revealed).unwrap();
    let restored = restore_route_claim_artifacts_from_durable_continuation(
        &continuation,
        &result.claim.raw_transaction,
        [0x10; 32],
        [0x11; 32],
        terms_hash,
        &adaptor_point,
    )
    .unwrap();
    assert_eq!(restored.claim.raw_transaction, result.claim.raw_transaction);
    assert_eq!(restored.claim.template_digest, result.claim.template_digest);

    assert!(verify_claim_witness(
        &result.claim.raw_transaction,
        &funding,
        &destination,
        1_000
    ));
    assert_eq!(result.claim.adaptor_point, adaptor_point.0);
    assert!(result.claim.extraction_deferred_until_confirmation);
    assert!(!result.claim.extracted_t_opens_adaptor_point);
    assert_eq!(
        extract_revealed_secret_from_confirmed_claim(
            &result.extraction,
            &result.claim.raw_transaction
        )
        .unwrap(),
        revealed
    );

    let mut different_witness = result.claim.raw_transaction.clone();
    let last = different_witness.len() - 1;
    different_witness[last] ^= 1;
    assert!(
        extract_revealed_secret_from_confirmed_claim(&result.extraction, &different_witness)
            .is_err()
    );

    assert_secret_not_persisted(&vault_one, &revealed.expose_scalar_bytes());
    assert_secret_not_persisted(&vault_two, &revealed.expose_scalar_bytes());

    remove_vault(&vault_one);
    remove_vault(&vault_two);
}

#[test]
fn prepared_route_continuation_rejects_tamper_and_cross_route_replay() {
    let terms_hash = [0x33; 32];
    let secret = RevealedSecretBytes::new([0x2b; 32]);
    let adaptor_point = point(&secret);
    let funding = FundingRef {
        txid: [0xa2; 32],
        vout: 0,
        amount_sat: 2_000_000,
    };
    let vault_one = temporary_vault("continuation-one");
    let vault_two = temporary_vault("continuation-two");
    let seal_one = seal_key(0x63);
    let seal_two = seal_key(0x64);
    let prepared = prepare_regtest_route_claim_durable_after_m8(
        &funding,
        &[0x51],
        1_000,
        [0x41; 32],
        [0x42; 32],
        terms_hash,
        &adaptor_point,
        [authorization(terms_hash), authorization(terms_hash)],
        &seal_one,
        &seal_two,
        &vault_one,
        &vault_two,
    )
    .unwrap();
    let continuation = prepared.durable_continuation_bytes().unwrap();

    let mut tampered = continuation.clone();
    tampered[100] ^= 1;
    assert!(
        f5_e2e::PreparedBitcoinRouteClaimV1::from_durable_continuation_bytes(
            &tampered,
            [0x41; 32],
            [0x42; 32],
            terms_hash,
            &adaptor_point,
        )
        .is_err()
    );
    assert!(
        f5_e2e::PreparedBitcoinRouteClaimV1::from_durable_continuation_bytes(
            &continuation,
            [0x51; 32],
            [0x42; 32],
            terms_hash,
            &adaptor_point,
        )
        .is_err()
    );

    remove_vault(&vault_one);
    remove_vault(&vault_two);
}

#[test]
fn prepared_route_rejects_a_secret_revealed_by_another_route() {
    let terms_hash = [0x13; 32];
    let expected = RevealedSecretBytes::new([0x2b; 32]);
    let wrong_route = RevealedSecretBytes::new([0x2c; 32]);
    let funding = FundingRef {
        txid: [0x92; 32],
        vout: 1,
        amount_sat: 50_000_000,
    };
    let vault_one = temporary_vault("replay-one");
    let vault_two = temporary_vault("replay-two");
    let seal_one = seal_key(0x65);
    let seal_two = seal_key(0x66);
    let prepared = prepare_regtest_route_claim_durable_after_m8(
        &funding,
        &[0x51],
        1_000,
        [0x20; 32],
        [0x21; 32],
        terms_hash,
        &point(&expected),
        [authorization(terms_hash), authorization(terms_hash)],
        &seal_one,
        &seal_two,
        &vault_one,
        &vault_two,
    )
    .unwrap();

    let error = adapt_prepared_route_claim(prepared, &wrong_route).unwrap_err();
    assert!(error.contains("does not open"));
    assert!(vault_one.exists());
    assert!(vault_two.exists());

    remove_vault(&vault_one);
    remove_vault(&vault_two);
}

#[test]
fn mismatched_t_and_t_point_fail_before_vault_creation() {
    let terms_hash = [0x13; 32];
    let revealed = RevealedSecretBytes::new([0x2b; 32]);
    let other_point = point(&RevealedSecretBytes::new([0x2c; 32]));
    let funding = FundingRef {
        txid: [0x91; 32],
        vout: 0,
        amount_sat: 50_000_000,
    };
    let vault_one = temporary_vault("wrong-one");
    let vault_two = temporary_vault("wrong-two");
    let seal_one = seal_key(0x67);
    let seal_two = seal_key(0x68);
    let error = build_regtest_route_claim_durable_after_m8(
        &funding,
        &[0x51],
        1_000,
        [0x10; 32],
        [0x11; 32],
        terms_hash,
        &revealed,
        &other_point,
        [authorization(terms_hash), authorization(terms_hash)],
        &seal_one,
        &seal_two,
        &vault_one,
        &vault_two,
    )
    .unwrap_err();
    assert!(error.contains("does not open"));
    assert!(!vault_one.exists());
    assert!(!vault_two.exists());
}

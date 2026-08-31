#![cfg(target_os = "linux")]

//! Two-process-equivalent MuSig2 adaptor claim with one key and vault each.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;

use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
use adapter_btc::taproot::build_taproot_contract;
use adapter_btc::templates::{
    frozen_template_digest_v1, BitcoinPrevoutV1, BitcoinTxInV1, BitcoinTxOutV1,
    FrozenBitcoinTemplateV1,
};
use adapter_btc::timelock::{
    bind_and_validate_funding_anchors, AnchoredCrossChainWindowV1, BitcoinCsvDelayV1,
    BitcoinFinalityPolicyV1, BitcoinFundingAnchorV1, ChainTimingBoundsV1, DomFundingAnchorV1,
    M8FundingAnchorsV1, M8TimingPolicyV1, TimelockOffsetV1,
};
use adapter_btc::types::BitcoinNetworkV1;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use btc_actuator::{
    BitcoinActionV1, BitcoinActuationScopeAuthorizationV1, BitcoinActuationScopeV1,
    BitcoinActuatorErrorV1, BitcoinAdaptorSecretV1, BitcoinClaimSessionV1,
    BitcoinClaimSigningContextV1, BitcoinFeeBumpPolicyV1, BitcoinLegV1, BitcoinOutpointV1,
    BitcoinParticipantClaimAuthorityRequestV1, BitcoinParticipantClaimAuthorityV1,
    BitcoinParticipantNonceVaultV1, BitcoinParticipantRoleV1, DurableBitcoinActuatorV1,
};
use btc_crypto::SecpContext;
use btc_vault::BitcoinNonceSealKeyV1;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1, ChainDeploymentV1,
    DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryValidationPolicyV1,
    ResolvedBitcoinDeploymentV1, SignedRegistryV1,
};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use rusqlite::Connection;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ROUTE: [u8; 32] = [0xa1; 32];
const EFFECT: [u8; 32] = [0xa2; 32];
const TERMS: [u8; 32] = [0xa3; 32];
const FUNDING_TXID: [u8; 32] = [0xa4; 32];
const FUNDING_VOUT: u32 = 1;
const FUNDING_AMOUNT: u64 = 200_000;
const CLAIM_FEE: u64 = 2_000;
const DOM_CHAIN: ChainId = ChainId([
    0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42, 0xf7,
    0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6, 0x98, 0xe1,
]);
const DOM_GENESIS: [u8; 32] = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];

fn timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 5,
        max_block_seconds: 20,
        max_reorg_seconds: 200,
        observation_seconds: 30,
        broadcast_seconds: 20,
    }
}

fn finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 3,
    }
}

fn deployment() -> TestResult<ResolvedBitcoinDeploymentV1> {
    let btc_chain = ChainId([0x02; 32]);
    let dom_asset = AssetId([0x11; 32]);
    let btc_asset = AssetId([0x12; 32]);
    let manifest = RegistryManifestV1 {
        network_id: [0xb1; 32],
        epoch: 9,
        valid_from: 1_000,
        expires_at: 9_000,
        dom: DomDeploymentV1 {
            chain_id: DOM_CHAIN,
            genesis_hash: DOM_GENESIS,
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: [0xb3; 32],
            scriptless_api_version: 1,
            timing: timing(),
            finality: finality(),
            native_asset: dom_asset,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: btc_chain,
                kind: ChainKindV1::Bitcoin {
                    network: BitcoinNetworkV1::Regtest,
                },
                timing: timing(),
                finality: finality(),
                native_asset: btc_asset,
                allowed_assets: vec![],
            },
            deployment: ChainDeploymentV1::Bitcoin(BitcoinDeploymentV1 {
                genesis_hash: genesis_block(Network::Regtest)
                    .block_hash()
                    .to_raw_hash()
                    .to_byte_array(),
                signet_challenge: vec![],
                max_fee_rate_sat_vbyte: 100,
                min_relay_fee_sat_kvb: 1_000,
            }),
        }],
        assets: vec![
            AssetBindingV1 {
                chain_id: btc_chain,
                asset_id: btc_asset,
                decimals: 8,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: DOM_CHAIN,
                asset_id: dom_asset,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
        ],
    };
    let crypto = SecpContext::new(&[0xb4; 32]);
    let digest = manifest.manifest_digest()?;
    let (signature, public_key) = crypto.sign_bip340(&[0xb5; 32], &digest, &[0xb6; 32])?;
    let authorities = AuthoritySetV1::new(1, vec![public_key])?;
    let signed = SignedRegistryV1::new(
        &manifest,
        vec![RegistrySignatureV1 {
            signer_index: 0,
            signature,
        }],
    )?;
    let resolved = signed.verify(
        &authorities,
        &crypto,
        RegistryValidationPolicyV1 {
            now_seconds: 2_000,
            expected_network_id: [0xb1; 32],
            minimum_epoch: 9,
        },
    )?;
    Ok(resolved
        .resolve_chain(btc_chain)
        .ok_or("missing Bitcoin profile")?
        .bitcoin_deployment_capability()?)
}

fn compressed(secret: [u8; 32]) -> TestResult<[u8; 33]> {
    let context = Secp256k1::new();
    let secret = SecretKey::from_slice(&secret)?;
    Ok(PublicKey::from_secret_key(&context, &secret).serialize())
}

fn m8_authorization() -> TestResult<AnchoredCrossChainWindowV1> {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 60,
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
    };
    let policy = M8TimingPolicyV1 {
        settlement_terms_hash: TERMS,
        first_refund: TimelockOffsetV1::BtcBlocks { delta_blocks: 10 },
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 30 },
        safety_margin_seconds: 10,
        dom_bounds: bounds,
        btc_bounds: bounds,
        bitcoin_finality: BitcoinFinalityPolicyV1 {
            network: BitcoinNetworkV1::Regtest,
            minimum_confirmations: 2,
            maximum_reorg_depth: 3,
            require_header_chain: true,
            require_witness_commitment: true,
            policy_id: [0xc1; 32],
            version: 1,
        },
    };
    let anchors = M8FundingAnchorsV1 {
        settlement_terms_hash: TERMS,
        policy_digest: policy.policy_digest()?,
        dom: DomFundingAnchorV1 {
            funding_txid: [0xc2; 32],
            block_hash: [0xc3; 32],
            height: 500,
            block_time_seconds: 1_700_000_000,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: FUNDING_TXID,
            block_hash: [0xc4; 32],
            height: 1_000,
            median_time_past: 1_700_000_000,
        },
    };
    Ok(bind_and_validate_funding_anchors(&policy, &anchors)?)
}

fn session_and_scope(
    deployment: &ResolvedBitcoinDeploymentV1,
    roster: ParticipantKeyRosterV1,
    refund_xonly: [u8; 32],
    adaptor_point: [u8; 33],
) -> TestResult<(BitcoinClaimSessionV1, BitcoinActuationScopeV1)> {
    let crypto = SecpContext::new(&[0xd1; 32]);
    let refund_delay = BitcoinCsvDelayV1::Blocks(144);
    let contract = build_taproot_contract(&crypto, &roster, &refund_xonly, refund_delay)?;
    let destination = vec![0x51, 0x20, 0xd2];
    let template = FrozenBitcoinTemplateV1 {
        codec_version: 1,
        network: BitcoinNetworkV1::Regtest,
        version: Version::TWO.0,
        lock_time: LockTime::ZERO.to_consensus_u32(),
        inputs: vec![BitcoinTxInV1 {
            txid: FUNDING_TXID,
            vout: FUNDING_VOUT,
            sequence: Sequence::MAX.to_consensus_u32(),
        }],
        outputs: vec![BitcoinTxOutV1 {
            amount_sat: FUNDING_AMOUNT - CLAIM_FEE,
            script_pubkey: destination.clone(),
        }],
        prevouts: vec![BitcoinPrevoutV1 {
            txid: FUNDING_TXID,
            vout: FUNDING_VOUT,
            amount_sat: FUNDING_AMOUNT,
            script_pubkey: contract.script_pubkey.clone(),
        }],
    };
    let expected_template_hash = frozen_template_digest_v1(&template)?;
    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    FUNDING_TXID,
                )),
                vout: FUNDING_VOUT,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(FUNDING_AMOUNT - CLAIM_FEE),
            script_pubkey: ScriptBuf::from_bytes(destination.clone()),
        }],
    };
    let expected_txid = unsigned.compute_txid().to_raw_hash().to_byte_array();
    let policy = BitcoinFeeBumpPolicyV1 {
        initial_fee_sat: CLAIM_FEE,
        maximum_fee_sat: CLAIM_FEE,
        maximum_fee_rate_sat_vbyte: 100,
        change_vout: None,
    };
    let preliminary = BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
        deployment,
        route_id: ROUTE,
        effect_id: EFFECT,
        leg: BitcoinLegV1::Downstream,
        action: BitcoinActionV1::Claim,
        fence_epoch: 1,
        terms_digest: TERMS,
        expected_txid,
        intent_digest: [0xd3; 32],
        contract_outpoint: Some(BitcoinOutpointV1 {
            txid: FUNDING_TXID,
            vout: FUNDING_VOUT,
        }),
        contract_amount_sat: FUNDING_AMOUNT,
        refund_record_digest: None,
        fee_policy: policy,
        valid_until_ms: 10_000,
    })?;
    let session = BitcoinClaimSessionV1 {
        route_id: ROUTE,
        effect_id: EFFECT,
        fence_epoch: 1,
        settlement_id: [0xd4; 32],
        session_id: [0xd5; 32],
        terms_digest: TERMS,
        registry_digest: deployment.registry_digest(),
        profile_digest: deployment.profile_digest(),
        deployment_digest: preliminary.deployment_digest(),
        network: BitcoinNetworkV1::Regtest,
        roster,
        funding_txid: FUNDING_TXID,
        funding_vout: FUNDING_VOUT,
        funding_amount_sat: FUNDING_AMOUNT,
        contract_script_pubkey: contract.script_pubkey,
        refund_key_xonly: refund_xonly,
        refund_delay,
        destination_script_pubkey: destination,
        fee_sat: CLAIM_FEE,
        expected_template_hash,
        adaptor_point,
        attempt: 0,
    };
    let signing_scope = BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
        deployment,
        route_id: ROUTE,
        effect_id: EFFECT,
        leg: BitcoinLegV1::Downstream,
        action: BitcoinActionV1::Claim,
        fence_epoch: 1,
        terms_digest: TERMS,
        expected_txid,
        intent_digest: session.session_digest()?,
        contract_outpoint: Some(BitcoinOutpointV1 {
            txid: FUNDING_TXID,
            vout: FUNDING_VOUT,
        }),
        contract_amount_sat: FUNDING_AMOUNT,
        refund_record_digest: None,
        fee_policy: policy,
        valid_until_ms: 10_000,
    })?;
    Ok((session, signing_scope))
}

#[test]
fn two_participant_stores_complete_claim_without_combining_keys() -> TestResult {
    let deployment = deployment()?;
    let mut maker_secret = [0x11; 32];
    let mut taker_secret = [0x22; 32];
    let mut adaptor_secret = [0x2b; 32];
    let maker_public = compressed(maker_secret)?;
    let taker_public = compressed(taker_secret)?;
    let maker = BitcoinParticipantClaimAuthorityV1::authorize_local_key(
        BitcoinParticipantClaimAuthorityRequestV1 {
            deployment: &deployment,
            route_id: ROUTE,
            terms_digest: TERMS,
            participant_id: [0x01; 32],
            role: BitcoinParticipantRoleV1::Maker,
            expected_public_key: maker_public,
        },
        &mut maker_secret,
    )?;
    let taker = BitcoinParticipantClaimAuthorityV1::authorize_local_key(
        BitcoinParticipantClaimAuthorityRequestV1 {
            deployment: &deployment,
            route_id: ROUTE,
            terms_digest: TERMS,
            participant_id: [0x02; 32],
            role: BitcoinParticipantRoleV1::Taker,
            expected_public_key: taker_public,
        },
        &mut taker_secret,
    )?;
    let roster = ParticipantKeyRosterV1::new([
        ParticipantKeyV1 {
            participant_id: maker.participant_id(),
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: maker.public_key(),
        },
        ParticipantKeyV1 {
            participant_id: taker.participant_id(),
            role: BitcoinSignerRoleV1::Taker,
            compressed_key: taker.public_key(),
        },
    ])?;
    let refund_key = compressed([0x33; 32])?;
    let refund_xonly: [u8; 32] = refund_key[1..].try_into()?;
    assert_eq!(maker_secret, [0; 32]);
    assert_eq!(taker_secret, [0; 32]);
    let adaptor_point = compressed([0x2b; 32])?;
    let (session, signing_scope) =
        session_and_scope(&deployment, roster, refund_xonly, adaptor_point)?;

    let maker_directory = tempfile::tempdir()?;
    let taker_directory = tempfile::tempdir()?;
    std::fs::set_permissions(
        maker_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )?;
    std::fs::set_permissions(
        taker_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let maker_store_path = maker_directory.path().join("actuator.sqlite");
    let taker_store_path = taker_directory.path().join("actuator.sqlite");
    let maker_vault_path = maker_directory.path().join("nonce.sqlite");
    let taker_vault_path = taker_directory.path().join("nonce.sqlite");
    let mut maker_vault = BitcoinParticipantNonceVaultV1::create(&maker_vault_path, &maker)?;
    let mut taker_vault = BitcoinParticipantNonceVaultV1::create(&taker_vault_path, &taker)?;
    let mut maker_store = DurableBitcoinActuatorV1::create(&maker_store_path, [0xe1; 32])?;
    let mut taker_store = DurableBitcoinActuatorV1::create(&taker_store_path, [0xe2; 32])?;
    maker_store.acquire_lease(100, 50)?;
    taker_store.acquire_lease(100, 1_000)?;
    let maker_seal = BitcoinNonceSealKeyV1::new([0xe3; 32])?;
    let taker_seal = BitcoinNonceSealKeyV1::new([0xe4; 32])?;

    let maker_nonce = maker_store.expose_claim_pubnonce(BitcoinClaimSigningContextV1 {
        scope: &signing_scope,
        authority: &maker,
        session: &session,
        authorization: m8_authorization()?,
        seal_key: &maker_seal,
        participant_state: &mut maker_vault,
        now_ms: 101,
    })?;
    let taker_nonce = taker_store.expose_claim_pubnonce(BitcoinClaimSigningContextV1 {
        scope: &signing_scope,
        authority: &taker,
        session: &session,
        authorization: m8_authorization()?,
        seal_key: &taker_seal,
        participant_state: &mut taker_vault,
        now_ms: 101,
    })?;
    assert_ne!(maker_nonce.bytes(), taker_nonce.bytes());

    // The maker store is permanently bound to the maker participant before
    // any remote authority can touch its nonce vault.
    assert!(matches!(
        maker_store.expose_claim_pubnonce(BitcoinClaimSigningContextV1 {
            scope: &signing_scope,
            authority: &taker,
            session: &session,
            authorization: m8_authorization()?,
            seal_key: &taker_seal,
            participant_state: &mut maker_vault,
            now_ms: 102,
        }),
        Err(BitcoinActuatorErrorV1::IdempotencyConflict)
            | Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch)
    ));
    drop(maker_store);
    drop(maker_vault);
    let mut maker_vault = BitcoinParticipantNonceVaultV1::open_existing(&maker_vault_path, &maker)?;
    let mut maker_store = DurableBitcoinActuatorV1::open_existing(&maker_store_path, [0xe5; 32])?;
    assert_eq!(maker_store.acquire_lease(151, 1_000)?.fence_epoch(), 2);
    let mut maker_session = session.clone();
    maker_session.fence_epoch = 2;
    let maker_signing_scope =
        BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
            deployment: &deployment,
            route_id: ROUTE,
            effect_id: EFFECT,
            leg: BitcoinLegV1::Downstream,
            action: BitcoinActionV1::Claim,
            fence_epoch: 2,
            terms_digest: TERMS,
            expected_txid: signing_scope.expected_txid(),
            intent_digest: maker_session.session_digest()?,
            contract_outpoint: Some(BitcoinOutpointV1 {
                txid: FUNDING_TXID,
                vout: FUNDING_VOUT,
            }),
            contract_amount_sat: FUNDING_AMOUNT,
            refund_record_digest: None,
            fee_policy: BitcoinFeeBumpPolicyV1 {
                initial_fee_sat: CLAIM_FEE,
                maximum_fee_sat: CLAIM_FEE,
                maximum_fee_rate_sat_vbyte: 100,
                change_vout: None,
            },
            valid_until_ms: 20_000,
        })?;
    maker_store.reconcile_claim_takeover(&maker_signing_scope, &maker, &maker_session, 152)?;
    assert_eq!(
        maker_store
            .expose_claim_pubnonce(BitcoinClaimSigningContextV1 {
                scope: &maker_signing_scope,
                authority: &maker,
                session: &maker_session,
                authorization: m8_authorization()?,
                seal_key: &maker_seal,
                participant_state: &mut maker_vault,
                now_ms: 153,
            })?
            .bytes(),
        maker_nonce.bytes()
    );

    let maker_partial = maker_store.produce_claim_partial(
        BitcoinClaimSigningContextV1 {
            scope: &maker_signing_scope,
            authority: &maker,
            session: &maker_session,
            authorization: m8_authorization()?,
            seal_key: &maker_seal,
            participant_state: &mut maker_vault,
            now_ms: 154,
        },
        taker_nonce.bytes(),
    )?;
    let mut equivocated_nonce = taker_nonce.bytes();
    equivocated_nonce[65] ^= 1;
    assert!(matches!(
        maker_store.produce_claim_partial(
            BitcoinClaimSigningContextV1 {
                scope: &maker_signing_scope,
                authority: &maker,
                session: &maker_session,
                authorization: m8_authorization()?,
                seal_key: &maker_seal,
                participant_state: &mut maker_vault,
                now_ms: 155,
            },
            equivocated_nonce,
        ),
        Err(BitcoinActuatorErrorV1::IdempotencyConflict)
    ));
    let taker_partial = taker_store.produce_claim_partial(
        BitcoinClaimSigningContextV1 {
            scope: &signing_scope,
            authority: &taker,
            session: &session,
            authorization: m8_authorization()?,
            seal_key: &taker_seal,
            participant_state: &mut taker_vault,
            now_ms: 105,
        },
        maker_nonce.bytes(),
    )?;
    let maker_partial_bytes = maker_partial.into_bytes();
    let taker_partial_bytes = taker_partial.into_bytes();
    let maker_pre_signature = maker_store.aggregate_claim_pre_signature(
        BitcoinClaimSigningContextV1 {
            scope: &maker_signing_scope,
            authority: &maker,
            session: &maker_session,
            authorization: m8_authorization()?,
            seal_key: &maker_seal,
            participant_state: &mut maker_vault,
            now_ms: 155,
        },
        taker_nonce.bytes(),
        taker_partial_bytes,
    )?;
    let mut equivocated_partial = taker_partial_bytes;
    equivocated_partial[0] ^= 1;
    assert!(matches!(
        maker_store.aggregate_claim_pre_signature(
            BitcoinClaimSigningContextV1 {
                scope: &maker_signing_scope,
                authority: &maker,
                session: &maker_session,
                authorization: m8_authorization()?,
                seal_key: &maker_seal,
                participant_state: &mut maker_vault,
                now_ms: 156,
            },
            taker_nonce.bytes(),
            equivocated_partial,
        ),
        Err(BitcoinActuatorErrorV1::IdempotencyConflict)
    ));
    let taker_pre_signature = taker_store.aggregate_claim_pre_signature(
        BitcoinClaimSigningContextV1 {
            scope: &signing_scope,
            authority: &taker,
            session: &session,
            authorization: m8_authorization()?,
            seal_key: &taker_seal,
            participant_state: &mut taker_vault,
            now_ms: 106,
        },
        maker_nonce.bytes(),
        maker_partial_bytes,
    )?;
    assert_eq!(
        maker_pre_signature.session_digest(),
        taker_pre_signature.session_digest()
    );
    let exact = maker_pre_signature.finalize_claim(BitcoinAdaptorSecretV1::verify(
        &mut adaptor_secret,
        adaptor_point,
    )?)?;
    assert_eq!(adaptor_secret, [0; 32]);
    assert_eq!(exact.txid(), signing_scope.expected_txid());
    let final_scope = BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
        deployment: &deployment,
        route_id: ROUTE,
        effect_id: EFFECT,
        leg: BitcoinLegV1::Downstream,
        action: BitcoinActionV1::Claim,
        fence_epoch: 2,
        terms_digest: TERMS,
        expected_txid: exact.txid(),
        intent_digest: exact.intent_digest(),
        contract_outpoint: Some(BitcoinOutpointV1 {
            txid: FUNDING_TXID,
            vout: FUNDING_VOUT,
        }),
        contract_amount_sat: FUNDING_AMOUNT,
        refund_record_digest: None,
        fee_policy: BitcoinFeeBumpPolicyV1 {
            initial_fee_sat: CLAIM_FEE,
            maximum_fee_sat: CLAIM_FEE,
            maximum_fee_rate_sat_vbyte: 100,
            change_vout: None,
        },
        valid_until_ms: 20_000,
    })?;
    maker_store.prepare_terminal(&final_scope, exact, 157)?;
    drop(maker_store);
    drop(taker_store);

    // A persisted transcript cannot be promoted or truncated behind the
    // actuator's retained authority. Every subsequent open replays its exact
    // field progression before exposing any operation.
    let connection = Connection::open(&maker_store_path)?;
    connection.execute(
        "UPDATE claim_transcripts SET remote_partial=NULL WHERE effect_id=?1",
        [EFFECT.as_slice()],
    )?;
    drop(connection);
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&maker_store_path, [0xe6; 32]),
        Err(BitcoinActuatorErrorV1::CorruptState)
    ));
    Ok(())
}

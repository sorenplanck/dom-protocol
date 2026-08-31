#![cfg(any(feature = "development", feature = "simulation"))]

use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_evm::{binding::adaptor_point_of_scalar, Direction};
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, ChainDeploymentV1, DomDeploymentV1,
    DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, EvmSessionBindingsV1,
    RegistryChainProfileV1, RegistryManifestV1, RegistrySignatureV1, RegistryStoreV1,
    RegistryValidationPolicyV1, SignedRegistryV1,
};
use dom_interopd::{
    AuthenticatedRouteAdmissionV1, RegistryRouteAdmissionAuthorityV1, RouteAdmissionRefusalV1,
    RouteAdmissionRequestV1, RouteLegSelectionV1, RouteRosterSnapshotsV1,
};
#[cfg(feature = "development")]
use dom_interopd::{
    ManualClockV1, RouteSupervisorConfigV1, RouteSupervisorErrorV1, RouteSupervisorV1,
};
use k256::ecdsa::SigningKey;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1, LockMechanism,
    ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
};
use participant_binding::{
    bind_evm_session_v1, evm_account_binding_digest_v1, verify_evm_account_binding_v1,
    EvmAccountBindingProofV1, EvmAccountBindingStatementV1, EvmBindingRoleV1,
    EvmSettlementPositionV1, EVM_ACCOUNT_SIGNATURE_BYTES_V1,
};
use route_composer::{ComposedBindingV1, ComposedWindowPolicyV1};
use route_executor::LegIdV1;
#[cfg(feature = "development")]
use route_executor::{CommitOutcomeV1, DurableRouteStoreV1};
use sha3::{Digest, Keccak256};

const NETWORK: [u8; 32] = [0x90; 32];
const DOM_CHAIN: ChainId = ChainId([
    0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42, 0xf7,
    0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6, 0x98, 0xe1,
]);
const DOM_GENESIS: [u8; 32] = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];
const EVM_CHAIN: ChainId = ChainId([0x02; 32]);
const DOM_ASSET: AssetId = AssetId([0x11; 32]);
const EVM_NATIVE: AssetId = AssetId([0x12; 32]);
const EVM_TOKEN: AssetId = AssetId([0x13; 32]);
const AUTHORITY_SECRET: [u8; 32] = [0x03; 32];
const ROSTER_SNAPSHOT: [u8; 32] = [0x95; 32];

fn route_rosters() -> RouteRosterSnapshotsV1 {
    RouteRosterSnapshotsV1 {
        upstream: ROSTER_SNAPSHOT,
        downstream: ROSTER_SNAPSHOT,
    }
}

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

fn manifest(epoch: u64) -> RegistryManifestV1 {
    RegistryManifestV1 {
        network_id: NETWORK,
        epoch,
        valid_from: 1_000,
        expires_at: 10_000,
        dom: DomDeploymentV1 {
            chain_id: DOM_CHAIN,
            genesis_hash: DOM_GENESIS,
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: [0x22; 32],
            scriptless_api_version: 1,
            timing: timing(),
            finality: finality(),
            native_asset: DOM_ASSET,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: EVM_CHAIN,
                kind: ChainKindV1::Evm {
                    evm_chain_id: 31_337,
                    native_lock_contract: [0x31; 20],
                    native_code_hash: [0x32; 32],
                    erc20_lock_contract: Some(([0x33; 20], [0x34; 32])),
                },
                timing: timing(),
                finality: finality(),
                native_asset: EVM_NATIVE,
                allowed_assets: vec![EVM_TOKEN],
            },
            deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                genesis_hash: [0x35; 32],
                native_start_block: 10,
                erc20_start_block: Some(11),
                abi_digest: [0x36; 32],
                compiler_digest: [0x37; 32],
                source_digest: [0x38; 32],
                deployment_digest: [epoch as u8; 32],
                finalized_tag_required: true,
                page_size: 256,
                gas_limit_hint: 300_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 2_000_000_000,
            }),
        }],
        assets: vec![
            AssetBindingV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_NATIVE,
                decimals: 18,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_TOKEN,
                decimals: 6,
                representation: AssetRepresentationV1::EvmErc20 {
                    token: [0x42; 20],
                    token_code_hash: [0x43; 32],
                },
            },
            AssetBindingV1 {
                chain_id: DOM_CHAIN,
                asset_id: DOM_ASSET,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
        ],
    }
}

fn signed(
    manifest: &RegistryManifestV1,
    secp: &SecpContext,
    nonce: u8,
) -> (AuthoritySetV1, SignedRegistryV1) {
    let digest = manifest.manifest_digest().unwrap();
    let (signature, key) = secp
        .sign_bip340(&AUTHORITY_SECRET, &digest, &[nonce; 32])
        .unwrap();
    (
        AuthoritySetV1::new(1, vec![key]).unwrap(),
        SignedRegistryV1::new(
            manifest,
            vec![RegistrySignatureV1 {
                signer_index: 0,
                signature,
            }],
        )
        .unwrap(),
    )
}

fn request() -> RouteAdmissionRequestV1 {
    RouteAdmissionRequestV1 {
        route_id: [0x51; 32],
        base_terms_digest: [0x52; 32],
        dom: RouteLegSelectionV1 {
            chain_id: DOM_CHAIN,
            asset_id: DOM_ASSET,
        },
        upstream: RouteLegSelectionV1 {
            chain_id: EVM_CHAIN,
            asset_id: EVM_NATIVE,
        },
        downstream: RouteLegSelectionV1 {
            chain_id: EVM_CHAIN,
            asset_id: EVM_TOKEN,
        },
    }
}

fn session(terms_hash: [u8; 32]) -> EvmSessionBindingsV1 {
    EvmSessionBindingsV1 {
        direction: Direction::DomToEvm,
        session_id: [0x61; 32],
        terms_hash,
        participants_hash: [0x62; 32],
        beneficiary: [0x63; 20],
        funder: [0x64; 20],
    }
}

struct AccountProofFixture {
    proof: EvmAccountBindingProofV1,
    xonly: [u8; 32],
    account: [u8; 20],
}

struct AccountProofSecrets {
    evm: [u8; 32],
    participant: [u8; 32],
}

fn account_proof(
    admission: &AuthenticatedRouteAdmissionV1,
    terms: &SettlementTermsV1,
    route_id: [u8; 32],
    position: EvmSettlementPositionV1,
    role: EvmBindingRoleV1,
    participant_id: ParticipantId,
    secrets: AccountProofSecrets,
) -> AccountProofFixture {
    let signing = SigningKey::from_slice(&secrets.evm).unwrap();
    let public = signing.verifying_key().to_encoded_point(false);
    let account_hash: [u8; 32] = Keccak256::digest(&public.as_bytes()[1..]).into();
    let mut account = [0; 20];
    account.copy_from_slice(&account_hash[12..]);
    let secp = SecpContext::new(&[0x96; 32]);
    let (_, xonly) = secp
        .sign_bip340(&secrets.participant, &[0x97; 32], &[0x98; 32])
        .unwrap();
    let statement = EvmAccountBindingStatementV1 {
        network_id: NETWORK,
        registry_digest: admission.registry_digest(),
        route_id,
        settlement_id: terms.settlement_id.0,
        session_id: terms.session_id.0,
        terms_digest: admission.frozen_bindings().terms_digest,
        roster_snapshot: ROSTER_SNAPSHOT,
        participant_id,
        participant_xonly_key: xonly,
        account,
        position,
        role,
        issued_at: 1_900,
        valid_until: 2_100,
        evm_chain_id: 31_337,
    };
    let digest = evm_account_binding_digest_v1(&statement).unwrap();
    let (evm_signature, recovery) = signing.sign_prehash_recoverable(&digest).unwrap();
    let mut evm_wire = [0; EVM_ACCOUNT_SIGNATURE_BYTES_V1];
    evm_wire[..64].copy_from_slice(&evm_signature.to_bytes());
    evm_wire[64] = 27 + recovery.to_byte();
    let (participant_signature, signed_xonly) = secp
        .sign_bip340(&secrets.participant, &digest, &[0x99; 32])
        .unwrap();
    assert_eq!(signed_xonly, xonly);
    AccountProofFixture {
        proof: EvmAccountBindingProofV1::new(statement, evm_wire, participant_signature),
        xonly,
        account,
    }
}

fn composition(
    admission: &AuthenticatedRouteAdmissionV1,
) -> (ComposedBindingV1, SettlementTermsV1, SettlementTermsV1) {
    let adaptor_point = adaptor_point_of_scalar(&[0x01; 32]).unwrap();
    let terms = |settlement: u8,
                 dom_deadline: u64,
                 counterparty_deadline: u64,
                 asset_id: AssetId,
                 profile_digest: [u8; 32]|
     -> SettlementTermsV1 {
        SettlementTermsV1 {
            settlement_id: SettlementId([settlement; 32]),
            session_id: SessionId([settlement.wrapping_add(1); 32]),
            intent_hash: IntentHash([0x91; 32]),
            solver_id: SolverId([0x92; 32]),
            roster: [ParticipantId([0x93; 32]), ParticipantId([0x94; 32])],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: DOM_CHAIN,
                asset_id: DOM_ASSET,
                amount: 50,
                beneficiary: ParticipantId([0x94; 32]),
                refund_to: ParticipantId([0x93; 32]),
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight {
                    value: dom_deadline,
                },
                finality: finality(),
                adapter_profile_hash: admission.dom_profile_digest(),
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: EVM_CHAIN,
                asset_id,
                amount: 70,
                beneficiary: ParticipantId([0x93; 32]),
                refund_to: ParticipantId([0x94; 32]),
                mechanism: LockMechanism::ConditionLock,
                deadline: TimelockSpec::TimestampSeconds {
                    value: counterparty_deadline,
                },
                finality: finality(),
                adapter_profile_hash: profile_digest,
            },
            adaptor_point_sec1: adaptor_point,
            fee_limit: FeeLimitV1 {
                dom_max: 1,
                counterparty_max: 1,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 100,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: Vec::new(),
        }
    };
    let upstream = terms(
        0xa1,
        2_000,
        2_100,
        EVM_NATIVE,
        admission.upstream_profile_digest(),
    );
    let downstream = terms(
        0xb1,
        900,
        1_000,
        EVM_TOKEN,
        admission.downstream_profile_digest(),
    );
    let binding = ComposedBindingV1::bind(
        upstream.clone(),
        downstream.clone(),
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 100,
        },
    )
    .unwrap();
    (binding, upstream, downstream)
}

#[test]
fn every_new_route_rereads_registry_and_binds_exact_epoch_into_terms() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("registry.sqlite3");
    let signer = SecpContext::new(&[0x70; 32]);
    let first_manifest = manifest(1);
    let (authorities, first_signed) = signed(&first_manifest, &signer, 0x71);
    let mut initial_store = RegistryStoreV1::open(&path).unwrap();
    initial_store
        .install(
            &first_signed,
            &authorities,
            &signer,
            RegistryValidationPolicyV1 {
                now_seconds: 2_000,
                expected_network_id: NETWORK,
                minimum_epoch: 1,
            },
        )
        .unwrap();
    let admission_authority = RegistryRouteAdmissionAuthorityV1::new(
        initial_store,
        authorities.clone(),
        SecpContext::new(&[0x72; 32]),
        NETWORK,
        1,
    )
    .unwrap();

    let first = admission_authority
        .admit_composed_route(2_000, request())
        .unwrap();
    assert_eq!(first.registry_epoch(), 1);
    assert_eq!(
        first.frozen_bindings().deployment_bundle_digest,
        first_manifest.manifest_digest().unwrap()
    );
    assert_ne!(
        first.frozen_bindings().terms_digest,
        request().base_terms_digest
    );
    let first_config = first
        .evm_adapter_config_for_lab(
            LegIdV1::Downstream,
            session(first.frozen_bindings().terms_digest),
        )
        .unwrap();
    assert_eq!(first_config.asset, [0x42; 20]);
    assert!(matches!(
        first.evm_adapter_config_for_lab(LegIdV1::Downstream, session([0x99; 32])),
        Err(RouteAdmissionRefusalV1::SessionBindingMismatch)
    ));

    let (composition, upstream_terms, downstream_terms) = composition(&first);
    let validated = admission_authority
        .admit_validated_composed_route(2_000, [0x81; 32], &composition, route_rosters())
        .unwrap();
    assert_ne!(
        validated.frozen_bindings().terms_digest,
        composition.binding_digest()
    );
    let upstream_funder_proof = account_proof(
        &validated,
        &upstream_terms,
        [0x81; 32],
        EvmSettlementPositionV1::Upstream,
        EvmBindingRoleV1::Funder,
        upstream_terms.counterparty_leg.refund_to,
        AccountProofSecrets {
            evm: [0x61; 32],
            participant: [0x62; 32],
        },
    );
    let upstream_beneficiary_proof = account_proof(
        &validated,
        &upstream_terms,
        [0x81; 32],
        EvmSettlementPositionV1::Upstream,
        EvmBindingRoleV1::Beneficiary,
        upstream_terms.counterparty_leg.beneficiary,
        AccountProofSecrets {
            evm: [0x71; 32],
            participant: [0x72; 32],
        },
    );
    let upstream_funder = verify_evm_account_binding_v1(
        &upstream_funder_proof.proof,
        upstream_funder_proof.xonly,
        ROSTER_SNAPSHOT,
        NETWORK,
        validated.registry_digest(),
        2_000,
    )
    .unwrap();
    let upstream_beneficiary = verify_evm_account_binding_v1(
        &upstream_beneficiary_proof.proof,
        upstream_beneficiary_proof.xonly,
        ROSTER_SNAPSHOT,
        NETWORK,
        validated.registry_digest(),
        2_000,
    )
    .unwrap();
    let upstream_session = bind_evm_session_v1(
        &upstream_terms,
        [0x81; 32],
        validated.frozen_bindings().terms_digest,
        EvmSettlementPositionV1::Upstream,
        31_337,
        NETWORK,
        validated.registry_digest(),
        2_000,
        &upstream_funder,
        &upstream_beneficiary,
    )
    .unwrap();
    let upstream_config = validated
        .evm_adapter_config(LegIdV1::Upstream, &upstream_session)
        .unwrap();
    assert_eq!(upstream_config.direction, Direction::EvmToDom);
    assert_eq!(upstream_config.funder, upstream_funder_proof.account);
    assert_eq!(
        upstream_config.beneficiary,
        upstream_beneficiary_proof.account
    );
    assert!(matches!(
        validated.evm_adapter_config(LegIdV1::Downstream, &upstream_session),
        Err(RouteAdmissionRefusalV1::SessionBindingMismatch)
    ));

    let downstream_funder_proof = account_proof(
        &validated,
        &downstream_terms,
        [0x81; 32],
        EvmSettlementPositionV1::Downstream,
        EvmBindingRoleV1::Funder,
        downstream_terms.counterparty_leg.refund_to,
        AccountProofSecrets {
            evm: [0x61; 32],
            participant: [0x62; 32],
        },
    );
    let downstream_beneficiary_proof = account_proof(
        &validated,
        &downstream_terms,
        [0x81; 32],
        EvmSettlementPositionV1::Downstream,
        EvmBindingRoleV1::Beneficiary,
        downstream_terms.counterparty_leg.beneficiary,
        AccountProofSecrets {
            evm: [0x71; 32],
            participant: [0x72; 32],
        },
    );
    let downstream_funder = verify_evm_account_binding_v1(
        &downstream_funder_proof.proof,
        downstream_funder_proof.xonly,
        ROSTER_SNAPSHOT,
        NETWORK,
        validated.registry_digest(),
        2_000,
    )
    .unwrap();
    let downstream_beneficiary = verify_evm_account_binding_v1(
        &downstream_beneficiary_proof.proof,
        downstream_beneficiary_proof.xonly,
        ROSTER_SNAPSHOT,
        NETWORK,
        validated.registry_digest(),
        2_000,
    )
    .unwrap();
    let downstream_session = bind_evm_session_v1(
        &downstream_terms,
        [0x81; 32],
        validated.frozen_bindings().terms_digest,
        EvmSettlementPositionV1::Downstream,
        31_337,
        NETWORK,
        validated.registry_digest(),
        2_000,
        &downstream_funder,
        &downstream_beneficiary,
    )
    .unwrap();
    let downstream_config = validated
        .evm_adapter_config(LegIdV1::Downstream, &downstream_session)
        .unwrap();
    assert_eq!(downstream_config.direction, Direction::DomToEvm);
    assert_eq!(downstream_config.asset, [0x42; 20]);

    let mut wrong_profile_terms = downstream_terms.clone();
    wrong_profile_terms.counterparty_leg.adapter_profile_hash = [0x82; 32];
    let profile_mismatch = ComposedBindingV1::bind(
        upstream_terms.clone(),
        wrong_profile_terms,
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 100,
        },
    )
    .unwrap();
    assert!(matches!(
        admission_authority.admit_validated_composed_route(
            2_000,
            [0x83; 32],
            &profile_mismatch,
            route_rosters()
        ),
        Err(RouteAdmissionRefusalV1::CompositionRegistryMismatch)
    ));

    let mut wrong_mechanism_terms = downstream_terms.clone();
    wrong_mechanism_terms.counterparty_leg.mechanism = LockMechanism::SchnorrAdaptor;
    let mechanism_mismatch = ComposedBindingV1::bind(
        upstream_terms.clone(),
        wrong_mechanism_terms,
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 100,
        },
    )
    .unwrap();
    assert!(matches!(
        admission_authority.admit_validated_composed_route(
            2_000,
            [0x84; 32],
            &mechanism_mismatch,
            route_rosters()
        ),
        Err(RouteAdmissionRefusalV1::CompositionRegistryMismatch)
    ));

    let mut wrong_clock_upstream = upstream_terms.clone();
    let mut wrong_clock_downstream = downstream_terms.clone();
    wrong_clock_upstream.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 2_100 };
    wrong_clock_downstream.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 1_000 };
    let clock_mismatch = ComposedBindingV1::bind(
        wrong_clock_upstream,
        wrong_clock_downstream,
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 100,
        },
    )
    .unwrap();
    assert!(matches!(
        admission_authority.admit_validated_composed_route(
            2_000,
            [0x85; 32],
            &clock_mismatch,
            route_rosters()
        ),
        Err(RouteAdmissionRefusalV1::CompositionRegistryMismatch)
    ));

    let mut wrong_dom_upstream = upstream_terms.clone();
    let mut wrong_dom_downstream = downstream_terms.clone();
    wrong_dom_upstream.dom_leg.deadline = TimelockSpec::TimestampSeconds { value: 2_000 };
    wrong_dom_downstream.dom_leg.deadline = TimelockSpec::TimestampSeconds { value: 900 };
    let dom_clock_mismatch = ComposedBindingV1::bind(
        wrong_dom_upstream,
        wrong_dom_downstream,
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 100,
        },
    )
    .unwrap();
    assert!(matches!(
        admission_authority.admit_validated_composed_route(
            2_000,
            [0x86; 32],
            &dom_clock_mismatch,
            route_rosters()
        ),
        Err(RouteAdmissionRefusalV1::CompositionRegistryMismatch)
    ));

    #[cfg(feature = "development")]
    {
        let route_directory = tempfile::tempdir().unwrap();
        let route_path = route_directory.path().join("routes.sqlite3");
        let mut route_store = DurableRouteStoreV1::open(&route_path).unwrap();
        route_store.create_route(request().route_id, 1_999).unwrap();
        let clock = ManualClockV1::new(2_000).unwrap();
        let config = RouteSupervisorConfigV1::new(1_000, 200, 100, 8).unwrap();
        let mut supervisor =
            RouteSupervisorV1::acquire(route_store, request().route_id, [0x53; 32], config, clock)
                .unwrap();
        assert!(matches!(
            supervisor.admit_route([0x54; 32], &first).unwrap(),
            CommitOutcomeV1::Committed { revision: 1, .. }
        ));
        assert_eq!(
            supervisor.snapshot().unwrap().bindings.as_ref(),
            Some(first.frozen_bindings())
        );

        let mut wrong_request = request();
        wrong_request.route_id = [0x55; 32];
        let wrong_route = admission_authority
            .admit_composed_route(2_000, wrong_request)
            .unwrap();
        assert!(matches!(
            supervisor.admit_route([0x56; 32], &wrong_route),
            Err(RouteSupervisorErrorV1::AdmissionScopeMismatch)
        ));
    }

    let second_manifest = manifest(2);
    let (_, second_signed) = signed(&second_manifest, &signer, 0x73);
    let mut writer = RegistryStoreV1::open(&path).unwrap();
    writer
        .install(
            &second_signed,
            &authorities,
            &signer,
            RegistryValidationPolicyV1 {
                now_seconds: 2_001,
                expected_network_id: NETWORK,
                minimum_epoch: 2,
            },
        )
        .unwrap();
    let second = admission_authority
        .admit_composed_route(2_001, request())
        .unwrap();
    assert_eq!(second.registry_epoch(), 2);
    assert_ne!(first.registry_digest(), second.registry_digest());
    assert_ne!(
        first.frozen_bindings().terms_digest,
        second.frozen_bindings().terms_digest
    );
    assert!(matches!(
        second.evm_adapter_config_for_lab(
            LegIdV1::Downstream,
            session(first.frozen_bindings().terms_digest)
        ),
        Err(RouteAdmissionRefusalV1::SessionBindingMismatch)
    ));
    let recovered = admission_authority
        .recover_composed_route(request(), first.frozen_bindings())
        .unwrap();
    assert_eq!(recovered.registry_epoch(), 1);
    assert_eq!(recovered.registry_digest(), first.registry_digest());
    assert_eq!(recovered.frozen_bindings(), first.frozen_bindings());
    let mut tampered = first.frozen_bindings().clone();
    tampered.terms_digest[0] ^= 1;
    assert!(matches!(
        admission_authority.recover_composed_route(request(), &tampered),
        Err(RouteAdmissionRefusalV1::PinnedBindingMismatch)
    ));
    // Recovery of the already-admitted epoch remains possible.
    first
        .evm_adapter_config_for_lab(
            LegIdV1::Downstream,
            session(first.frozen_bindings().terms_digest),
        )
        .unwrap();
}

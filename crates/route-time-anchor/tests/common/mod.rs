#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_btc::types::BitcoinNetworkV1;
use bitcoin::{blockdata::constants::genesis_block, hashes::Hash, Network};
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1, ChainDeploymentV1,
    DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryValidationPolicyV1, ResolvedRegistryV1,
    SignedRegistryV1,
};
use dom_consensus::derive_chain_id;
use dom_core::configured_genesis_hash_for_network_magic;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1, LockMechanism,
    ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
};
use route_time_anchor::{
    resolved_dom_profile_digest_v1, CanonicalAnchorObservationV2, CanonicalCheckpointObservationV2,
    CanonicalTimeCheckpointV2, CanonicalTimeRangeV2, CanonicalTipObservationV2,
    RouteTimeEvidenceV2, RouteTimeEvidenceVerificationContextV2, RouteTimePolicyLimitsV2,
    RouteTimePolicyV2, RouteTimePolicyVerificationContextV2, SignedRouteTimeEvidenceV2,
    SignedRouteTimePolicyV2, TimeAnchorSignatureV2,
};

pub const REGISTRY_NETWORK: [u8; 32] = [0x90; 32];
pub const EVM_CHAIN: ChainId = ChainId([0x20; 32]);
pub const BTC_CHAIN: ChainId = ChainId([0x30; 32]);
pub const DOM_ASSET: AssetId = AssetId([0x11; 32]);
pub const EVM_ASSET: AssetId = AssetId([0x12; 32]);
pub const BTC_ASSET: AssetId = AssetId([0x13; 32]);
pub const ANCHOR_TIME: u64 = 1_000_000;
pub const EVIDENCE_TIME: u64 = 1_000_010;
pub const POLICY_SECRETS: [[u8; 32]; 3] = [[0x11; 32], [0x12; 32], [0x13; 32]];
pub const EVIDENCE_SECRETS: [[u8; 32]; 3] = [[0x21; 32], [0x22; 32], [0x23; 32]];

pub struct Fixture {
    pub secp: SecpContext,
    pub registry: ResolvedRegistryV1,
    pub upstream: SettlementTermsV1,
    pub downstream: SettlementTermsV1,
    pub policy: RouteTimePolicyV2,
    pub policy_authorities: AuthoritySetV1,
    pub evidence_authorities: AuthoritySetV1,
}

impl Fixture {
    pub fn policy_context(&self) -> RouteTimePolicyVerificationContextV2<'_> {
        RouteTimePolicyVerificationContextV2::new(
            &self.policy_authorities,
            &self.secp,
            &self.registry,
            &self.upstream,
            &self.downstream,
        )
    }

    pub fn evidence_context(&self) -> RouteTimeEvidenceVerificationContextV2<'_> {
        RouteTimeEvidenceVerificationContextV2::new(
            self.policy_context(),
            &self.evidence_authorities,
        )
    }
}

pub fn fixture() -> Fixture {
    let secp = SecpContext::new(&[0x77; 32]);
    let manifest = manifest_for_dom_network(DomNetworkV1::Regtest);
    let registry_authorities = authority_set(&secp, &[[0x03; 32], [0x04; 32], [0x05; 32]]);
    let registry_digest = manifest.manifest_digest().unwrap();
    let registry_signatures = sign_digest(
        &secp,
        &[[0x03; 32], [0x04; 32], [0x05; 32]],
        &registry_digest,
        0x50,
    )
    .into_iter()
    .map(|signature| RegistrySignatureV1 {
        signer_index: signature.signer_index,
        signature: signature.signature,
    })
    .collect();
    let signed_registry = SignedRegistryV1::new(&manifest, registry_signatures).unwrap();
    let registry = signed_registry
        .verify(
            &registry_authorities,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds: EVIDENCE_TIME,
                expected_network_id: REGISTRY_NETWORK,
                minimum_epoch: 7,
            },
        )
        .unwrap();
    let (upstream, downstream) = terms(&registry);
    let policy =
        RouteTimePolicyV2::from_registry(&registry, &upstream, &downstream, limits()).unwrap();
    Fixture {
        secp,
        registry,
        upstream,
        downstream,
        policy,
        policy_authorities: authority_set(&SecpContext::new(&[0x78; 32]), &POLICY_SECRETS),
        evidence_authorities: authority_set(&SecpContext::new(&[0x79; 32]), &EVIDENCE_SECRETS),
    }
}

pub fn mainnet_registry_and_terms() -> (ResolvedRegistryV1, SettlementTermsV1, SettlementTermsV1) {
    let secp = SecpContext::new(&[0x7a; 32]);
    let manifest = manifest_for_dom_network(DomNetworkV1::Mainnet);
    let secrets = [[0x03; 32], [0x04; 32], [0x05; 32]];
    let authorities = authority_set(&secp, &secrets);
    let digest = manifest.manifest_digest().unwrap();
    let signatures = sign_digest(&secp, &secrets, &digest, 0x50)
        .into_iter()
        .map(|signature| RegistrySignatureV1 {
            signer_index: signature.signer_index,
            signature: signature.signature,
        })
        .collect();
    let registry = SignedRegistryV1::new(&manifest, signatures)
        .unwrap()
        .verify(
            &authorities,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds: EVIDENCE_TIME,
                expected_network_id: REGISTRY_NETWORK,
                minimum_epoch: 7,
            },
        )
        .unwrap();
    let (upstream, downstream) = terms(&registry);
    (registry, upstream, downstream)
}

pub fn limits() -> RouteTimePolicyLimitsV2 {
    RouteTimePolicyLimitsV2 {
        valid_from_seconds: 900_000,
        expires_at_seconds: 4_000_000,
        max_evidence_age_seconds: 600,
        max_anchor_interval_width_seconds: 20,
        max_anchor_time_skew_seconds: 120,
        max_future_skew_seconds: 30,
        max_upstream_funding_anchor_delay_seconds: 3_600,
        max_downstream_funding_anchor_delay_seconds: 3_600,
        hub_margin_seconds: 60,
        counterparty_margin_seconds: 2_100_000,
    }
}

pub fn checkpoints(
    policy: &RouteTimePolicyV2,
    time_shift: u64,
    tip_shift: u64,
) -> [CanonicalTimeCheckpointV2; 3] {
    let bindings = policy.checkpoint_bindings();
    [
        CanonicalTimeCheckpointV2::new(
            bindings[0],
            CanonicalCheckpointObservationV2::new(
                CanonicalAnchorObservationV2::new(100, [0xa1; 32], [0xa0; 32]),
                CanonicalTimeRangeV2::new(ANCHOR_TIME + time_shift, ANCHOR_TIME + time_shift + 10),
                CanonicalTipObservationV2::new(101 + tip_shift, [0xb1; 32], [0xc1; 32]),
            ),
        ),
        CanonicalTimeCheckpointV2::new(
            bindings[1],
            CanonicalCheckpointObservationV2::new(
                CanonicalAnchorObservationV2::new(500, [0xa2; 32], [0xa3; 32]),
                CanonicalTimeRangeV2::new(ANCHOR_TIME + time_shift, ANCHOR_TIME + time_shift + 10),
                CanonicalTipObservationV2::new(501 + tip_shift, [0xb2; 32], [0xc2; 32]),
            ),
        ),
        CanonicalTimeCheckpointV2::new(
            bindings[2],
            CanonicalCheckpointObservationV2::new(
                CanonicalAnchorObservationV2::new(700, [0xa4; 32], [0xa5; 32]),
                CanonicalTimeRangeV2::new(ANCHOR_TIME + time_shift, ANCHOR_TIME + time_shift + 10),
                CanonicalTipObservationV2::new(701 + tip_shift, [0xb3; 32], [0xc3; 32]),
            ),
        ),
    ]
}

pub fn evidence(
    policy: &RouteTimePolicyV2,
    sequence: u64,
    observed_at: u64,
    tip_shift: u64,
) -> RouteTimeEvidenceV2 {
    RouteTimeEvidenceV2::new(
        policy,
        sequence,
        observed_at,
        observed_at + 300,
        checkpoints(policy, 0, tip_shift),
    )
    .unwrap()
}

pub fn signed_policy(fixture: &Fixture) -> SignedRouteTimePolicyV2 {
    let digest = fixture.policy.policy_digest().unwrap();
    SignedRouteTimePolicyV2::new(
        &fixture.policy,
        sign_digest(&fixture.secp, &POLICY_SECRETS, &digest, 0x60),
    )
    .unwrap()
}

pub fn signed_evidence(
    fixture: &Fixture,
    evidence: &RouteTimeEvidenceV2,
) -> SignedRouteTimeEvidenceV2 {
    let digest = evidence.evidence_digest().unwrap();
    SignedRouteTimeEvidenceV2::new(
        evidence,
        sign_digest(&fixture.secp, &EVIDENCE_SECRETS, &digest, 0x70),
    )
    .unwrap()
}

pub fn sign_digest(
    secp: &SecpContext,
    secrets: &[[u8; 32]],
    digest: &[u8; 32],
    aux: u8,
) -> Vec<TimeAnchorSignatureV2> {
    secrets
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            let (signature, _) = secp
                .sign_bip340(secret, digest, &[aux.wrapping_add(index as u8); 32])
                .unwrap();
            TimeAnchorSignatureV2 {
                signer_index: index as u16,
                signature,
            }
        })
        .collect()
}

fn authority_set(secp: &SecpContext, secrets: &[[u8; 32]]) -> AuthoritySetV1 {
    let keys = secrets
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            secp.sign_bip340(secret, &[0x41; 32], &[0x42 + index as u8; 32])
                .unwrap()
                .1
        })
        .collect();
    AuthoritySetV1::new(2, keys).unwrap()
}

fn manifest_for_dom_network(dom_network: DomNetworkV1) -> RegistryManifestV1 {
    let network_magic = dom_network.canonical_magic();
    let genesis = configured_genesis_hash_for_network_magic(network_magic).unwrap();
    let dom_chain = ChainId(*derive_chain_id(network_magic, &genesis).as_bytes());
    let dom_timing = ChainTimingBoundsV1 {
        min_block_seconds: 1,
        max_block_seconds: 2,
        max_reorg_seconds: 20,
        observation_seconds: 2,
        broadcast_seconds: 2,
    };
    let evm_timing = ChainTimingBoundsV1 {
        min_block_seconds: 1,
        max_block_seconds: 2,
        max_reorg_seconds: 20,
        observation_seconds: 2,
        broadcast_seconds: 2,
    };
    let btc_timing = ChainTimingBoundsV1 {
        min_block_seconds: 500,
        max_block_seconds: 700,
        max_reorg_seconds: 2_000_000,
        observation_seconds: 60,
        broadcast_seconds: 60,
    };
    let finality = FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 3,
    };
    let mut manifest = RegistryManifestV1 {
        network_id: REGISTRY_NETWORK,
        epoch: 7,
        valid_from: 800_000,
        expires_at: 5_000_000,
        dom: DomDeploymentV1 {
            chain_id: dom_chain,
            genesis_hash: *genesis.as_bytes(),
            runtime_identity: DomRuntimeIdentityV1::pinned(dom_network),
            consensus_rules_digest: [0x44; 32],
            scriptless_api_version: 1,
            timing: dom_timing,
            finality,
            native_asset: DOM_ASSET,
        },
        chains: vec![
            RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: EVM_CHAIN,
                    kind: ChainKindV1::Evm {
                        evm_chain_id: 31_337,
                        native_lock_contract: [0x31; 20],
                        native_code_hash: [0x32; 32],
                        erc20_lock_contract: None,
                    },
                    timing: evm_timing,
                    finality,
                    native_asset: EVM_ASSET,
                    allowed_assets: vec![],
                },
                deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                    genesis_hash: [0x35; 32],
                    native_start_block: 10,
                    erc20_start_block: None,
                    abi_digest: [0x36; 32],
                    compiler_digest: [0x37; 32],
                    source_digest: [0x38; 32],
                    deployment_digest: [0x39; 32],
                    finalized_tag_required: true,
                    page_size: 256,
                    gas_limit_hint: 300_000,
                    max_fee_per_gas: 100_000_000_000,
                    max_priority_fee_per_gas: 2_000_000_000,
                }),
            },
            RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: BTC_CHAIN,
                    kind: ChainKindV1::Bitcoin {
                        network: BitcoinNetworkV1::Regtest,
                    },
                    timing: btc_timing,
                    finality,
                    native_asset: BTC_ASSET,
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
            },
        ],
        assets: vec![
            AssetBindingV1 {
                chain_id: dom_chain,
                asset_id: DOM_ASSET,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_ASSET,
                decimals: 18,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: BTC_CHAIN,
                asset_id: BTC_ASSET,
                decimals: 8,
                representation: AssetRepresentationV1::Native,
            },
        ],
    };
    manifest
        .assets
        .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
    manifest
}

fn terms(registry: &ResolvedRegistryV1) -> (SettlementTermsV1, SettlementTermsV1) {
    let dom = registry.manifest().dom;
    let dom_profile = resolved_dom_profile_digest_v1(registry).unwrap();
    let evm_profile = registry
        .resolve_chain(EVM_CHAIN)
        .unwrap()
        .profile()
        .profile_digest()
        .unwrap();
    let btc_profile = registry
        .resolve_chain(BTC_CHAIN)
        .unwrap()
        .profile()
        .profile_digest()
        .unwrap();
    let adaptor_point: [u8; 33] =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap();
    let common_dom = |deadline| LegTermsV1 {
        role: LegRole::Dom,
        chain_id: dom.chain_id,
        asset_id: DOM_ASSET,
        amount: 50,
        beneficiary: ParticipantId([0xb2; 32]),
        refund_to: ParticipantId([0xb1; 32]),
        mechanism: LockMechanism::DomAdaptor2of2,
        deadline: TimelockSpec::BlockHeight { value: deadline },
        finality: dom.finality,
        adapter_profile_hash: dom_profile,
    };
    let base = |settlement: u8, dom_leg, counterparty_leg| SettlementTermsV1 {
        settlement_id: SettlementId([settlement; 32]),
        session_id: SessionId([settlement.wrapping_add(1); 32]),
        intent_hash: IntentHash([0x81; 32]),
        solver_id: SolverId([0x82; 32]),
        roster: [ParticipantId([0xb1; 32]), ParticipantId([0xb2; 32])],
        dom_leg,
        counterparty_leg,
        adaptor_point_sec1: adaptor_point,
        fee_limit: FeeLimitV1 {
            dom_max: 10,
            counterparty_max: 10,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 100,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    };
    let upstream = base(
        0xa0,
        common_dom(400),
        LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: EVM_CHAIN,
            asset_id: EVM_ASSET,
            amount: 60,
            beneficiary: ParticipantId([0xb1; 32]),
            refund_to: ParticipantId([0xb2; 32]),
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::TimestampSeconds { value: 3_200_000 },
            finality: registry
                .resolve_chain(EVM_CHAIN)
                .unwrap()
                .profile()
                .finality,
            adapter_profile_hash: evm_profile,
        },
    );
    let downstream = base(
        0xd0,
        common_dom(200),
        LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: BTC_CHAIN,
            asset_id: BTC_ASSET,
            amount: 70,
            beneficiary: ParticipantId([0xb1; 32]),
            refund_to: ParticipantId([0xb2; 32]),
            mechanism: LockMechanism::SchnorrAdaptor,
            deadline: TimelockSpec::BtcTime512s { value: 20 },
            finality: registry
                .resolve_chain(BTC_CHAIN)
                .unwrap()
                .profile()
                .finality,
            adapter_profile_hash: btc_profile,
        },
    );
    (upstream, downstream)
}

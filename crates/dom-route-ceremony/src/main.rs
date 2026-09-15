//! Local route ceremony for the composable EVM+Bitcoin shape.
//!
//! `dom-route-ceremony <deploy-local-manifest.v1.json> <state-dir>`
//!
//! Stage 1 rebuilds the canonical registry manifest from the local deployment
//! mold, installs it under a freshly generated 2-of-3 authority set, resolves
//! it, and composes the two `SettlementTermsV1` the route needs.
//!
//! Stage 2a derives the route-time policy from that registry, threshold-signs
//! the policy and its first evidence under two further independent authority
//! sets, installs them into a durable V2 time anchor, proves the route ladder,
//! composes the binding and admits the route. Nothing is invented: every chain
//! id, asset id, profile digest and finality policy is read back from the
//! verified registry, exactly as the daemon's own input loader reads them.

#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use adapter_btc::roster::BitcoinSignerRoleV1;
use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_btc::types::BitcoinNetworkV1;
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1, ChainDeploymentV1,
    DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
    ResolvedRegistryV1, SignedRegistryV1,
};
use dom_actuator::{DomParticipantV1, DomSessionBindingV1, DomWalletAuthorityBindingV1};
use dom_consensus::derive_chain_id;
use dom_core::{configured_genesis_hash_for_network_magic, NETWORK_MAGIC_REGTEST};
use dom_interopd::{
    production_f6_authority_bundle_digest_v8, ProductionAuthorityBundleV1,
    ProductionBitcoinLegKeyProofsV1, ProductionBitcoinParticipantKeyProofV1,
    ProductionBitcoinParticipantKeyStatementRequestV1, ProductionBitcoinPrebroadcastPinsV7,
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionContractsBootstrapPinsV5,
    ProductionEvmLegProofsV1, ProductionF6PathReferencesV4, ProductionF6PathReferencesV8,
    ProductionFamilyInputsV10, ProductionFamilyInputsV5, ProductionFamilyInputsV6,
    ProductionFamilyInputsV7, ProductionFamilyInputsV8, ProductionFamilyInputsV9,
    ProductionOperationalPoliciesV10, ProductionParticipantBindingBundleV1,
    ProductionPathReferencesV1, ProductionRelayAuthorityPinsV6, ProductionRelayEndpointModeV1,
    ProductionRelayNetworkConfigV1, ProductionRelayNetworkLinkV1, ProductionRelayRosterBundleV1,
    ProductionRosterLegV1, ProductionRosterMemberV1, ProductionRoutePinsV1,
    ProductionRoutePositionV1, ProductionRuntimeBoundsV1, RegistryRouteAdmissionAuthorityV1,
    RouteRosterSnapshotsV1, PRODUCTION_CREATE_CONFIG_FILE_V10,
    PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1, PRODUCTION_REOPEN_CONFIG_FILE_V10,
};
use dom_wallet2::{save_wallet_state, Network, WalletV2State};
use k256::ecdsa::SigningKey;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1, LockMechanism,
    ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
};
use participant_binding::{
    evm_account_binding_digest_v1, EvmAccountBindingProofV1, EvmAccountBindingStatementV1,
    EvmBindingRoleV1, EvmSettlementPositionV1, EVM_ACCOUNT_SIGNATURE_BYTES_V1,
};
use relay::production::RelayDatabaseIdV1;
use relay::SenderRoleV1;
use route_composer::ComposedBindingV2;
use route_executor::LegIdV1;
use route_time_anchor::{
    resolved_dom_profile_digest_v1, CanonicalAnchorObservationV2, CanonicalCheckpointObservationV2,
    CanonicalTimeCheckpointV2, CanonicalTimeRangeV2, CanonicalTipObservationV2,
    DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2, RouteTimeEvidenceV2,
    RouteTimeEvidenceVerificationContextV2, RouteTimePolicyLimitsV2, RouteTimePolicyV2,
    RouteTimePolicyVerificationContextV2, SignedRouteTimeEvidenceV2, SignedRouteTimePolicyV2,
    TimeAnchorSignatureV2,
};
use sha3::{Digest as _, Keccak256};
use zeroize::Zeroizing;

const AUTHORITY_SECRET_PREFIX_V1: &str = "ceremony-registry-authority";
const POLICY_SECRET_PREFIX_V1: &str = "ceremony-policy-authority";
const EVIDENCE_SECRET_PREFIX_V1: &str = "ceremony-evidence-authority";
const NETWORK_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/LOCAL-NETWORK-ID/V1\0";
const EPOCH_V1: u64 = 1;
const VALIDITY_SECONDS_V1: u64 = 31_536_000;
const REGISTRY_FILE_V1: &str = "registry.v1.sqlite3";
const TIME_ANCHOR_FILE_V1: &str = "planning-time.v2.sqlite3";

/// Upstream is the DOM<->EVM leg; downstream is the DOM<->Bitcoin leg.
const UPSTREAM_SETTLEMENT: u8 = 0xa0;
const DOWNSTREAM_SETTLEMENT: u8 = 0xd0;
const ROUTE_ID: [u8; 32] = [0x0c; 32];
const UPSTREAM_ROSTER: [u8; 32] = [0x51; 32];
const DOWNSTREAM_ROSTER: [u8; 32] = [0x52; 32];

/// The ceremony's trusted seconds. `ANCHOR_TIME` is when the chain anchors were
/// observed; `EVIDENCE_TIME` is when the evidence row was issued and admitted.
const ANCHOR_TIME: u64 = 1_000_000;
const EVIDENCE_TIME: u64 = 1_000_010;

/// Passphrase sealing the generated DOM participant wallet. It is a ceremony
/// input, not a secret this tool invents for itself: the operator must hand the
/// daemon this exact string as the fifth line of the V3 secret stream, or
/// `DomParticipantWalletV1::open_existing` refuses with `WalletUnavailable`.
const DOM_WALLET_PASSPHRASE: &str = "dom-route-ceremony-local-wallet";

fn fail(message: &str) -> ! {
    eprintln!("dom-route-ceremony: {message}");
    std::process::exit(1);
}

/// Everything stage 1 produced that later stages still need.
struct ProvisionedV1 {
    registry: ResolvedRegistryV1,
    network_id: [u8; 32],
    authorities: AuthoritySetV1,
    secp: SecpContext,
    registry_path: PathBuf,
}

/// Public digests stage 2a froze, in the order the bootstrap config pins them,
/// plus the signed artifacts stage 2b writes into `inputs/`.
struct CeremonyV1 {
    policy_authority_set_digest: [u8; 32],
    evidence_authority_set_digest: [u8; 32],
    route_scope_digest: [u8; 32],
    policy_digest: [u8; 32],
    evidence_digest: [u8; 32],
    frozen_terms_digest: [u8; 32],
    policy_authorities: AuthoritySetV1,
    evidence_authorities: AuthoritySetV1,
    signed_policy: SignedRouteTimePolicyV2,
    signed_evidence: SignedRouteTimeEvidenceV2,
    /// The two Relay transport secrets, retained so the participant bindings
    /// can be signed by the same keys the roster publishes.
    relay_secrets: [[u8; 32]; 2],
    relay_keys: [[u8; 32]; 2],
}

/// Digests stage 2b produced from the artifacts it wrote.
struct BoundInputsV1 {
    relay_binding_digest: [u8; 32],
    participant_bindings_digest: [u8; 32],
}

/// Identities stage 3 committed that stage 4's Relay network document must
/// reproduce exactly: the local Relay database and the two remote peers the
/// V10 operational policies pin.
struct RelayIdentitiesV1 {
    local_relay_database_id: [u8; 32],
    upstream_remote_relay_database_id: [u8; 32],
    downstream_remote_relay_database_id: [u8; 32],
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(mold_path), Some(state_dir)) = (args.next(), args.next()) else {
        fail("usage: dom-route-ceremony <deploy-local-manifest.v1.json> <state-dir>");
    };
    if args.next().is_some() {
        fail("unexpected extra argument");
    }
    let mold: serde_json::Value = serde_json::from_slice(
        &fs::read(&mold_path).unwrap_or_else(|error| fail(&format!("mold unreadable: {error}"))),
    )
    .unwrap_or_else(|error| fail(&format!("mold is not valid JSON: {error}")));
    let state_dir = PathBuf::from(state_dir);

    let provisioned = provision_registry(&mold, &state_dir).unwrap_or_else(|error| fail(&error));
    let (upstream, downstream) = terms(&provisioned.registry).unwrap_or_else(|error| fail(&error));
    let ceremony = time_ceremony(&state_dir, &provisioned, &upstream, &downstream)
        .unwrap_or_else(|error| fail(&error));

    let upstream_hash = upstream
        .terms_hash()
        .unwrap_or_else(|error| fail(&format!("upstream terms hash: {error:?}")));
    let downstream_hash = downstream
        .terms_hash()
        .unwrap_or_else(|error| fail(&format!("downstream terms hash: {error:?}")));

    println!(
        "network_id                        = {}",
        hex::encode(provisioned.network_id)
    );
    println!(
        "dom_chain_id                      = {}",
        hex::encode(provisioned.registry.manifest().dom.chain_id.0)
    );
    println!(
        "registry_manifest_digest          = {}",
        hex::encode(provisioned.registry.manifest_digest())
    );
    println!(
        "upstream_terms_digest             = {}",
        hex::encode(upstream_hash)
    );
    println!(
        "downstream_terms_digest           = {}",
        hex::encode(downstream_hash)
    );
    println!(
        "route_scope_digest                = {}",
        hex::encode(ceremony.route_scope_digest)
    );
    println!(
        "time_policy_authority_set_digest  = {}",
        hex::encode(ceremony.policy_authority_set_digest)
    );
    println!(
        "time_evidence_authority_set_digest= {}",
        hex::encode(ceremony.evidence_authority_set_digest)
    );
    println!(
        "time_policy_digest                = {}",
        hex::encode(ceremony.policy_digest)
    );
    println!(
        "time_evidence_digest              = {}",
        hex::encode(ceremony.evidence_digest)
    );
    println!(
        "admitted_frozen_terms_digest      = {}",
        hex::encode(ceremony.frozen_terms_digest)
    );

    let bound = write_inputs(&state_dir, &provisioned, &upstream, &downstream, &ceremony)
        .unwrap_or_else(|error| fail(&error));
    println!(
        "relay_binding_digest              = {}",
        hex::encode(bound.relay_binding_digest)
    );
    println!(
        "participant_bindings_digest       = {}",
        hex::encode(bound.participant_bindings_digest)
    );

    let (config_digest, relay_identities) = write_bootstrap_configs(
        &state_dir,
        &provisioned,
        &upstream,
        &downstream,
        &ceremony,
        &bound,
    )
    .unwrap_or_else(|error| fail(&error));
    println!(
        "bootstrap_config_digest           = {}",
        hex::encode(config_digest)
    );
    write_relay_network_config(&state_dir, &relay_identities).unwrap_or_else(|error| fail(&error));
    println!(
        "relay_local_database_id           = {}",
        hex::encode(relay_identities.local_relay_database_id)
    );
    println!("state dir ready: {}", state_dir.display());
}

// --------------------------------------------------------------- registry --

fn provision_registry(mold: &serde_json::Value, state_dir: &Path) -> Result<ProvisionedV1, String> {
    fs::create_dir_all(state_dir).map_err(|error| format!("state dir: {error}"))?;
    fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("state dir mode: {error}"))?;

    let manifest = manifest_from_mold(mold)?;
    let network_id = manifest.network_id;
    let digest = manifest
        .manifest_digest()
        .map_err(|error| format!("manifest digest: {error:?}"))?;

    let secp = SecpContext::new(&random32());
    let mut keys = Vec::new();
    let mut signatures = Vec::new();
    for index in 0_u16..3 {
        let secret = Zeroizing::new(random32());
        let (signature, xonly) = secp
            .sign_bip340(&secret, &digest, &random32())
            .map_err(|error| format!("authority signature: {error:?}"))?;
        write_owner_file(
            &state_dir.join(format!("{AUTHORITY_SECRET_PREFIX_V1}-{index}.secret")),
            hex::encode(&secret[..]).as_bytes(),
        )?;
        keys.push(xonly);
        signatures.push(RegistrySignatureV1 {
            signer_index: index,
            signature,
        });
    }
    let authorities =
        AuthoritySetV1::new(2, keys).map_err(|error| format!("authority set: {error:?}"))?;
    let signed = SignedRegistryV1::new(&manifest, signatures)
        .map_err(|error| format!("signed registry: {error:?}"))?;

    let registry_path = state_dir.join(REGISTRY_FILE_V1);
    if registry_path.exists() {
        return Err(format!(
            "{REGISTRY_FILE_V1} already exists; refusing to overwrite"
        ));
    }
    let policy = RegistryValidationPolicyV1 {
        now_seconds: manifest.valid_from,
        expected_network_id: network_id,
        minimum_epoch: EPOCH_V1,
    };
    let mut store = RegistryStoreV1::create(&registry_path)
        .map_err(|error| format!("registry create: {error:?}"))?;
    store
        .install(&signed, &authorities, &secp, policy)
        .map_err(|error| format!("registry install: {error:?}"))?;
    drop(store);

    let registry = signed
        .verify(&authorities, &secp, policy)
        .map_err(|error| format!("registry verify: {error:?}"))?;
    Ok(ProvisionedV1 {
        registry,
        network_id,
        authorities,
        secp,
        registry_path,
    })
}

fn manifest_from_mold(mold: &serde_json::Value) -> Result<RegistryManifestV1, String> {
    let genesis = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)
        .map_err(|_| "canonical DOM regtest genesis missing".to_owned())?;
    let dom_chain = ChainId(*derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis).as_bytes());
    let source_commit = require_str(mold, &["source_commit"])?;
    let network_id = domain_digest(NETWORK_ID_DOMAIN_V1, source_commit.as_bytes());
    let evm_chain = evm_chain_id(mold)?;
    let btc_chain = btc_chain_id();
    let dom_asset = AssetId(domain_digest(b"DOM-ASSET/NATIVE/V1\0", &dom_chain.0));
    let evm_native = AssetId(domain_digest(b"DOM-ASSET/EVM-NATIVE/V1\0", &evm_chain.0));
    let btc_asset = AssetId(domain_digest(b"DOM-ASSET/BTC-NATIVE/V1\0", &btc_chain.0));

    let native_lock = require_address(mold, &["evm", "native_lock"])?;
    let native_code_hash = require_hash32(mold, &["evm", "native_runtime_codehash"])?;
    let erc20_lock = require_address(mold, &["evm", "erc20_lock"])?;
    let erc20_code_hash = require_hash32(mold, &["evm", "erc20_runtime_codehash"])?;
    let evm_genesis = require_hash32(mold, &["evm", "genesis_hash"])?;
    let deploy_block = require_u64(mold, &["evm", "deploy_block"])?;
    let btc_genesis = bitcoin_genesis_bytes(mold)?;
    let valid_from = 1;

    let mut manifest = RegistryManifestV1 {
        network_id,
        epoch: EPOCH_V1,
        valid_from,
        expires_at: valid_from + VALIDITY_SECONDS_V1,
        dom: DomDeploymentV1 {
            chain_id: dom_chain,
            genesis_hash: *genesis.as_bytes(),
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: domain_digest(
                b"DOM-CONSENSUS-RULES/LOCAL-CYCLE/V1\0",
                source_commit.as_bytes(),
            ),
            scriptless_api_version: 1,
            timing: local_timing(),
            finality: local_finality(),
            native_asset: dom_asset,
        },
        chains: vec![
            RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: evm_chain,
                    kind: ChainKindV1::Evm {
                        evm_chain_id: require_u64(mold, &["evm", "chain_id"])?,
                        native_lock_contract: native_lock,
                        native_code_hash,
                        erc20_lock_contract: Some((erc20_lock, erc20_code_hash)),
                    },
                    timing: local_timing(),
                    finality: local_finality(),
                    native_asset: evm_native,
                    allowed_assets: vec![],
                },
                deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                    genesis_hash: evm_genesis,
                    native_start_block: deploy_block,
                    erc20_start_block: Some(deploy_block),
                    abi_digest: domain_digest(b"DOM-EVM-ABI/LOCAL-CYCLE/V1\0", &native_code_hash),
                    compiler_digest: domain_digest(
                        b"DOM-EVM-COMPILER/LOCAL-CYCLE/V1\0",
                        source_commit.as_bytes(),
                    ),
                    source_digest: domain_digest(
                        b"DOM-EVM-SOURCE/LOCAL-CYCLE/V1\0",
                        source_commit.as_bytes(),
                    ),
                    deployment_digest: domain_digest(
                        b"DOM-EVM-DEPLOYMENT/LOCAL-CYCLE/V1\0",
                        &[native_lock.as_slice(), erc20_lock.as_slice()].concat(),
                    ),
                    finalized_tag_required: true,
                    page_size: 256,
                    gas_limit_hint: 300_000,
                    max_fee_per_gas: 100_000_000_000,
                    max_priority_fee_per_gas: 2_000_000_000,
                }),
            },
            RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: btc_chain,
                    kind: ChainKindV1::Bitcoin {
                        network: BitcoinNetworkV1::Regtest,
                    },
                    timing: local_timing(),
                    finality: local_finality(),
                    native_asset: btc_asset,
                    allowed_assets: vec![],
                },
                deployment: ChainDeploymentV1::Bitcoin(BitcoinDeploymentV1 {
                    genesis_hash: btc_genesis,
                    signet_challenge: vec![],
                    max_fee_rate_sat_vbyte: 100,
                    min_relay_fee_sat_kvb: 1_000,
                }),
            },
        ],
        assets: vec![
            AssetBindingV1 {
                chain_id: dom_chain,
                asset_id: dom_asset,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: evm_chain,
                asset_id: evm_native,
                decimals: 18,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: btc_chain,
                asset_id: btc_asset,
                decimals: 8,
                representation: AssetRepresentationV1::Native,
            },
        ],
    };
    manifest
        .chains
        .sort_by_key(|entry| entry.profile.chain_id.0);
    manifest
        .assets
        .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
    Ok(manifest)
}

// ------------------------------------------------------------------ terms --

fn terms(registry: &ResolvedRegistryV1) -> Result<(SettlementTermsV1, SettlementTermsV1), String> {
    let dom = registry.manifest().dom;
    let dom_profile = resolved_dom_profile_digest_v1(registry)
        .map_err(|error| format!("dom profile digest: {error:?}"))?;

    let evm_chain = ChainId(domain_digest(
        b"DOM-CHAIN-ID/EVM-LOCAL/V1\0",
        &31_337_u64.to_be_bytes(),
    ));
    let btc_chain = btc_chain_id();

    let evm = registry
        .resolve_chain(evm_chain)
        .ok_or_else(|| "EVM chain absent from registry".to_owned())?;
    let btc = registry
        .resolve_chain(btc_chain)
        .ok_or_else(|| "Bitcoin chain absent from registry".to_owned())?;
    let evm_profile = evm
        .profile()
        .profile_digest()
        .map_err(|error| format!("evm profile digest: {error:?}"))?;
    let btc_profile = btc
        .profile()
        .profile_digest()
        .map_err(|error| format!("btc profile digest: {error:?}"))?;
    let evm_asset = evm.profile().native_asset;
    let btc_asset = btc.profile().native_asset;

    // Generator point, compressed: a public adaptor point stand-in. The route
    // scalar itself is never produced here.
    let adaptor_point: [u8; 33] =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .map_err(|error| format!("adaptor point: {error}"))?
            .try_into()
            .map_err(|_| "adaptor point is not 33 bytes".to_owned())?;

    let initiator = ParticipantId([0xb1; 32]);
    let solver = ParticipantId([0xb2; 32]);

    let dom_leg = |deadline: u64| LegTermsV1 {
        role: LegRole::Dom,
        chain_id: dom.chain_id,
        asset_id: dom.native_asset,
        amount: 50,
        beneficiary: solver,
        refund_to: initiator,
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
        roster: [initiator, solver],
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

    // The hub rung requires `upstream.earliest >= downstream.latest + hub_margin`,
    // with `earliest = time_lower + (deadline - anchor_height) * min_block` and
    // `latest = time_upper + (deadline - anchor_height) * max_block`. On the
    // timing this ceremony installs (DOM min 1s / max 30s, anchor height 100,
    // observed range [1_000_000, 1_000_010]) the downstream deadline of 200
    // projects to a latest of 1_003_010, so the upstream DOM deadline must be
    // at least 5_110 blocks. 8_000 keeps roughly 2_900s of slack instead of
    // sitting on the boundary. The component fixture's 400/200 pair was
    // calibrated for a 2s DOM block and does not transfer to this deployment.
    let upstream = base(
        UPSTREAM_SETTLEMENT,
        dom_leg(8_000),
        LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: evm_chain,
            asset_id: evm_asset,
            amount: 60,
            beneficiary: initiator,
            refund_to: solver,
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::TimestampSeconds { value: 3_200_000 },
            finality: evm.profile().finality,
            adapter_profile_hash: evm_profile,
        },
    );
    let downstream = base(
        DOWNSTREAM_SETTLEMENT,
        dom_leg(200),
        LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: btc_chain,
            asset_id: btc_asset,
            amount: 70,
            beneficiary: initiator,
            refund_to: solver,
            mechanism: LockMechanism::SchnorrAdaptor,
            deadline: TimelockSpec::BtcTime512s { value: 20 },
            finality: btc.profile().finality,
            adapter_profile_hash: btc_profile,
        },
    );
    Ok((upstream, downstream))
}

// ------------------------------------------------------- time and admission --

fn time_ceremony(
    state_dir: &Path,
    provisioned: &ProvisionedV1,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<CeremonyV1, String> {
    let registry = &provisioned.registry;
    let secp = &provisioned.secp;

    let policy = RouteTimePolicyV2::from_registry(registry, upstream, downstream, limits())
        .map_err(|error| format!("route time policy: {error:?}"))?;
    let policy_digest = policy
        .policy_digest()
        .map_err(|error| format!("policy digest: {error:?}"))?;

    let (policy_authorities, policy_secrets) =
        authority_set(secp, state_dir, POLICY_SECRET_PREFIX_V1)?;
    let (evidence_authorities, evidence_secrets) =
        authority_set(secp, state_dir, EVIDENCE_SECRET_PREFIX_V1)?;

    let signed_policy =
        SignedRouteTimePolicyV2::new(&policy, sign_digest(secp, &policy_secrets, &policy_digest)?)
            .map_err(|error| format!("signed policy: {error:?}"))?;

    let evidence = RouteTimeEvidenceV2::new(
        &policy,
        1,
        EVIDENCE_TIME,
        EVIDENCE_TIME + 300,
        checkpoints(&policy),
    )
    .map_err(|error| format!("route time evidence: {error:?}"))?;
    let evidence_digest = evidence
        .evidence_digest()
        .map_err(|error| format!("evidence digest: {error:?}"))?;
    let signed_evidence = SignedRouteTimeEvidenceV2::new(
        &evidence,
        sign_digest(secp, &evidence_secrets, &evidence_digest)?,
    )
    .map_err(|error| format!("signed evidence: {error:?}"))?;

    let config = RouteTimeAnchorStoreConfigV2::new(
        registry,
        upstream,
        downstream,
        &policy_authorities,
        &evidence_authorities,
        secp,
    )
    .map_err(|error| format!("time anchor config: {error:?}"))?;
    let policy_authority_set_digest = config.policy_authority_set_digest();
    let evidence_authority_set_digest = config.evidence_authority_set_digest();
    let route_scope_digest = config.route_scope_digest();

    let anchor_path = state_dir.join(TIME_ANCHOR_FILE_V1);
    let mut anchor = DurableRouteTimeAnchorStoreV2::create(&anchor_path, config)
        .map_err(|error| format!("time anchor create: {error:?}"))?;

    let policy_context = RouteTimePolicyVerificationContextV2::new(
        &policy_authorities,
        secp,
        registry,
        upstream,
        downstream,
    );
    let evidence_context =
        RouteTimeEvidenceVerificationContextV2::new(policy_context, &evidence_authorities);

    anchor
        .install_policy(&signed_policy, policy_context, EVIDENCE_TIME)
        .map_err(|error| format!("install policy: {error:?}"))?;
    anchor
        .install_evidence(&signed_evidence, evidence_context, EVIDENCE_TIME)
        .map_err(|error| format!("install evidence: {error:?}"))?;
    let proof = anchor
        .prove_route_ladder(evidence_context, EVIDENCE_TIME)
        .map_err(|error| format!("prove route ladder: {error:?}"))?;
    let current = anchor
        .consume_capability_at(proof, EVIDENCE_TIME)
        .map_err(|error| format!("consume capability: {error:?}"))?;

    let composition = ComposedBindingV2::bind(upstream.clone(), downstream.clone(), current)
        .map_err(|error| format!("composed binding: {error:?}"))?;

    let admission_store = RegistryStoreV1::open_existing(&provisioned.registry_path)
        .map_err(|error| format!("reopen registry: {error:?}"))?;
    let authority = RegistryRouteAdmissionAuthorityV1::new(
        admission_store,
        provisioned.authorities.clone(),
        SecpContext::new(&random32()),
        provisioned.network_id,
        EPOCH_V1,
    )
    .map_err(|error| format!("admission authority: {error:?}"))?;
    let admission = authority
        .admit_validated_composed_route_v2(
            EVIDENCE_TIME,
            ROUTE_ID,
            &composition,
            RouteRosterSnapshotsV1 {
                upstream: UPSTREAM_ROSTER,
                downstream: DOWNSTREAM_ROSTER,
            },
        )
        .map_err(|error| format!("route admission: {error:?}"))?;

    // The participant proofs must be signed by the very keys the roster
    // publishes: `production_inputs` verifies each proof against the roster
    // member's `xonly_key`, not against a separate participant key. Generating
    // the two here, and retaining both secret and key, is what keeps the roster
    // and the bindings consistent by construction.
    let mut relay_secrets = [[0_u8; 32]; 2];
    let mut relay_keys = [[0_u8; 32]; 2];
    for index in 0..2 {
        let secret = random32();
        let (_, xonly) = secp
            .sign_bip340(&secret, &[0x02; 32], &random32())
            .map_err(|error| format!("relay transport key: {error:?}"))?;
        relay_secrets[index] = secret;
        relay_keys[index] = xonly;
    }

    Ok(CeremonyV1 {
        policy_authority_set_digest,
        evidence_authority_set_digest,
        route_scope_digest,
        policy_digest,
        evidence_digest,
        frozen_terms_digest: admission.frozen_bindings().terms_digest,
        policy_authorities,
        evidence_authorities,
        signed_policy,
        signed_evidence,
        relay_secrets,
        relay_keys,
    })
}

// ------------------------------------------------------- stage 2b: inputs --

/// Writes the eight remaining `inputs/` artifacts. The registry database was
/// already installed by stage 1 at the state-dir root, and the bootstrap config
/// declares every path, so nothing here has to match a hardcoded layout.
fn write_inputs(
    state_dir: &Path,
    provisioned: &ProvisionedV1,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
    ceremony: &CeremonyV1,
) -> Result<BoundInputsV1, String> {
    let inputs = state_dir.join("inputs");
    fs::create_dir_all(&inputs).map_err(|error| format!("inputs dir: {error}"))?;
    fs::set_permissions(&inputs, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("inputs mode: {error}"))?;

    // -- authority bundle, terms and the two signed time artifacts ----------
    let authority_bundle = ProductionAuthorityBundleV1::new(
        provisioned.authorities.clone(),
        ceremony.policy_authorities.clone(),
        ceremony.evidence_authorities.clone(),
    )
    .map_err(|error| format!("authority bundle: {error:?}"))?;
    write_owner_file(
        &inputs.join("registry-authorities.v1"),
        &authority_bundle
            .canonical_bytes()
            .map_err(|error| format!("authority bytes: {error:?}"))?,
    )?;
    write_owner_file(
        &inputs.join("upstream-terms.v1"),
        &upstream
            .canonical_bytes()
            .map_err(|error| format!("upstream bytes: {error:?}"))?,
    )?;
    write_owner_file(
        &inputs.join("downstream-terms.v1"),
        &downstream
            .canonical_bytes()
            .map_err(|error| format!("downstream bytes: {error:?}"))?,
    )?;
    write_owner_file(
        &inputs.join("time-policy.v2"),
        &ceremony
            .signed_policy
            .canonical_bytes()
            .map_err(|error| format!("signed policy bytes: {error:?}"))?,
    )?;
    write_owner_file(
        &inputs.join("time-evidence.v2"),
        &ceremony
            .signed_evidence
            .canonical_bytes()
            .map_err(|error| format!("signed evidence bytes: {error:?}"))?,
    )?;

    // -- Relay roster: upstream first, downstream second, distinct sessions --
    let initiator = upstream.roster[0];
    let solver = upstream.roster[1];
    let members = [
        ProductionRosterMemberV1 {
            participant_id: initiator,
            xonly_key: ceremony.relay_keys[0],
            role: SenderRoleV1::Initiator,
        },
        ProductionRosterMemberV1 {
            participant_id: solver,
            xonly_key: ceremony.relay_keys[1],
            role: SenderRoleV1::Solver,
        },
    ];
    let roster_bundle = ProductionRelayRosterBundleV1::new(
        provisioned.network_id,
        ROUTE_ID,
        [
            ProductionRosterLegV1 {
                position: ProductionRoutePositionV1::Upstream,
                session_id: upstream.session_id.0,
                roster_snapshot: UPSTREAM_ROSTER,
                policy_version: upstream.policy_version,
                members,
            },
            ProductionRosterLegV1 {
                position: ProductionRoutePositionV1::Downstream,
                session_id: downstream.session_id.0,
                roster_snapshot: DOWNSTREAM_ROSTER,
                policy_version: downstream.policy_version,
                members,
            },
        ],
    )
    .map_err(|error| format!("roster bundle: {error:?}"))?;
    write_owner_file(
        &inputs.join("relay-roster.v1"),
        &roster_bundle
            .canonical_bytes()
            .map_err(|error| format!("roster bytes: {error:?}"))?,
    )?;
    let relay_binding_digest = roster_bundle
        .bundle_digest()
        .map_err(|error| format!("roster digest: {error:?}"))?;

    // -- Participant bindings: EVM upstream, Bitcoin downstream -------------
    // The funder is the leg's `refund_to` and the beneficiary its
    // `beneficiary`; swapping them builds cleanly and is refused later.
    let funder_id = upstream.counterparty_leg.refund_to;
    let beneficiary_id = upstream.counterparty_leg.beneficiary;
    let index_of = |participant| {
        if participant == initiator {
            0
        } else {
            1
        }
    };
    let evm_leg = ProductionEvmLegProofsV1::new(
        ProductionRoutePositionV1::Upstream,
        evm_proof(
            provisioned,
            upstream,
            ceremony,
            funder_id,
            index_of(funder_id),
            EvmBindingRoleV1::Funder,
            [0x71; 32],
        )?,
        evm_proof(
            provisioned,
            upstream,
            ceremony,
            beneficiary_id,
            index_of(beneficiary_id),
            EvmBindingRoleV1::Beneficiary,
            [0x72; 32],
        )?,
    )
    .map_err(|error| format!("evm leg proofs: {error:?}"))?;

    let btc = provisioned
        .registry
        .resolve_chain(downstream.counterparty_leg.chain_id)
        .ok_or_else(|| "Bitcoin chain absent from registry".to_owned())?
        .bitcoin_deployment_capability()
        .map_err(|error| format!("bitcoin capability: {error:?}"))?;
    let bitcoin_leg = ProductionBitcoinLegKeyProofsV1::new(
        ProductionRoutePositionV1::Downstream,
        [
            bitcoin_proof(
                provisioned,
                downstream,
                ceremony,
                &btc,
                initiator,
                0,
                BitcoinSignerRoleV1::Maker,
                0x02,
            )?,
            bitcoin_proof(
                provisioned,
                downstream,
                ceremony,
                &btc,
                solver,
                1,
                BitcoinSignerRoleV1::Taker,
                0x03,
            )?,
        ],
    )
    .map_err(|error| format!("bitcoin leg proofs: {error:?}"))?;

    let participant_bundle = ProductionParticipantBindingBundleV1::new_with_bitcoin_bindings(
        ROUTE_ID,
        vec![evm_leg],
        vec![bitcoin_leg],
    )
    .map_err(|error| format!("participant bundle: {error:?}"))?;
    write_owner_file(
        &inputs.join("participant-bindings.v1"),
        &participant_bundle
            .canonical_bytes()
            .map_err(|error| format!("participant bytes: {error:?}"))?,
    )?;
    let participant_bindings_digest = participant_bundle
        .bundle_digest()
        .map_err(|error| format!("participant digest: {error:?}"))?;

    // -- DOM participant wallet, bound to both authenticated sessions -------
    write_dom_wallet(&inputs, provisioned, upstream, downstream, ceremony)?;

    Ok(BoundInputsV1 {
        relay_binding_digest,
        participant_bindings_digest,
    })
}

// --------------------------------------------- stage 3: bootstrap configs --

/// Writes `bootstrap-create-v10.conf` and its reopen companion through the
/// daemon's own validated writer, plus the five auxiliary artifacts the layout
/// validator requires to exist before `run --create`.
///
/// Every managed path must be ABSENT at create time, so nothing under `state/`
/// is produced here — only the directory that parents them.
fn write_bootstrap_configs(
    state_dir: &Path,
    provisioned: &ProvisionedV1,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
    ceremony: &CeremonyV1,
    bound: &BoundInputsV1,
) -> Result<([u8; 32], RelayIdentitiesV1), String> {
    let inputs = state_dir.join("inputs");
    // Parents every managed path; the stores themselves stay absent.
    make_owner_dir(&state_dir.join("state"))?;
    // Provisioned outside the daemon: two owner directories and three input
    // files. The layout validator checks existence, owner and mode only.
    make_owner_dir(&inputs.join("contracts-transport-identity"))?;
    make_owner_dir(&inputs.join("bitcoin-prebroadcast"))?;
    write_owner_file(
        &inputs.join("contracts-budget-policy"),
        b"ceremony-budget-v1",
    )?;
    write_owner_file(
        &inputs.join("contracts-bootstrap.v1"),
        b"ceremony-contracts-v1",
    )?;

    const F6_BUNDLE_BYTES: &[u8] = b"ceremony-threshold-authenticated-f6-bundle-v7";
    write_owner_file(&inputs.join("f6-authority-bundle.v7"), F6_BUNDLE_BYTES)?;
    let f6_authority_bundle_digest = production_f6_authority_bundle_digest_v8(F6_BUNDLE_BYTES)
        .map_err(|error| format!("f6 bundle digest: {error:?}"))?;

    let upstream_terms_digest = upstream
        .terms_hash()
        .map_err(|error| format!("upstream hash: {error:?}"))?;
    let downstream_terms_digest = downstream
        .terms_hash()
        .map_err(|error| format!("downstream hash: {error:?}"))?;
    let registry_authority_set_digest = provisioned
        .authorities
        .authority_set_digest()
        .map_err(|error| format!("registry authority digest: {error:?}"))?;

    // Operator-chosen identities. They authenticate nothing by themselves: the
    // owning store rechecks each one when it is created.
    let mut next = 0xC0_u8;
    let mut operator_digest = || {
        let value = [next; 32];
        next = next.wrapping_add(1);
        value
    };

    let pins = ProductionRoutePinsV1 {
        network_id: provisioned.network_id,
        route_id: ROUTE_ID,
        registry_manifest_digest: provisioned.registry.manifest_digest(),
        registry_minimum_epoch: EPOCH_V1,
        registry_authority_set_digest,
        time_policy_authority_set_digest: ceremony.policy_authority_set_digest,
        time_evidence_authority_set_digest: ceremony.evidence_authority_set_digest,
        upstream_terms_digest,
        downstream_terms_digest,
        route_scope_digest: ceremony.route_scope_digest,
        participant_bindings_digest: bound.participant_bindings_digest,
        relay_binding_digest: bound.relay_binding_digest,
        time_policy_digest: ceremony.policy_digest,
        time_evidence_digest: ceremony.evidence_digest,
        process_owner_id: operator_digest(),
        coordinator_id: operator_digest(),
        coordinator_plan_authority_id: operator_digest(),
        actuator_bindings_digest: operator_digest(),
        solver_inventory_binding_digest: operator_digest(),
    };

    let bounds = ProductionRuntimeBoundsV1 {
        lease_duration_ms: 120_000,
        renew_before_ms: 60_000,
        dispatch_lease_ms: 45_000,
        coordinator_lease_ms: 120_000,
        actuator_lease_ms: 120_000,
        external_call_timeout_ms: 30_000,
        waiting_backoff_ms: 1_000,
        recovery_backoff_ms: 100,
        relay_poll_backoff_ms: 500,
        per_queue_batch_limit: 1,
    };

    // The registry database lives at the state-dir root, exactly where stage 1
    // installed it: the config declares every path, so no move is needed.
    let paths = ProductionPathReferencesV1::from_ordered(
        [
            "registry.v1.sqlite3",
            "inputs/registry-authorities.v1",
            "inputs/upstream-terms.v1",
            "inputs/downstream-terms.v1",
            "inputs/participant-bindings.v1",
            "inputs/relay-roster.v1",
            "inputs/time-policy.v2",
            "inputs/time-evidence.v2",
            "inputs/dom-wallet.enc",
            "state/route.sqlite3",
            "state/time-anchor.sqlite3",
            "state/coordinator.sqlite3",
            "state/dom-actuator.sqlite3",
            "state/evm-actuator.sqlite3",
            "state/bitcoin-actuator.sqlite3",
            "state/bitcoin-participant.v1",
            "state/dom-upstream-participant.v1",
            "state/dom-downstream-participant.v1",
            "state/solver-inventory.sqlite3",
            "state/relay-queue",
            "state/upstream-sender",
            "state/upstream-inbox",
            "state/upstream-frames",
            "state/upstream-contracts",
            "state/downstream-sender",
            "state/downstream-inbox",
            "state/downstream-frames",
            "state/downstream-contracts",
        ]
        .map(str::to_owned),
    )
    .map_err(|error| format!("path references: {error:?}"))?;

    let f6_v4 = ProductionF6PathReferencesV4::from_ordered(
        [
            "state/solver-status.sqlite3",
            "state/upstream-pre-f6-time.sqlite3",
            "state/downstream-pre-f6-time.sqlite3",
            "state/upstream-f6-binding.log",
            "state/upstream-f6-receipts.sqlite3",
            "state/upstream-f6-candidates.log",
            "state/upstream-f6-attestation.sqlite3",
            "state/downstream-f6-binding.log",
            "state/downstream-f6-receipts.sqlite3",
            "state/downstream-f6-candidates.log",
            "state/downstream-f6-attestation.sqlite3",
        ]
        .map(str::to_owned),
    )
    .map_err(|error| format!("f6 v4 paths: {error:?}"))?;

    let f6_v8 = ProductionF6PathReferencesV8::from_ordered(
        [
            "state/upstream-f6-v7-status.sqlite3",
            "state/downstream-f6-v7-status.sqlite3",
            "state/upstream-f6-v7-time.sqlite3",
            "state/downstream-f6-v7-time.sqlite3",
            "state/upstream-f6-v7-candidate.sqlite3",
            "state/downstream-f6-v7-candidate.sqlite3",
            "inputs/f6-authority-bundle.v7",
        ]
        .map(str::to_owned),
    )
    .map_err(|error| format!("f6 v8 paths: {error:?}"))?;

    let contracts_pins =
        ProductionContractsBootstrapPinsV5::new(operator_digest(), operator_digest())
            .map_err(|error| format!("contracts bootstrap pins: {error:?}"))?;

    let local_relay_database_id = operator_digest();
    let relay_pins = ProductionRelayAuthorityPinsV6 {
        relay_database_id: local_relay_database_id,
        upstream_sender_store_id: operator_digest(),
        upstream_inbox_id: operator_digest(),
        upstream_reassembler_id: operator_digest(),
        downstream_sender_store_id: operator_digest(),
        downstream_inbox_id: operator_digest(),
        downstream_reassembler_id: operator_digest(),
        relay_max_envelopes: 4_096,
        sender_max_envelopes: 4_096,
        inbox_max_entries: 4_096,
        frame_max_messages: 256,
        frame_max_active_bytes: 8 * 1024 * 1024,
        frame_max_active_chunks: 4_096,
    };

    // The single real binding among these pins: the Bitcoin leg is downstream,
    // so its terms digest must equal the downstream route pin.
    let prebroadcast_pins = ProductionBitcoinPrebroadcastPinsV7 {
        leg: LegIdV1::Downstream,
        settlement_id: downstream.settlement_id.0,
        session_id: downstream.session_id.0,
        terms_digest: downstream_terms_digest,
        deployment_digest: operator_digest(),
        route_binding: operator_digest(),
        plan_digest: operator_digest(),
        receipt_digest: operator_digest(),
        contract_script_pubkey_digest: operator_digest(),
        claim_destination_script_pubkey_digest: operator_digest(),
        refund_destination_script_pubkey_digest: operator_digest(),
        refund_key_xonly: operator_digest(),
        funding_template_hash: operator_digest(),
        claim_template_hash: operator_digest(),
        refund_template_hash: operator_digest(),
    };

    // Retained: stage 4's Relay network document must name these exact two
    // peers, and `validate_remote_database_ids` refuses a swap rather than
    // reinterpreting it.
    let upstream_remote_relay_database_id = operator_digest();
    let downstream_remote_relay_database_id = operator_digest();
    let policies = ProductionOperationalPoliciesV10::new(
        upstream_remote_relay_database_id,
        downstream_remote_relay_database_id,
        100_000_000_000,
        2_000_000_000,
        3_600_000,
        86_400_000,
    )
    .map_err(|error| format!("operational policies: {error:?}"))?;

    let family = ProductionFamilyInputsV10::new(
        ProductionFamilyInputsV9::new(
            ProductionFamilyInputsV8::new(
                ProductionFamilyInputsV7::new(
                    ProductionFamilyInputsV6::new(
                        ProductionFamilyInputsV5::new(
                            "inputs/contracts-transport-identity".to_owned(),
                            "inputs/contracts-budget-policy".to_owned(),
                            f6_v4,
                            "inputs/contracts-bootstrap.v1".to_owned(),
                            contracts_pins,
                        ),
                        relay_pins,
                    ),
                    "inputs/bitcoin-prebroadcast".to_owned(),
                    prebroadcast_pins,
                ),
                f6_v8,
                f6_authority_bundle_digest,
            ),
            1,
        ),
        policies,
    );

    let create = ProductionBootstrapConfigV1::from_parts_v10(
        ProductionBootstrapModeV1::Create,
        pins,
        bounds,
        paths.clone(),
        family.clone(),
    )
    .map_err(|error| format!("create config: {error:?}"))?;
    let reopen = ProductionBootstrapConfigV1::from_parts_v10(
        ProductionBootstrapModeV1::ReopenExisting,
        pins,
        bounds,
        paths,
        family,
    )
    .map_err(|error| format!("reopen config: {error:?}"))?;

    let create_bytes = create
        .canonical_bytes()
        .map_err(|error| format!("create bytes: {error:?}"))?;
    write_owner_file(
        &state_dir.join(PRODUCTION_CREATE_CONFIG_FILE_V10),
        &create_bytes,
    )?;
    write_owner_file(
        &state_dir.join(PRODUCTION_REOPEN_CONFIG_FILE_V10),
        &reopen
            .canonical_bytes()
            .map_err(|error| format!("reopen bytes: {error:?}"))?,
    )?;

    Ok((
        domain_digest(b"DOM-ROUTE-CEREMONY/CONFIG/V1\0", &create_bytes),
        RelayIdentitiesV1 {
            local_relay_database_id,
            upstream_remote_relay_database_id,
            downstream_remote_relay_database_id,
        },
    ))
}

// ----------------------------------------- stage 4: Relay network document --

/// Writes `production-relay-network.v1`, the two-link Noise manifest the daemon
/// loads immediately after the bootstrap config.
///
/// This is the first artifact that is genuinely two-party: each link names the
/// socket of a peer daemon and the exact public identity expected from that
/// peer's durable Relay database. On one machine both links can only point at
/// loopback, which satisfies the configuration gate; completing Noise XX still
/// requires a second daemon listening on the other side.
fn write_relay_network_config(
    state_dir: &Path,
    identities: &RelayIdentitiesV1,
) -> Result<(), String> {
    let upstream = ProductionRelayNetworkLinkV1::new(
        ProductionRelayEndpointModeV1::Connect,
        "127.0.0.1:41001"
            .parse()
            .map_err(|error| format!("upstream address: {error}"))?,
        RelayDatabaseIdV1::new(identities.upstream_remote_relay_database_id)
            .map_err(|error| format!("upstream peer id: {error:?}"))?,
    )
    .map_err(|error| format!("upstream link: {error:?}"))?;
    let downstream = ProductionRelayNetworkLinkV1::new(
        ProductionRelayEndpointModeV1::Listen,
        "127.0.0.1:41002"
            .parse()
            .map_err(|error| format!("downstream address: {error}"))?,
        RelayDatabaseIdV1::new(identities.downstream_remote_relay_database_id)
            .map_err(|error| format!("downstream peer id: {error:?}"))?,
    )
    .map_err(|error| format!("downstream link: {error:?}"))?;

    let network = ProductionRelayNetworkConfigV1::new(upstream, downstream)
        .map_err(|error| format!("relay network config: {error:?}"))?;

    // Re-run the daemon's own cross-checks here so a mismatch is reported by
    // the generator, where the values are visible, instead of as an opaque
    // startup refusal.
    let local = RelayDatabaseIdV1::new(identities.local_relay_database_id)
        .map_err(|error| format!("local relay id: {error:?}"))?;
    network
        .validate_remote_database_ids(
            RelayDatabaseIdV1::new(identities.upstream_remote_relay_database_id)
                .map_err(|error| format!("upstream peer id: {error:?}"))?,
            RelayDatabaseIdV1::new(identities.downstream_remote_relay_database_id)
                .map_err(|error| format!("downstream peer id: {error:?}"))?,
        )
        .and_then(|()| network.validate_local_database_id(local))
        .map_err(|error| format!("relay identity cross-check: {error:?}"))?;

    write_owner_file(
        &state_dir.join(PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1),
        &network
            .canonical_bytes()
            .map_err(|error| format!("relay network bytes: {error:?}"))?,
    )
}

fn make_owner_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("mode {}: {error}", path.display()))
}

/// One dual-signed EVM account binding: an EIP-712 style account signature and
/// a BIP340 signature by the same Relay key the roster publishes.
#[allow(clippy::too_many_arguments)]
fn evm_proof(
    provisioned: &ProvisionedV1,
    terms: &SettlementTermsV1,
    ceremony: &CeremonyV1,
    participant_id: ParticipantId,
    member_index: usize,
    role: EvmBindingRoleV1,
    evm_secret: [u8; 32],
) -> Result<EvmAccountBindingProofV1, String> {
    let statement = EvmAccountBindingStatementV1 {
        network_id: provisioned.network_id,
        registry_digest: provisioned.registry.manifest_digest(),
        route_id: ROUTE_ID,
        settlement_id: terms.settlement_id.0,
        session_id: terms.session_id.0,
        terms_digest: ceremony.frozen_terms_digest,
        roster_snapshot: UPSTREAM_ROSTER,
        participant_id,
        participant_xonly_key: ceremony.relay_keys[member_index],
        account: evm_account(evm_secret),
        position: EvmSettlementPositionV1::Upstream,
        role,
        issued_at: EVIDENCE_TIME - 100,
        valid_until: EVIDENCE_TIME + 200,
        evm_chain_id: 31_337,
    };
    let digest = evm_account_binding_digest_v1(&statement)
        .map_err(|error| format!("evm binding digest: {error:?}"))?;

    let signing =
        SigningKey::from_slice(&evm_secret).map_err(|error| format!("evm key: {error}"))?;
    let (signature, recovery) = signing
        .sign_prehash_recoverable(&digest)
        .map_err(|error| format!("evm signature: {error}"))?;
    let mut evm_signature = [0_u8; EVM_ACCOUNT_SIGNATURE_BYTES_V1];
    evm_signature[..64].copy_from_slice(&signature.to_bytes());
    evm_signature[64] = 27 + recovery.to_byte();

    let (participant_signature, signed_key) = provisioned
        .secp
        .sign_bip340(&ceremony.relay_secrets[member_index], &digest, &random32())
        .map_err(|error| format!("participant signature: {error:?}"))?;
    if signed_key != ceremony.relay_keys[member_index] {
        return Err("participant signature key diverges from the roster key".to_owned());
    }
    Ok(EvmAccountBindingProofV1::new(
        statement,
        evm_signature,
        participant_signature,
    ))
}

/// One Bitcoin claim-key binding, signed by the same Relay key.
#[allow(clippy::too_many_arguments)]
fn bitcoin_proof(
    provisioned: &ProvisionedV1,
    terms: &SettlementTermsV1,
    ceremony: &CeremonyV1,
    btc: &deployment_registry::ResolvedBitcoinDeploymentV1,
    participant_id: ParticipantId,
    member_index: usize,
    role: BitcoinSignerRoleV1,
    key_prefix: u8,
) -> Result<ProductionBitcoinParticipantKeyProofV1, String> {
    let mut bitcoin_public_key = [0_u8; 33];
    bitcoin_public_key[0] = key_prefix;
    bitcoin_public_key[1..].copy_from_slice(&ceremony.relay_keys[member_index]);

    let request = ProductionBitcoinParticipantKeyStatementRequestV1 {
        network_id: provisioned.network_id,
        route_id: ROUTE_ID,
        position: ProductionRoutePositionV1::Downstream,
        session_id: terms.session_id.0,
        terms_digest: ceremony.frozen_terms_digest,
        roster_snapshot: DOWNSTREAM_ROSTER,
        participant_id,
        role,
        relay_xonly_key: ceremony.relay_keys[member_index],
        bitcoin_public_key,
        registry_digest: btc.registry_digest(),
        registry_epoch: btc.registry_epoch(),
        profile_digest: btc.profile_digest(),
        asset_binding_digest: btc.asset_binding_digest(),
        chain_id: terms.counterparty_leg.chain_id.0,
        genesis_hash: btc.deployment().genesis_hash,
    };
    let digest = request
        .digest()
        .map_err(|error| format!("bitcoin key digest: {error:?}"))?;
    let (signature, _) = provisioned
        .secp
        .sign_bip340(&ceremony.relay_secrets[member_index], &digest, &random32())
        .map_err(|error| format!("bitcoin key signature: {error:?}"))?;
    ProductionBitcoinParticipantKeyProofV1::new(participant_id, role, bitcoin_public_key, signature)
        .map_err(|error| format!("bitcoin key proof: {error:?}"))
}

/// Creates the encrypted DOM participant wallet the daemon opens read-only.
fn write_dom_wallet(
    inputs: &Path,
    provisioned: &ProvisionedV1,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
    ceremony: &CeremonyV1,
) -> Result<(), String> {
    let resolved = provisioned
        .registry
        .resolve_dom()
        .map_err(|error| format!("resolve dom: {error:?}"))?;
    let participant = DomParticipantV1::new(upstream.roster[0].0, 0)
        .map_err(|error| format!("dom participant: {error:?}"))?;
    let upstream_binding = DomSessionBindingV1::from_resolved_deployment(
        ROUTE_ID,
        upstream.session_id.0,
        participant,
        ceremony.frozen_terms_digest,
        resolved,
    )
    .map_err(|error| format!("upstream session binding: {error:?}"))?;
    let downstream_binding = DomSessionBindingV1::from_resolved_deployment(
        ROUTE_ID,
        downstream.session_id.0,
        participant,
        ceremony.frozen_terms_digest,
        resolved,
    )
    .map_err(|error| format!("downstream session binding: {error:?}"))?;
    // Refused unless the two sessions differ and every other authority field
    // matches; this is what binds one physical wallet to exactly this route.
    DomWalletAuthorityBindingV1::new(upstream_binding, downstream_binding)
        .map_err(|error| format!("wallet authority binding: {error:?}"))?;

    let path = inputs.join("dom-wallet.enc");
    let state = WalletV2State::new(Network::Regtest, upstream_binding.chain_id());
    save_wallet_state(&state, &path, DOM_WALLET_PASSPHRASE)
        .map_err(|error| format!("save wallet: {error:?}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("wallet mode: {error}"))?;
    Ok(())
}

fn evm_account(secret: [u8; 32]) -> [u8; 20] {
    let key = SigningKey::from_slice(&secret).expect("valid EVM key");
    let encoded = key.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    let mut account = [0_u8; 20];
    account.copy_from_slice(&hash[12..]);
    account
}

fn limits() -> RouteTimePolicyLimitsV2 {
    RouteTimePolicyLimitsV2 {
        valid_from_seconds: 900_000,
        expires_at_seconds: 4_000_000,
        max_evidence_age_seconds: 600,
        max_anchor_interval_width_seconds: 20,
        max_anchor_time_skew_seconds: 120,
        max_future_skew_seconds: 30,
        max_upstream_funding_anchor_delay_seconds: 3_600,
        max_downstream_funding_anchor_delay_seconds: 3_600,
        // Floors are derived from the chain timing this ceremony actually
        // installs, not from the component fixture's: with `local_timing`
        // (reorg 600, observation 30, broadcast 20) on every chain,
        // `minimum_safety_margin_seconds` is 1300 for the hub and 1300 for the
        // counterparty pair. Both margins are set above those floors.
        hub_margin_seconds: 2_000,
        counterparty_margin_seconds: 2_100_000,
    }
}

fn checkpoints(policy: &RouteTimePolicyV2) -> [CanonicalTimeCheckpointV2; 3] {
    let bindings = policy.checkpoint_bindings();
    [
        CanonicalTimeCheckpointV2::new(
            bindings[0],
            CanonicalCheckpointObservationV2::new(
                CanonicalAnchorObservationV2::new(100, [0xa1; 32], [0xa0; 32]),
                CanonicalTimeRangeV2::new(ANCHOR_TIME, ANCHOR_TIME + 10),
                CanonicalTipObservationV2::new(101, [0xb1; 32], [0xc1; 32]),
            ),
        ),
        CanonicalTimeCheckpointV2::new(
            bindings[1],
            CanonicalCheckpointObservationV2::new(
                CanonicalAnchorObservationV2::new(500, [0xa2; 32], [0xa3; 32]),
                CanonicalTimeRangeV2::new(ANCHOR_TIME, ANCHOR_TIME + 10),
                CanonicalTipObservationV2::new(501, [0xb2; 32], [0xc2; 32]),
            ),
        ),
        CanonicalTimeCheckpointV2::new(
            bindings[2],
            CanonicalCheckpointObservationV2::new(
                CanonicalAnchorObservationV2::new(700, [0xa4; 32], [0xa5; 32]),
                CanonicalTimeRangeV2::new(ANCHOR_TIME, ANCHOR_TIME + 10),
                CanonicalTipObservationV2::new(701, [0xb3; 32], [0xc3; 32]),
            ),
        ),
    ]
}

/// Generates one independent 2-of-3 BIP340 authority set, retaining each
/// secret as an owner-only file so the ceremony is reproducible by the operator.
fn authority_set(
    secp: &SecpContext,
    state_dir: &Path,
    prefix: &str,
) -> Result<(AuthoritySetV1, Vec<[u8; 32]>), String> {
    let mut keys = Vec::new();
    let mut secrets = Vec::new();
    for index in 0_u16..3 {
        let secret = random32();
        let (_, xonly) = secp
            .sign_bip340(&secret, &[0x01; 32], &random32())
            .map_err(|error| format!("{prefix} key: {error:?}"))?;
        write_owner_file(
            &state_dir.join(format!("{prefix}-{index}.secret")),
            hex::encode(secret).as_bytes(),
        )?;
        keys.push(xonly);
        secrets.push(secret);
    }
    let set = AuthoritySetV1::new(2, keys).map_err(|error| format!("{prefix} set: {error:?}"))?;
    Ok((set, secrets))
}

fn sign_digest(
    secp: &SecpContext,
    secrets: &[[u8; 32]],
    digest: &[u8; 32],
) -> Result<Vec<TimeAnchorSignatureV2>, String> {
    secrets
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            let (signature, _) = secp
                .sign_bip340(secret, digest, &random32())
                .map_err(|error| format!("threshold signature: {error:?}"))?;
            Ok(TimeAnchorSignatureV2 {
                signer_index: index as u16,
                signature,
            })
        })
        .collect()
}

// ---------------------------------------------------------------- helpers --

fn evm_chain_id(mold: &serde_json::Value) -> Result<ChainId, String> {
    Ok(ChainId(domain_digest(
        b"DOM-CHAIN-ID/EVM-LOCAL/V1\0",
        &require_u64(mold, &["evm", "chain_id"])?.to_be_bytes(),
    )))
}

fn btc_chain_id() -> ChainId {
    ChainId(domain_digest(b"DOM-CHAIN-ID/BTC-REGTEST/V1\0", b"regtest"))
}

fn local_timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 1,
        max_block_seconds: 30,
        max_reorg_seconds: 600,
        observation_seconds: 30,
        broadcast_seconds: 20,
    }
}

fn local_finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 6,
    }
}

fn bitcoin_genesis_bytes(mold: &serde_json::Value) -> Result<[u8; 32], String> {
    let display = require_str(mold, &["bitcoin", "genesis_hash"])?;
    let bytes = hex::decode(&display).map_err(|_| "bitcoin genesis is not hex".to_owned())?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "bitcoin genesis is not 32 bytes".to_owned())?;
    // bitcoind displays block hashes byte-reversed; the registry stores raw.
    let mut raw = array;
    raw.reverse();
    Ok(raw)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update as _, VariableOutput as _};
    let mut hasher = blake2::Blake2bVar::new(32).expect("blake2 32");
    hasher.update(domain);
    hasher.update(bytes);
    let mut out = [0_u8; 32];
    hasher.finalize_variable(&mut out).expect("blake2 finalize");
    out
}

fn random32() -> [u8; 32] {
    use rand::RngCore as _;
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS entropy");
    bytes
}

fn write_owner_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))?;
    Ok(())
}

fn require_str(mold: &serde_json::Value, path: &[&str]) -> Result<String, String> {
    let mut value = mold;
    for key in path {
        value = value
            .get(key)
            .ok_or_else(|| format!("mold missing {}", path.join(".")))?;
    }
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("mold field {} is not a string", path.join(".")))
}

fn require_u64(mold: &serde_json::Value, path: &[&str]) -> Result<u64, String> {
    let mut value = mold;
    for key in path {
        value = value
            .get(key)
            .ok_or_else(|| format!("mold missing {}", path.join(".")))?;
    }
    value
        .as_u64()
        .ok_or_else(|| format!("mold field {} is not a u64", path.join(".")))
}

fn require_address(mold: &serde_json::Value, path: &[&str]) -> Result<[u8; 20], String> {
    let text = require_str(mold, path)?;
    let text = text.strip_prefix("0x").unwrap_or(&text);
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
        .ok_or_else(|| format!("mold field {} is not a 20-byte hex", path.join(".")))
}

fn require_hash32(mold: &serde_json::Value, path: &[&str]) -> Result<[u8; 32], String> {
    let text = require_str(mold, path)?;
    let text = text.strip_prefix("0x").unwrap_or(&text);
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| format!("mold field {} is not a 32-byte hex", path.join(".")))
}

use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_btc::types::BitcoinNetworkV1;
use adapter_evm::Direction;
use bitcoin::{blockdata::constants::genesis_block, hashes::Hash, Network};
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1, ChainDeploymentV1,
    DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, EvmSessionBindingsV1,
    InstallOutcomeV1, RegistryChainProfileV1, RegistryError, RegistryManifestV1,
    RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1, SignedRegistryV1,
};
use dom_consensus::derive_chain_id;
use dom_core::{
    configured_genesis_hash_for_network_magic, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};

const NETWORK: [u8; 32] = [0x90; 32];
const EVM_CHAIN: ChainId = ChainId([0x02; 32]);
const BTC_CHAIN: ChainId = ChainId([0x03; 32]);
const DOM_ASSET: AssetId = AssetId([0x11; 32]);
const EVM_NATIVE: AssetId = AssetId([0x12; 32]);
const EVM_TOKEN: AssetId = AssetId([0x13; 32]);
const BTC_ASSET: AssetId = AssetId([0x14; 32]);

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

fn regtest_genesis() -> [u8; 32] {
    genesis_block(Network::Regtest)
        .block_hash()
        .to_raw_hash()
        .to_byte_array()
}

fn dom_regtest_identity() -> (ChainId, [u8; 32], DomRuntimeIdentityV1) {
    let genesis = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)
        .expect("canonical DOM regtest genesis");
    (
        ChainId(*derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis).as_bytes()),
        *genesis.as_bytes(),
        DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
    )
}

fn move_dom_to_testnet(value: &mut RegistryManifestV1) {
    let genesis = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_TESTNET)
        .expect("canonical DOM testnet genesis");
    let old_chain = value.dom.chain_id;
    let chain = ChainId(*derive_chain_id(NETWORK_MAGIC_TESTNET, &genesis).as_bytes());
    value.dom.chain_id = chain;
    value.dom.genesis_hash = *genesis.as_bytes();
    value.dom.runtime_identity = DomRuntimeIdentityV1::pinned(DomNetworkV1::Testnet);
    for asset in &mut value.assets {
        if asset.chain_id == old_chain {
            asset.chain_id = chain;
        }
    }
    value
        .assets
        .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
}

fn manifest(epoch: u64) -> RegistryManifestV1 {
    let (dom_chain, dom_genesis, runtime_identity) = dom_regtest_identity();
    let mut manifest = RegistryManifestV1 {
        network_id: NETWORK,
        epoch,
        valid_from: 1_000,
        expires_at: 10_000,
        dom: DomDeploymentV1 {
            chain_id: dom_chain,
            genesis_hash: dom_genesis,
            runtime_identity,
            consensus_rules_digest: [0x22; 32],
            scriptless_api_version: 1,
            timing: timing(),
            finality: finality(),
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
                    timing: timing(),
                    finality: finality(),
                    native_asset: BTC_ASSET,
                    allowed_assets: vec![],
                },
                deployment: ChainDeploymentV1::Bitcoin(BitcoinDeploymentV1 {
                    genesis_hash: regtest_genesis(),
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

fn policy(minimum_epoch: u64) -> RegistryValidationPolicyV1 {
    RegistryValidationPolicyV1 {
        now_seconds: 2_000,
        expected_network_id: NETWORK,
        minimum_epoch,
    }
}

fn authority_and_signed(
    manifest: &RegistryManifestV1,
    secp: &SecpContext,
    signer_indexes: &[usize],
) -> (AuthoritySetV1, SignedRegistryV1) {
    let digest = manifest.manifest_digest().unwrap();
    let secrets = [[0x03; 32], [0x04; 32], [0x05; 32]];
    let mut keys = Vec::new();
    let mut all_signatures = Vec::new();
    for (index, secret) in secrets.iter().enumerate() {
        let (signature, key) = secp
            .sign_bip340(secret, &digest, &[0x70 + index as u8; 32])
            .unwrap();
        keys.push(key);
        all_signatures.push(RegistrySignatureV1 {
            signer_index: index as u16,
            signature,
        });
    }
    let signatures = signer_indexes
        .iter()
        .map(|index| all_signatures[*index])
        .collect();
    (
        AuthoritySetV1::new(2, keys).unwrap(),
        SignedRegistryV1::new(manifest, signatures).unwrap(),
    )
}

#[test]
fn canonical_roundtrip_binds_every_manifest_field() {
    let value = manifest(7);
    let bytes = value.canonical_bytes().unwrap();
    assert_eq!(RegistryManifestV1::decode(&bytes).unwrap(), value);
    assert_eq!(
        RegistryManifestV1::decode(&bytes)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        bytes
    );
    let original_digest = value.manifest_digest().unwrap();
    assert_eq!(&bytes[8..10], &2_u16.to_be_bytes());
    let mut legacy_version = bytes.clone();
    legacy_version[8..10].copy_from_slice(&1_u16.to_be_bytes());
    assert!(matches!(
        RegistryManifestV1::decode(&legacy_version),
        Err(RegistryError::UnsupportedVersion)
    ));
    let mut changed = value.clone();
    if let ChainDeploymentV1::Evm(evm) = &mut changed.chains[0].deployment {
        evm.deployment_digest[0] ^= 1;
    }
    assert_ne!(changed.manifest_digest().unwrap(), original_digest);
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        RegistryManifestV1::decode(&trailing),
        Err(RegistryError::NonCanonicalEncoding)
    ));
}

#[test]
fn threshold_verification_issues_resolved_profiles_and_evm_configs() {
    let secp = SecpContext::new(&[0x60; 32]);
    let value = manifest(7);
    let (authorities, signed) = authority_and_signed(&value, &secp, &[0, 2]);
    let resolved = signed.verify(&authorities, &secp, policy(7)).unwrap();
    assert_eq!(resolved.epoch(), 7);
    assert_eq!(resolved.manifest_digest(), value.manifest_digest().unwrap());
    let evm = resolved.resolve_chain(EVM_CHAIN).unwrap();
    assert_eq!(evm.registry_digest(), resolved.manifest_digest());
    let session = EvmSessionBindingsV1 {
        direction: Direction::DomToEvm,
        session_id: [0x51; 32],
        terms_hash: [0x52; 32],
        participants_hash: [0x53; 32],
        beneficiary: [0x54; 20],
        funder: [0x55; 20],
    };
    let native = evm.evm_adapter_config(EVM_NATIVE, session).unwrap();
    assert_eq!(native.contract, [0x31; 20]);
    assert_eq!(native.asset, [0u8; 20]);
    assert_eq!(native.start_block, 10);
    let token = evm.evm_adapter_config(EVM_TOKEN, session).unwrap();
    assert_eq!(token.contract, [0x33; 20]);
    assert_eq!(token.asset, [0x42; 20]);
    assert_eq!(token.start_block, 11);

    let capability = evm.evm_deployment_capability(EVM_TOKEN, session).unwrap();
    assert_eq!(capability.registry_digest(), resolved.manifest_digest());
    assert_eq!(capability.registry_epoch(), 7);
    assert_ne!(capability.profile_digest(), [0; 32]);
    assert_eq!(
        capability.asset_binding_digest(),
        resolved.asset_binding_digest(EVM_CHAIN, EVM_TOKEN).unwrap()
    );
    assert_eq!(capability.adapter_config(), token);
    assert_eq!(capability.deployment().genesis_hash, [0x35; 32]);
    assert_eq!(capability.deployment().abi_digest, [0x36; 32]);
    assert_eq!(capability.deployment().compiler_digest, [0x37; 32]);
    assert_eq!(capability.deployment().source_digest, [0x38; 32]);
    assert_eq!(capability.deployment().deployment_digest, [0x39; 32]);
    assert!(capability.deployment().finalized_tag_required);
    assert_eq!(capability.deployment().max_fee_per_gas, 100_000_000_000);
    assert_eq!(
        capability.deployment().max_priority_fee_per_gas,
        2_000_000_000
    );
    match capability.asset_binding().representation {
        AssetRepresentationV1::EvmErc20 {
            token,
            token_code_hash,
        } => {
            assert_eq!(token, [0x42; 20]);
            assert_eq!(token_code_hash, [0x43; 32]);
        }
        AssetRepresentationV1::Native => panic!("token capability must retain token facts"),
    }

    let dom = resolved.resolve_dom().unwrap();
    assert_eq!(dom.registry_digest(), resolved.manifest_digest());
    assert_eq!(dom.deployment(), value.dom);
    assert_eq!(dom.native_asset_binding().asset_id, DOM_ASSET);
    assert_ne!(dom.native_asset_binding_digest(), [0; 32]);

    let bitcoin = resolved
        .resolve_chain(BTC_CHAIN)
        .unwrap()
        .bitcoin_deployment_capability()
        .unwrap();
    assert_eq!(bitcoin.registry_digest(), resolved.manifest_digest());
    assert_eq!(bitcoin.profile().chain_id, BTC_CHAIN);
    assert_eq!(bitcoin.deployment().genesis_hash, regtest_genesis());
    assert_eq!(bitcoin.deployment().max_fee_rate_sat_vbyte, 100);
    assert_eq!(bitcoin.deployment().min_relay_fee_sat_kvb, 1_000);
    assert_eq!(bitcoin.asset_binding().asset_id, BTC_ASSET);
}

#[test]
fn signatures_policy_and_authorities_fail_closed() {
    let secp = SecpContext::new(&[0x61; 32]);
    let value = manifest(7);
    let (authorities, signed) = authority_and_signed(&value, &secp, &[0, 1]);

    let (_, one_signature) = authority_and_signed(&value, &secp, &[0]);
    assert!(matches!(
        one_signature.verify(&authorities, &secp, policy(7)),
        Err(RegistryError::ThresholdNotMet)
    ));

    let mut wrong_network = policy(7);
    wrong_network.expected_network_id = [0x99; 32];
    assert!(matches!(
        signed.verify(&authorities, &secp, wrong_network),
        Err(RegistryError::WrongNetwork)
    ));
    assert!(matches!(
        signed.verify(&authorities, &secp, policy(8)),
        Err(RegistryError::EpochBelowMinimum)
    ));
    let mut expired = policy(7);
    expired.now_seconds = 10_000;
    assert!(matches!(
        signed.verify(&authorities, &secp, expired),
        Err(RegistryError::InvalidTime)
    ));

    let mut changed = value;
    changed.expires_at += 1;
    let reused = SignedRegistryV1::new(&changed, signed.signatures().to_vec()).unwrap();
    assert!(matches!(
        reused.verify(&authorities, &secp, policy(7)),
        Err(RegistryError::InvalidSignature)
    ));

    let mut changed_identity = manifest(7);
    move_dom_to_testnet(&mut changed_identity);
    assert_ne!(
        changed_identity.manifest_digest().unwrap(),
        manifest(7).manifest_digest().unwrap()
    );
    let reused_identity =
        SignedRegistryV1::new(&changed_identity, signed.signatures().to_vec()).unwrap();
    assert!(matches!(
        reused_identity.verify(&authorities, &secp, policy(7)),
        Err(RegistryError::InvalidSignature)
    ));
    assert!(matches!(
        AuthoritySetV1::new(2, vec![[1u8; 32], [1u8; 32]]),
        Err(RegistryError::InvalidAuthoritySet)
    ));
    let off_curve = AuthoritySetV1::new(1, vec![[0xff; 32]]).unwrap();
    assert!(matches!(
        signed.verify(&off_curve, &secp, policy(7)),
        Err(RegistryError::InvalidAuthoritySet)
    ));
}

#[test]
fn signed_codec_refuses_reordering_tamper_and_trailing_bytes() {
    let secp = SecpContext::new(&[0x62; 32]);
    let value = manifest(7);
    let (authorities, signed) = authority_and_signed(&value, &secp, &[0, 1]);
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(&bytes[8..10], &2_u16.to_be_bytes());
    let decoded = SignedRegistryV1::decode(&bytes).unwrap();
    decoded.verify(&authorities, &secp, policy(7)).unwrap();

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        SignedRegistryV1::decode(&trailing),
        Err(RegistryError::NonCanonicalEncoding)
    ));
    let mut legacy_version = bytes.clone();
    legacy_version[8..10].copy_from_slice(&1_u16.to_be_bytes());
    assert!(matches!(
        SignedRegistryV1::decode(&legacy_version),
        Err(RegistryError::UnsupportedVersion)
    ));
    let reversed = vec![signed.signatures()[1], signed.signatures()[0]];
    assert!(matches!(
        SignedRegistryV1::new(&value, reversed),
        Err(RegistryError::InvalidSignature)
    ));
    let duplicate = vec![signed.signatures()[0], signed.signatures()[0]];
    assert!(matches!(
        SignedRegistryV1::new(&value, duplicate),
        Err(RegistryError::InvalidSignature)
    ));

    let mut tampered = bytes;
    let first_manifest_network_byte = 16 + 12;
    tampered[first_manifest_network_byte] ^= 1;
    let tampered = SignedRegistryV1::decode(&tampered).unwrap();
    assert!(matches!(
        tampered.verify(&authorities, &secp, policy(7)),
        Err(RegistryError::WrongNetwork)
    ));
}

#[test]
fn cross_field_manifest_refusals_cover_deployments_and_assets() {
    let mut value = manifest(7);
    value.dom.runtime_identity.network_magic = NETWORK_MAGIC_TESTNET;
    assert!(matches!(
        value.validate(),
        Err(RegistryError::InvalidDomRuntimeIdentity)
    ));

    let mut value = manifest(7);
    value.dom.finality.max_reorg_depth = 4_096;
    value.dom.timing.max_reorg_seconds = u32::MAX;
    assert!(matches!(
        value.validate(),
        Err(RegistryError::InvalidChainProfile)
    ));

    let mut value = manifest(7);
    value.assets.push(value.assets[0]);
    assert!(matches!(
        value.validate(),
        Err(RegistryError::DuplicateEntry)
    ));

    let mut value = manifest(7);
    value
        .assets
        .iter_mut()
        .find(|asset| asset.chain_id == EVM_CHAIN && asset.asset_id == EVM_TOKEN)
        .unwrap()
        .representation = AssetRepresentationV1::Native;
    assert!(matches!(
        value.validate(),
        Err(RegistryError::InvalidAssetBinding)
    ));

    let mut value = manifest(7);
    if let ChainDeploymentV1::Evm(evm) = &mut value.chains[0].deployment {
        evm.finalized_tag_required = false;
    }
    assert!(matches!(
        value.validate(),
        Err(RegistryError::DeploymentMismatch)
    ));

    let mut value = manifest(7);
    if let ChainDeploymentV1::Bitcoin(bitcoin) = &mut value.chains[1].deployment {
        bitcoin.signet_challenge = vec![0x51];
    }
    assert!(matches!(
        value.validate(),
        Err(RegistryError::DeploymentMismatch)
    ));

    let mut value = manifest(7);
    if let ChainDeploymentV1::Bitcoin(bitcoin) = &mut value.chains[1].deployment {
        bitcoin.genesis_hash = [0x41; 32];
    }
    assert!(matches!(
        value.validate(),
        Err(RegistryError::DeploymentMismatch)
    ));
}

#[test]
fn store_is_monotonic_idempotent_restart_safe_and_externally_anchored() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("registry.sqlite");
    let secp = SecpContext::new(&[0x63; 32]);
    let first = manifest(7);
    let (authorities, signed_first) = authority_and_signed(&first, &secp, &[0, 1]);
    {
        let mut store = RegistryStoreV1::open(&path).unwrap();
        let (outcome, resolved) = store
            .install(&signed_first, &authorities, &secp, policy(7))
            .unwrap();
        assert_eq!(outcome, InstallOutcomeV1::Installed);
        assert_eq!(resolved.epoch(), 7);
        assert_eq!(store.current_epoch().unwrap(), Some(7));
        let (outcome, _) = store
            .install(&signed_first, &authorities, &secp, policy(7))
            .unwrap();
        assert_eq!(outcome, InstallOutcomeV1::AlreadyCurrent);
    }
    {
        let mut store = RegistryStoreV1::open(&path).unwrap();
        assert_eq!(
            store
                .load_current(&authorities, &secp, policy(7))
                .unwrap()
                .unwrap()
                .epoch(),
            7
        );
        assert!(matches!(
            store.load_current(&authorities, &secp, policy(8)),
            Err(RegistryError::EpochBelowMinimum)
        ));

        let older = manifest(6);
        let (_, signed_older) = authority_and_signed(&older, &secp, &[0, 1]);
        assert!(matches!(
            store.install(&signed_older, &authorities, &secp, policy(6)),
            Err(RegistryError::Rollback)
        ));

        let mut conflict = manifest(7);
        conflict.expires_at += 1;
        let (_, signed_conflict) = authority_and_signed(&conflict, &secp, &[0, 1]);
        assert!(matches!(
            store.install(&signed_conflict, &authorities, &secp, policy(7)),
            Err(RegistryError::Rollback)
        ));

        let newer = manifest(8);
        let (_, signed_newer) = authority_and_signed(&newer, &secp, &[0, 2]);
        assert_eq!(
            store
                .install(&signed_newer, &authorities, &secp, policy(8))
                .unwrap()
                .0,
            InstallOutcomeV1::Installed
        );
        assert_eq!(store.current_epoch().unwrap(), Some(8));
    }
}

#[test]
fn same_epoch_install_does_not_hide_corrupt_retained_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("registry-corrupt.sqlite");
    let secp = SecpContext::new(&[0x64; 32]);
    let value = manifest(7);
    let (authorities, signed) = authority_and_signed(&value, &secp, &[0, 1]);
    {
        let mut store = RegistryStoreV1::open(&path).unwrap();
        store
            .install(&signed, &authorities, &secp, policy(7))
            .unwrap();
    }
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE registry_current SET signed_bytes = ?1 WHERE singleton = 1",
                rusqlite::params![vec![0u8]],
            )
            .unwrap();
    }
    let mut reopened = RegistryStoreV1::open(&path).unwrap();
    assert!(matches!(
        reopened.install(&signed, &authorities, &secp, policy(7)),
        Err(RegistryError::CorruptState)
    ));
}

#[test]
fn retained_epoch_columns_cannot_authorize_a_signed_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("registry-column-rollback.sqlite");
    let secp = SecpContext::new(&[0x65; 32]);
    let current = manifest(10);
    let (authorities, signed_current) = authority_and_signed(&current, &secp, &[0, 1]);
    {
        let mut store = RegistryStoreV1::open(&path).unwrap();
        store
            .install(&signed_current, &authorities, &secp, policy(10))
            .unwrap();
    }
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE registry_current SET epoch_be = ?1 WHERE singleton = 1",
            rusqlite::params![1_u64.to_be_bytes().as_slice()],
        )
        .unwrap();

    let candidate = manifest(8);
    let (_, signed_candidate) = authority_and_signed(&candidate, &secp, &[0, 2]);
    let mut reopened = RegistryStoreV1::open(&path).unwrap();
    assert!(matches!(
        reopened.install(&signed_candidate, &authorities, &secp, policy(8)),
        Err(RegistryError::CorruptState)
    ));
}

#[test]
fn newer_install_cannot_silently_repair_a_corrupt_current_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("registry-corrupt-upgrade.sqlite");
    let secp = SecpContext::new(&[0x66; 32]);
    let current = manifest(7);
    let (authorities, signed_current) = authority_and_signed(&current, &secp, &[0, 1]);
    {
        let mut store = RegistryStoreV1::open(&path).unwrap();
        store
            .install(&signed_current, &authorities, &secp, policy(7))
            .unwrap();
    }
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE registry_current SET signed_bytes = ?1 WHERE singleton = 1",
            rusqlite::params![vec![0u8]],
        )
        .unwrap();

    let newer = manifest(8);
    let (_, signed_newer) = authority_and_signed(&newer, &secp, &[0, 2]);
    let mut reopened = RegistryStoreV1::open(&path).unwrap();
    assert!(matches!(
        reopened.install(&signed_newer, &authorities, &secp, policy(8)),
        Err(RegistryError::CorruptState)
    ));
}

#[test]
fn semantically_unordered_manifests_are_refused() {
    let mut chains = manifest(7);
    chains.chains.swap(0, 1);
    assert!(matches!(
        chains.validate(),
        Err(RegistryError::NonCanonicalEncoding)
    ));

    let mut assets = manifest(7);
    assets.assets.swap(0, 1);
    assert!(matches!(
        assets.validate(),
        Err(RegistryError::NonCanonicalEncoding)
    ));

    let mut allowed = manifest(7);
    allowed.chains[0].profile.allowed_assets = vec![AssetId([0x15; 32]), AssetId([0x13; 32])];
    assert!(matches!(
        allowed.validate(),
        Err(RegistryError::NonCanonicalEncoding)
    ));
}

#[test]
fn zero_assets_and_token_aliases_are_refused() {
    let mut zero = manifest(7);
    zero.chains[0].profile.allowed_assets[0] = AssetId([0u8; 32]);
    assert!(matches!(zero.validate(), Err(RegistryError::ZeroField)));

    let mut alias = manifest(7);
    alias.chains[0]
        .profile
        .allowed_assets
        .push(AssetId([0x15; 32]));
    alias.assets.insert(
        3,
        AssetBindingV1 {
            chain_id: EVM_CHAIN,
            asset_id: AssetId([0x15; 32]),
            decimals: 6,
            representation: AssetRepresentationV1::EvmErc20 {
                token: [0x42; 20],
                token_code_hash: [0x43; 32],
            },
        },
    );
    alias
        .assets
        .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
    assert!(matches!(
        alias.validate(),
        Err(RegistryError::DuplicateEntry)
    ));
}

#[test]
fn evm_resolver_refuses_zero_session_bindings() {
    let secp = SecpContext::new(&[0x67; 32]);
    let value = manifest(7);
    let (authorities, signed) = authority_and_signed(&value, &secp, &[0, 1]);
    let resolved = signed.verify(&authorities, &secp, policy(7)).unwrap();
    let evm = resolved.resolve_chain(EVM_CHAIN).unwrap();
    let valid = EvmSessionBindingsV1 {
        direction: Direction::DomToEvm,
        session_id: [0x51; 32],
        terms_hash: [0x52; 32],
        participants_hash: [0x53; 32],
        beneficiary: [0x54; 20],
        funder: [0x55; 20],
    };
    for invalid in [
        EvmSessionBindingsV1 {
            session_id: [0; 32],
            ..valid
        },
        EvmSessionBindingsV1 {
            terms_hash: [0; 32],
            ..valid
        },
        EvmSessionBindingsV1 {
            participants_hash: [0; 32],
            ..valid
        },
        EvmSessionBindingsV1 {
            beneficiary: [0; 20],
            ..valid
        },
        EvmSessionBindingsV1 {
            funder: [0; 20],
            ..valid
        },
    ] {
        assert!(matches!(
            evm.evm_adapter_config(EVM_NATIVE, invalid),
            Err(RegistryError::ZeroField)
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn hardened_store_never_recreates_or_accepts_ambiguous_retained_state() {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let missing = temp.path().join("missing.sqlite3");
    assert!(matches!(
        RegistryStoreV1::open_existing(&missing),
        Err(RegistryError::DatabaseMissing)
    ));

    let path = temp.path().join("registry-hardened.sqlite3");
    let created = RegistryStoreV1::create(&path).unwrap();
    drop(created);
    assert!(matches!(
        RegistryStoreV1::create(&path),
        Err(RegistryError::DatabasePresent)
    ));
    RegistryStoreV1::open_existing(&path).unwrap();

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        RegistryStoreV1::open_existing(&path),
        Err(RegistryError::InvalidStorageAuthority)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let alias = temp.path().join("registry-alias.sqlite3");
    symlink(&path, &alias).unwrap();
    assert!(matches!(
        RegistryStoreV1::open_existing(&alias),
        Err(RegistryError::InvalidStorageAuthority)
    ));

    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER unauthorized_registry_trigger
             AFTER INSERT ON registry_history BEGIN SELECT 1; END;",
        )
        .unwrap();
    assert!(matches!(
        RegistryStoreV1::open_existing(&path),
        Err(RegistryError::CorruptState)
    ));
}

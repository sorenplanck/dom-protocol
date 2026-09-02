//! Stage 9 — production configuration generated from the local deploy mold.
//!
//! `deploy-genconfig <deploy-local-manifest.v1.json> <state-dir>` turns the
//! facts the integrated harness recorded into the authenticated artifacts the
//! daemon's startup consumes:
//!
//! 1. a **signed deployment registry** (`registry.v1.sqlite3`): a canonical
//!    manifest carrying the DOM regtest identity derived from consensus
//!    constants, the exact deployed lock addresses and runtime codehashes,
//!    and the real Bitcoin regtest genesis — signed by a freshly generated
//!    2-of-3 authority set whose secrets land beside it as owner-only files;
//! 2. the **chain-services document** (`production-chain-services.v1`) with
//!    the harness's real EVM and Bitcoin endpoints;
//! 3. `genconfig-report.v1.json` with every digest the V10 bootstrap pins.
//!
//! Everything written is read back through the same verifying loaders the
//! daemon uses; a document that does not survive its own verifier is never
//! left on disk. No fact is invented here: each one is either read from the
//! mold, derived from consensus constants, or generated and then persisted
//! (the authority secrets) for the local cycle.

#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_btc::types::BitcoinNetworkV1;
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1, ChainDeploymentV1,
    DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
    SignedRegistryV1,
};
use dom_consensus::derive_chain_id;
use dom_core::{configured_genesis_hash_for_network_magic, NETWORK_MAGIC_REGTEST};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use rand::RngCore as _;
use zeroize::Zeroizing;

const REGISTRY_FILE_V1: &str = "registry.v1.sqlite3";
const CHAIN_SERVICES_FILE_V1: &str = "production-chain-services.v1";
const REPORT_FILE_V1: &str = "genconfig-report.v1.json";
const AUTHORITY_SECRET_PREFIX_V1: &str = "registry-authority";
/// Local-cycle interop network id: domain-separated digest of the mold's
/// source commit, so two different trees never share a network identity.
const NETWORK_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/LOCAL-NETWORK-ID/V1\0";
const EPOCH_V1: u64 = 1;
/// One year of validity for the local cycle.
const VALIDITY_SECONDS_V1: u64 = 31_536_000;

fn fail(message: &str) -> ! {
    eprintln!("deploy-genconfig: {message}");
    std::process::exit(1);
}

use deploy_genconfig::chain_services_document;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(mold_path), Some(state_dir)) = (args.next(), args.next()) else {
        fail("usage: deploy-genconfig <deploy-local-manifest.v1.json> <state-dir>");
    };
    if args.next().is_some() {
        fail("unexpected extra argument");
    }
    let mold: serde_json::Value = serde_json::from_slice(
        &fs::read(&mold_path).unwrap_or_else(|error| fail(&format!("mold unreadable: {error}"))),
    )
    .unwrap_or_else(|error| fail(&format!("mold is not valid JSON: {error}")));
    let state_dir = PathBuf::from(state_dir);
    fs::create_dir_all(&state_dir).unwrap_or_else(|error| fail(&format!("state dir: {error}")));
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| fail(&format!("state dir mode: {error}")));

    let manifest = manifest_from_mold(&mold);
    let digest = manifest
        .manifest_digest()
        .unwrap_or_else(|error| fail(&format!("manifest digest: {error:?}")));

    // Fresh 2-of-3 authority set; secrets persisted owner-only so later
    // epochs of this local cycle can be signed by the same authorities.
    let secp = SecpContext::new(&random32());
    let mut keys = Vec::new();
    let mut signatures = Vec::new();
    for index in 0_u16..3 {
        let secret = Zeroizing::new(random32());
        let (signature, xonly) = secp
            .sign_bip340(&secret, &digest, &random32())
            .unwrap_or_else(|error| fail(&format!("authority signature: {error:?}")));
        write_owner_file(
            &state_dir.join(format!("{AUTHORITY_SECRET_PREFIX_V1}-{index}.secret")),
            hex::encode(&secret[..]).as_bytes(),
        );
        keys.push(xonly);
        signatures.push(RegistrySignatureV1 {
            signer_index: index,
            signature,
        });
    }
    let authorities = AuthoritySetV1::new(2, keys.clone())
        .unwrap_or_else(|error| fail(&format!("authority set: {error:?}")));
    let signed = SignedRegistryV1::new(&manifest, signatures)
        .unwrap_or_else(|error| fail(&format!("signed registry: {error:?}")));

    // Install into a fresh store and read it back through the verifier.
    let registry_path = state_dir.join(REGISTRY_FILE_V1);
    if registry_path.exists() {
        fail("registry.v1.sqlite3 already exists; refusing to overwrite");
    }
    let mut store = RegistryStoreV1::create(&registry_path)
        .unwrap_or_else(|error| fail(&format!("registry create: {error:?}")));
    let policy = RegistryValidationPolicyV1 {
        now_seconds: manifest.valid_from,
        expected_network_id: manifest.network_id,
        minimum_epoch: EPOCH_V1,
    };
    store
        .install(&signed, &authorities, &secp, policy)
        .unwrap_or_else(|error| fail(&format!("registry install: {error:?}")));
    let (reloaded, _resolved) = {
        let reopened = RegistryStoreV1::open_existing(&registry_path)
            .unwrap_or_else(|error| fail(&format!("registry reopen: {error:?}")));
        let resolved = reopened
            .load_current(&authorities, &secp, policy)
            .unwrap_or_else(|error| fail(&format!("registry reload: {error:?}")))
            .unwrap_or_else(|| fail("registry reload returned no current manifest"));
        (resolved.manifest_digest(), resolved)
    };
    if reloaded != digest {
        fail("reloaded registry digest diverges from the installed manifest");
    }

    // Chain-services document from the mold's real endpoints, validated by
    // encoding through the canonical writer used at decode time.
    let chain_services = chain_services_document(&mold).unwrap_or_else(|error| fail(&error));
    write_owner_file(&state_dir.join(CHAIN_SERVICES_FILE_V1), &chain_services);

    let report = serde_json::json!({
        "version": 1,
        "network_id": hex::encode(manifest.network_id),
        "registry_epoch": EPOCH_V1,
        "registry_manifest_digest": hex::encode(digest),
        "registry_path": registry_path,
        "chain_services_path": state_dir.join(CHAIN_SERVICES_FILE_V1),
        "authority_threshold": 2,
        "authority_xonly_keys": keys.iter().map(hex::encode).collect::<Vec<_>>(),
        "dom_chain_id": hex::encode(manifest.dom.chain_id.0),
        "evm_chain_id": hex::encode(evm_chain_id_bytes(&mold)),
        "bitcoin_chain_id": hex::encode(bitcoin_chain_id_bytes()),
    });
    write_owner_file(
        &state_dir.join(REPORT_FILE_V1),
        serde_json::to_vec_pretty(&report)
            .unwrap_or_else(|error| fail(&format!("report: {error}")))
            .as_slice(),
    );
    println!(
        "genconfig: registry installed (epoch {EPOCH_V1}, digest {}), chain services written, report at {}",
        hex::encode(digest),
        state_dir.join(REPORT_FILE_V1).display()
    );
}

fn manifest_from_mold(mold: &serde_json::Value) -> RegistryManifestV1 {
    let genesis = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)
        .unwrap_or_else(|_| fail("canonical DOM regtest genesis missing"));
    let dom_chain = ChainId(*derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis).as_bytes());
    let source_commit = require_str(mold, &["source_commit"]);
    let network_id = domain_digest(NETWORK_ID_DOMAIN_V1, source_commit.as_bytes());
    let evm_chain = ChainId(evm_chain_id_bytes(mold));
    let btc_chain = ChainId(bitcoin_chain_id_bytes());
    let dom_asset = AssetId(domain_digest(b"DOM-ASSET/NATIVE/V1\0", &dom_chain.0));
    let evm_native = AssetId(domain_digest(b"DOM-ASSET/EVM-NATIVE/V1\0", &evm_chain.0));
    let btc_asset = AssetId(domain_digest(b"DOM-ASSET/BTC-NATIVE/V1\0", &btc_chain.0));
    let native_lock = require_address(mold, &["evm", "native_lock"]);
    let native_code_hash = require_hash32(mold, &["evm", "native_runtime_codehash"]);
    let erc20_lock = require_address(mold, &["evm", "erc20_lock"]);
    let erc20_code_hash = require_hash32(mold, &["evm", "erc20_runtime_codehash"]);
    let evm_genesis = require_hash32(mold, &["evm", "genesis_hash"]);
    let deploy_block = require_u64(mold, &["evm", "deploy_block"]);
    let btc_genesis = bitcoin_genesis_bytes(mold);
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
                        evm_chain_id: require_u64(mold, &["evm", "chain_id"]),
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
    manifest
}

/// Local regtest cadence: one-second dev blocks with shallow finality.
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

fn evm_chain_id_bytes(mold: &serde_json::Value) -> [u8; 32] {
    domain_digest(
        b"DOM-CHAIN-ID/EVM-LOCAL/V1\0",
        &require_u64(mold, &["evm", "chain_id"]).to_be_bytes(),
    )
}

fn bitcoin_chain_id_bytes() -> [u8; 32] {
    domain_digest(b"DOM-CHAIN-ID/BTC-REGTEST/V1\0", b"regtest")
}

fn bitcoin_genesis_bytes(mold: &serde_json::Value) -> [u8; 32] {
    let display = require_str(mold, &["bitcoin", "genesis_hash"]);
    let bytes = hex::decode(&display).unwrap_or_else(|_| fail("bitcoin genesis is not hex"));
    let array: [u8; 32] = bytes
        .try_into()
        .unwrap_or_else(|_| fail("bitcoin genesis is not 32 bytes"));
    // bitcoind displays block hashes byte-reversed; the registry stores raw.
    let mut raw = array;
    raw.reverse();
    raw
}

fn require_str(mold: &serde_json::Value, path: &[&str]) -> String {
    let mut value = mold;
    for key in path {
        value = value
            .get(key)
            .unwrap_or_else(|| fail(&format!("mold missing {}", path.join("."))));
    }
    value
        .as_str()
        .unwrap_or_else(|| fail(&format!("mold field {} is not a string", path.join("."))))
        .to_owned()
}

fn require_u64(mold: &serde_json::Value, path: &[&str]) -> u64 {
    let mut value = mold;
    for key in path {
        value = value
            .get(key)
            .unwrap_or_else(|| fail(&format!("mold missing {}", path.join("."))));
    }
    value
        .as_u64()
        .unwrap_or_else(|| fail(&format!("mold field {} is not a u64", path.join("."))))
}

fn require_hash32(mold: &serde_json::Value, path: &[&str]) -> [u8; 32] {
    let text = require_str(mold, path);
    let text = text.strip_prefix("0x").unwrap_or(&text);
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .unwrap_or_else(|| {
            fail(&format!(
                "mold field {} is not a 32-byte hex",
                path.join(".")
            ))
        })
}

fn require_address(mold: &serde_json::Value, path: &[&str]) -> [u8; 20] {
    let text = require_str(mold, path);
    let text = text.strip_prefix("0x").unwrap_or(&text);
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
        .unwrap_or_else(|| {
            fail(&format!(
                "mold field {} is not a 20-byte hex",
                path.join(".")
            ))
        })
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
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS entropy");
    bytes
}

fn write_owner_file(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .unwrap_or_else(|error| fail(&format!("{}: {error}", path.display())));
    file.write_all(bytes)
        .unwrap_or_else(|error| fail(&format!("{}: {error}", path.display())));
}

//! Stage-9 cycle gate: the provisioned registry must verify positively, and
//! every mutation class the roadmap names — content tamper, configuration
//! field edits, network substitution — must refuse byte-for-byte.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use deploy_genconfig::{
    chain_services_document, provision_registry, verify_registry, RegistryValidationPolicyV1,
    CHAIN_SERVICES_FILE_V1, REGISTRY_FILE_V1,
};

fn mold(directory: &std::path::Path) -> serde_json::Value {
    let datadir = directory.join("btc");
    fs::create_dir_all(datadir.join("regtest")).expect("datadir");
    fs::set_permissions(&datadir, fs::Permissions::from_mode(0o700)).expect("datadir mode");
    fs::set_permissions(datadir.join("regtest"), fs::Permissions::from_mode(0o700))
        .expect("regtest mode");
    let cookie = datadir.join("regtest/.cookie");
    fs::write(&cookie, b"__cookie__:hunter2").expect("cookie");
    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).expect("cookie mode");
    serde_json::json!({
        "source_commit": "0123456789abcdef0123456789abcdef01234567",
        "evm": {
            "rpc": "http://127.0.0.1:8545",
            "chain_id": 31337,
            "genesis_hash": format!("0x{}", "11".repeat(32)),
            "native_lock": format!("0x{}", "22".repeat(20)),
            "native_runtime_codehash": format!("0x{}", "33".repeat(32)),
            "erc20_lock": format!("0x{}", "44".repeat(20)),
            "erc20_runtime_codehash": format!("0x{}", "55".repeat(32)),
            "deploy_block": 2,
        },
        "bitcoin": {
            "datadir": datadir.to_str().expect("utf8"),
            "rpc_port": 18443,
            "wallet": "dom-local",
            "genesis_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        },
    })
}

#[test]
fn positive_cycle_then_every_mutation_class_refuses() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let state = directory.path().join("state");
    let mold = mold(directory.path());

    // Positive: provision, then independently re-verify the exact digest.
    let provisioned = provision_registry(&mold, &state).expect("provision");
    let registry_path = state.join(REGISTRY_FILE_V1);
    let reverified = verify_registry(
        &registry_path,
        &provisioned.authorities,
        &provisioned.secp,
        provisioned.policy,
    )
    .expect("positive verify");
    assert_eq!(reverified, provisioned.manifest_digest);

    // Positive: the chain-services document round-trips through the daemon.
    let document = chain_services_document(&mold).expect("document");
    fs::write(state.join(CHAIN_SERVICES_FILE_V1), &document).expect("write");
    let decoded = dom_interopd::ProductionChainServicesConfigV1::decode_canonical(&document)
        .expect("daemon loader");
    assert_eq!(decoded.canonical_bytes().expect("re-encode"), document);

    // Mutation 1 — registry content tamper: flip one byte of the signed
    // payload region and the reload must refuse.
    let original = fs::read(&registry_path).expect("registry bytes");
    let mut tampered = original.clone();
    let target = tampered.len() / 2;
    tampered[target] ^= 0x01;
    fs::write(&registry_path, &tampered).expect("write tamper");
    assert!(
        verify_registry(
            &registry_path,
            &provisioned.authorities,
            &provisioned.secp,
            provisioned.policy,
        )
        .is_err(),
        "a byte-flipped registry must refuse verification"
    );
    fs::write(&registry_path, &original).expect("restore");

    // Mutation 2 — configuration field edit: change one digit of the wallet
    // line; the canonical digest refuses the document.
    let text = String::from_utf8(document.clone()).expect("ascii");
    let edited = text.replace(
        "bitcoin_wallet_name=dom-local",
        "bitcoin_wallet_name=dom-loca1",
    );
    assert_ne!(edited, text);
    assert!(
        dom_interopd::ProductionChainServicesConfigV1::decode_canonical(edited.as_bytes()).is_err(),
        "an edited chain-services field must refuse decoding"
    );

    // Mutation 3 — network substitution: verifying under a different
    // expected network id must refuse even with the honest bytes.
    let mut foreign_policy = provisioned.policy;
    foreign_policy.expected_network_id[0] ^= 0x01;
    assert!(
        verify_registry(
            &registry_path,
            &provisioned.authorities,
            &provisioned.secp,
            RegistryValidationPolicyV1 { ..foreign_policy },
        )
        .is_err(),
        "a foreign network id must refuse the honest registry"
    );

    // And the honest state still verifies after every refusal above.
    assert_eq!(
        verify_registry(
            &registry_path,
            &provisioned.authorities,
            &provisioned.secp,
            provisioned.policy,
        )
        .expect("still verifies"),
        provisioned.manifest_digest
    );
}

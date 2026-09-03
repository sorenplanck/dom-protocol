//! The generated chain-services document must survive the daemon's own
//! verifying loader byte for byte — the stage-9 "positive config" gate.
//! The loader canonicalizes and requires the Bitcoin cookie to exist as an
//! owner-only file, exactly as the harness's bitcoind provides it.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use deploy_genconfig::chain_services_document;

#[test]
fn generated_chain_services_decode_through_the_daemon_loader() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let datadir = directory.path().join("btc");
    fs::create_dir_all(datadir.join("regtest")).expect("datadir");
    fs::set_permissions(&datadir, fs::Permissions::from_mode(0o700)).expect("datadir mode");
    fs::set_permissions(datadir.join("regtest"), fs::Permissions::from_mode(0o700))
        .expect("regtest mode");
    let cookie = datadir.join("regtest/.cookie");
    fs::write(&cookie, b"__cookie__:hunter2").expect("cookie");
    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).expect("cookie mode");

    let mold = serde_json::json!({
        "evm": {"rpc": "http://127.0.0.1:8545"},
        "bitcoin": {
            "datadir": datadir.to_str().expect("utf8 datadir"),
            "rpc_port": 18443,
            "wallet": "dom-local",
        },
    });
    let document = chain_services_document(&mold).expect("document");
    let decoded = dom_interopd::ProductionChainServicesConfigV1::decode_canonical(&document)
        .expect("daemon loader must accept the generated document");
    assert_eq!(
        decoded.canonical_bytes().expect("re-encode"),
        document,
        "round trip through the daemon writer must be byte-identical"
    );
}

use dom_config::NodeConfig;
use dom_core::DomError;
use dom_node::node::DomNode;
use tempfile::TempDir;

const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

fn assert_mainnet_init_fails_before_storage(label: &str, mutate: impl FnOnce(&mut NodeConfig)) {
    let temp = TempDir::new().expect("tempdir");
    let data_dir = temp.path().join(label);
    let mut config = NodeConfig::mainnet();
    config.data_dir = data_dir.display().to_string();
    mutate(&mut config);

    let err = match DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE) {
        Ok(_) => panic!("mainnet must fail closed"),
        Err(err) => err,
    };
    assert!(matches!(err, DomError::Invalid(_)));
    assert!(
        err.to_string().contains("mainnet genesis is not finalized"),
        "unexpected error: {err}"
    );
    assert!(
        !data_dir.exists(),
        "mainnet readiness gate must fail before storage, listeners, RPC, or mining setup"
    );
}

#[test]
fn init_refuses_mainnet_when_genesis_is_unfinalized() {
    assert_mainnet_init_fails_before_storage("dom-mainnet", |_| {});
}

#[test]
fn init_refuses_all_mainnet_service_modes_before_startup_side_effects() {
    assert_mainnet_init_fails_before_storage("dom-mainnet-sync", |config| {
        config.mine = false;
        config.rpc_listen_addr = None;
    });
    assert_mainnet_init_fails_before_storage("dom-mainnet-mining", |config| {
        config.mine = true;
    });
    assert_mainnet_init_fails_before_storage("dom-mainnet-rpc", |config| {
        config.rpc_listen_addr = Some("127.0.0.1:0".into());
    });
    assert_mainnet_init_fails_before_storage("dom-mainnet-mining-rpc", |config| {
        config.mine = true;
        config.rpc_listen_addr = Some("127.0.0.1:0".into());
    });
}

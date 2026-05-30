use dom_config::NodeConfig;
use dom_core::DomError;
use dom_node::node::DomNode;
use tempfile::TempDir;

const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

#[test]
fn init_refuses_mainnet_when_genesis_is_unfinalized() {
    let temp = TempDir::new().expect("tempdir");
    let mut config = NodeConfig::mainnet();
    config.data_dir = temp.path().join("dom-mainnet").display().to_string();

    let err = match DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE) {
        Ok(_) => panic!("mainnet must fail closed"),
        Err(err) => err,
    };
    assert!(matches!(err, DomError::Invalid(_)));
    assert!(
        err.to_string().contains("mainnet genesis is not finalized"),
        "unexpected error: {err}"
    );
}

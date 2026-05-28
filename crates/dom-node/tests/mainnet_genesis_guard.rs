use dom_config::NodeConfig;
use dom_core::DomError;
use dom_node::node::DomNode;
use tempfile::TempDir;

#[test]
fn init_refuses_mainnet_when_genesis_is_unfinalized() {
    let temp = TempDir::new().expect("tempdir");
    let mut config = NodeConfig::mainnet();
    config.data_dir = temp.path().join("dom-mainnet").display().to_string();

    let err = match DomNode::init(config) {
        Ok(_) => panic!("mainnet must fail closed"),
        Err(err) => err,
    };
    assert!(matches!(err, DomError::Invalid(_)));
    assert!(
        err.to_string().contains("mainnet disabled"),
        "unexpected error: {err}"
    );
}

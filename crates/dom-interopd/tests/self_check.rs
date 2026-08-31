use dom_interopd::{
    build_attestation_v1, require_operational_artifact_v1, self_check_json_v1, RuntimeBuildModeV1,
    StartupRefusalV1,
};

#[test]
fn default_build_attests_but_refuses_operational_startup() {
    let attestation = build_attestation_v1();
    assert_eq!(attestation.mode, RuntimeBuildModeV1::Development);
    assert!(!attestation.operational_artifact);
    assert_eq!(
        require_operational_artifact_v1(),
        Err(StartupRefusalV1::NonOperationalArtifact)
    );
}

#[test]
fn self_check_is_machine_readable_and_contains_no_runtime_secret() {
    let encoded = self_check_json_v1().expect("self-check JSON");
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("valid JSON");
    assert_eq!(value["mode"], "development");
    assert!(
        value["cargo_lock_blake2b256"]
            .as_str()
            .expect("lock digest")
            .len()
            >= 64
    );
    assert!(value.get("secret").is_none());
    assert!(value.get("private_key").is_none());
}

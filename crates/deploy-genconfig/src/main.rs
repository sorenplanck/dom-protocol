//! Stage 9 — production configuration generated from the local deploy mold.
//!
//! `deploy-genconfig <deploy-local-manifest.v1.json> <state-dir>`: see the
//! library documentation for what is produced and how it is re-verified.

#![forbid(unsafe_code)]

use std::fs;

use deploy_genconfig::{
    chain_services_document, provision_registry, write_owner_file, CHAIN_SERVICES_FILE_V1,
    REGISTRY_FILE_V1,
};

const REPORT_FILE_V1: &str = "genconfig-report.v1.json";

fn fail(message: &str) -> ! {
    eprintln!("deploy-genconfig: {message}");
    std::process::exit(1);
}

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
    let state_dir = std::path::PathBuf::from(state_dir);

    let provisioned = provision_registry(&mold, &state_dir).unwrap_or_else(|error| fail(&error));
    let chain_services = chain_services_document(&mold).unwrap_or_else(|error| fail(&error));
    write_owner_file(&state_dir.join(CHAIN_SERVICES_FILE_V1), &chain_services)
        .unwrap_or_else(|error| fail(&error));

    let report = serde_json::json!({
        "version": 1,
        "network_id": hex::encode(provisioned.network_id),
        "registry_epoch": provisioned.epoch,
        "registry_manifest_digest": hex::encode(provisioned.manifest_digest),
        "registry_path": state_dir.join(REGISTRY_FILE_V1),
        "chain_services_path": state_dir.join(CHAIN_SERVICES_FILE_V1),
        "authority_threshold": 2,
        "authority_xonly_keys": provisioned
            .authority_keys
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        "dom_chain_id": hex::encode(provisioned.dom_chain_id),
    });
    write_owner_file(
        &state_dir.join(REPORT_FILE_V1),
        serde_json::to_vec_pretty(&report)
            .unwrap_or_else(|error| fail(&format!("report: {error}")))
            .as_slice(),
    )
    .unwrap_or_else(|error| fail(&error));
    println!(
        "genconfig: registry installed (epoch {}, digest {}), chain services written, report at {}",
        provisioned.epoch,
        hex::encode(provisioned.manifest_digest),
        state_dir.join(REPORT_FILE_V1).display()
    );
}

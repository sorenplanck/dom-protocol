//! Offline integrity/schema verifier for a public EVM contract release record.
//!
//! Success proves that the Python release producer and Rust registry consumer
//! agree. It does not authenticate the record; registry threshold signatures
//! remain mandatory before production admission.

use std::{error::Error, path::PathBuf};

use deployment_registry::{EvmContractReleaseV1, MAX_EVM_CONTRACT_RELEASE_BYTES};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let path = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: verify_evm_contract_release <release.json>")?,
    );
    if arguments.next().is_some() {
        return Err("usage: verify_evm_contract_release <release.json>".into());
    }
    let metadata = std::fs::metadata(&path)?;
    let maximum = u64::try_from(MAX_EVM_CONTRACT_RELEASE_BYTES)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("release record is absent, empty, non-regular or oversized".into());
    }
    let bytes = std::fs::read(path)?;
    let release = EvmContractReleaseV1::parse_json(&bytes)?;
    let digest = release
        .manifest_digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        "integrity_checked=true authenticated=false evm_chain_id={} manifest_digest=0x{}",
        release.evm_chain_id(),
        digest
    );
    Ok(())
}

#![no_main]

use dom_crypto::recovery::{
    derive_recovery_root, recover_output_from_capsule, PublicOutputKind, RecoveryCapsule,
    RecoveryChainContext,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(capsule) = RecoveryCapsule::from_bytes(data) else {
        return;
    };
    let chain = RecoveryChainContext {
        network_magic: 1,
        chain_id: [2u8; 32],
    };
    let root = derive_recovery_root(&[3u8; 64], chain).expect("fixed seed");
    let mut commitment = [0u8; 33];
    commitment[0] = 2;
    let _ = recover_output_from_capsule(
        &root,
        chain,
        &commitment,
        1,
        PublicOutputKind::Regular,
        &capsule,
    );
});

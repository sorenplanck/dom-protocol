#![no_main]

use dom_crypto::recovery::RecoveryChainContext;
use dom_wallet_core_api::{CoinbaseScanMetadata, ScanBlock, ScanOutput};
use dom_wallet_recovery::restore_from_canonical_scan;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut commitment = [0u8; 33];
    commitment[0] = 2;
    for (dst, src) in commitment[1..].iter_mut().zip(data.iter().copied()) {
        *dst = src;
    }
    let capsule = data.iter().copied().take(96).collect::<Vec<_>>();
    let proof = data.iter().copied().skip(96).take(835).collect::<Vec<_>>();
    let block_hash = [4u8; 32];
    let block = ScanBlock {
        height: 0,
        block_hash,
        previous_block_hash: [0u8; 32],
        timestamp: 0,
        canonical_marker: block_hash,
        outputs: vec![ScanOutput {
            commitment,
            range_proof: proof,
            recovery_capsule: capsule,
            recovery_version: 1,
            is_coinbase: false,
            block_height: 0,
            block_hash,
            output_position: 0,
        }],
        inputs: Vec::new(),
        kernels: Vec::new(),
        coinbase: CoinbaseScanMetadata {
            output_commitment: [0u8; 33],
            explicit_value: 0,
            kernel_excess: [0u8; 33],
        },
        total_fees_noms: 0,
        protocol_version: 1,
        range_proof_serialization_version: 1,
    };
    let chain = RecoveryChainContext {
        network_magic: 1,
        chain_id: [2u8; 32],
    };
    let _ = restore_from_canonical_scan(&[3u8; 64], chain, &[block]);
});

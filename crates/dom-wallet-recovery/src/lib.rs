//! Wallet V3 seed-only restoration from canonical scanner projections.
#![deny(unsafe_code)]

use dom_crypto::recovery::{
    derive_recovery_root, recover_output_from_capsule, OutputRecoveryDomain, PublicOutputKind,
    RecoveryCapsule, RecoveryChainContext, RECOVERY_VERSION,
};
use dom_tx::InputSource;
use dom_wallet_core_api::{ScanBlock, ScanOutput};
use std::collections::BTreeMap;
use thiserror::Error;

/// Restore failure. Authentication failure for an unrelated output is not an
/// error and is intentionally absent from this enum.
#[derive(Debug, Error)]
pub enum RestoreError {
    #[error("chain projection gap or discontinuity: {0}")]
    Continuity(String),
    #[error("malformed owned output: {0}")]
    Malformed(String),
    #[error("cryptographic recovery failed: {0}")]
    Crypto(String),
}

/// A fully reconstructed wallet output. Secret debug fields are redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct RestoredOutput {
    pub commitment: [u8; 33],
    pub value: u64,
    pub blinding: [u8; 32],
    pub account: u32,
    pub derivation_index: u64,
    pub domain: OutputRecoveryDomain,
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub is_coinbase: bool,
    pub spent_at_height: Option<u64>,
}

impl std::fmt::Debug for RestoredOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoredOutput")
            .field("commitment", &hex_commitment(&self.commitment))
            .field("value", &"[REDACTED]")
            .field("blinding", &"[REDACTED]")
            .field("account", &self.account)
            .field("derivation_index", &self.derivation_index)
            .field("domain", &self.domain)
            .field("block_height", &self.block_height)
            .field("block_hash", &"[REDACTED]")
            .field("is_coinbase", &self.is_coinbase)
            .field("spent_at_height", &self.spent_at_height)
            .finish()
    }
}

fn hex_commitment(commitment: &[u8; 33]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(66);
    for byte in commitment {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

impl InputSource for RestoredOutput {
    fn commitment(&self) -> [u8; 33] {
        self.commitment
    }

    fn value(&self) -> u64 {
        self.value
    }

    fn blinding(&self) -> [u8; 32] {
        self.blinding
    }

    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }
}

/// Semantic wallet state reconstructed solely from seed and canonical blocks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoredWalletState {
    outputs: BTreeMap<[u8; 33], RestoredOutput>,
}

impl RestoredWalletState {
    pub fn outputs(&self) -> impl Iterator<Item = &RestoredOutput> {
        self.outputs.values()
    }

    pub fn unspent_outputs(&self) -> impl Iterator<Item = &RestoredOutput> {
        self.outputs
            .values()
            .filter(|output| output.spent_at_height.is_none())
    }

    pub fn get(&self, commitment: &[u8; 33]) -> Option<&RestoredOutput> {
        self.outputs.get(commitment)
    }
}

/// Restore all owned historical outputs and reconcile spent state. `blocks`
/// must be the unfiltered canonical scanner stream in ascending contiguous order.
pub fn restore_from_canonical_scan(
    seed: &[u8],
    chain: RecoveryChainContext,
    blocks: &[ScanBlock],
) -> Result<RestoredWalletState, RestoreError> {
    validate_continuity(blocks)?;
    let root = derive_recovery_root(seed, chain)
        .map_err(|error| RestoreError::Crypto(error.to_string()))?;
    let mut state = RestoredWalletState::default();

    for block in blocks {
        for output in &block.outputs {
            if let Some(restored) = try_restore_output(&root, chain, output)? {
                match state.outputs.get(&restored.commitment) {
                    Some(existing) if existing == &restored => {}
                    Some(_) => {
                        return Err(RestoreError::Continuity(
                            "duplicate owned commitment has divergent metadata".into(),
                        ))
                    }
                    None => {
                        state.outputs.insert(restored.commitment, restored);
                    }
                }
            }
        }
        for input in &block.inputs {
            if let Some(output) = state.outputs.get_mut(&input.spent_commitment) {
                output.spent_at_height = Some(block.height);
            }
        }
    }
    Ok(state)
}

fn try_restore_output(
    root: &dom_crypto::recovery::RecoveryRoot,
    chain: RecoveryChainContext,
    output: &ScanOutput,
) -> Result<Option<RestoredOutput>, RestoreError> {
    if output.recovery_version == 0 && output.recovery_capsule.is_empty() {
        return Ok(None);
    }
    if output.recovery_version != RECOVERY_VERSION {
        return Err(RestoreError::Malformed(format!(
            "unsupported recovery version {}",
            output.recovery_version
        )));
    }
    let capsule = RecoveryCapsule::from_bytes(&output.recovery_capsule)
        .map_err(|error| RestoreError::Malformed(error.to_string()))?;
    if output.range_proof.len() != dom_crypto::RANGE_PROOF_SIZE {
        return Err(RestoreError::Malformed(
            "scanner returned a noncanonical range proof length".into(),
        ));
    }
    let public_kind = if output.is_coinbase {
        PublicOutputKind::Coinbase
    } else {
        PublicOutputKind::Regular
    };
    let Some(recovered) = recover_output_from_capsule(
        root,
        chain,
        &output.commitment,
        dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        public_kind,
        &capsule,
    )
    .map_err(|error| RestoreError::Crypto(error.to_string()))?
    else {
        return Ok(None);
    };
    match dom_crypto::range_proof_verify_with_extra_commit(
        &output.commitment,
        &output.range_proof,
        capsule.as_bytes(),
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(RestoreError::Crypto(
                "owned output range proof is invalid".into(),
            ))
        }
        Err(error) => return Err(RestoreError::Crypto(error.to_string())),
    }
    Ok(Some(RestoredOutput {
        commitment: output.commitment,
        value: recovered.value,
        blinding: *recovered.blinding.as_bytes(),
        account: recovered.account,
        derivation_index: recovered.derivation_index,
        domain: recovered.domain,
        block_height: output.block_height,
        block_hash: output.block_hash,
        is_coinbase: output.is_coinbase,
        spent_at_height: None,
    }))
}

fn validate_continuity(blocks: &[ScanBlock]) -> Result<(), RestoreError> {
    for window in blocks.windows(2) {
        let previous = &window[0];
        let current = &window[1];
        if current.height != previous.height.saturating_add(1) {
            return Err(RestoreError::Continuity(format!(
                "height {} does not follow {}",
                current.height, previous.height
            )));
        }
        if current.previous_block_hash != previous.block_hash {
            return Err(RestoreError::Continuity(format!(
                "block {} does not extend the preceding canonical hash",
                current.height
            )));
        }
        if previous.canonical_marker != previous.block_hash
            || current.canonical_marker != current.block_hash
        {
            return Err(RestoreError::Continuity(
                "canonical marker does not match projected block hash".into(),
            ));
        }
    }
    if let Some(block) = blocks.first() {
        if block.canonical_marker != block.block_hash {
            return Err(RestoreError::Continuity(
                "canonical marker does not match first projected block hash".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::recovery::{OutputRecoveryDomain, RecoveryChainContext};
    use dom_tx::{build_recoverable_output, SpendBuilder};
    use dom_wallet_core_api::{CoinbaseScanMetadata, ScanInput, ScanKernel};

    const SEED: [u8; 64] = [0x31; 64];

    fn chain() -> RecoveryChainContext {
        RecoveryChainContext {
            network_magic: 0x4452_4547,
            chain_id: [0x71; 32],
        }
    }

    fn scan_output(
        material: &dom_tx::RecoverableOutputMaterial,
        block_height: u64,
        block_hash: [u8; 32],
        position: u32,
        is_coinbase: bool,
    ) -> ScanOutput {
        let capsule = material.output.recovery_capsule().unwrap().unwrap();
        ScanOutput {
            commitment: *material.output.commitment.as_bytes(),
            range_proof: material.output.range_proof_bytes().unwrap().to_vec(),
            recovery_capsule: capsule.as_bytes().to_vec(),
            recovery_version: capsule.version(),
            is_coinbase,
            block_height,
            block_hash,
            output_position: position,
        }
    }

    fn block(
        height: u64,
        hash: [u8; 32],
        previous: [u8; 32],
        outputs: Vec<ScanOutput>,
        inputs: Vec<ScanInput>,
    ) -> ScanBlock {
        ScanBlock {
            height,
            block_hash: hash,
            previous_block_hash: previous,
            timestamp: height,
            canonical_marker: hash,
            outputs,
            inputs,
            kernels: vec![ScanKernel {
                excess: *dom_crypto::pedersen::Commitment::commit(
                    0,
                    &dom_crypto::pedersen::BlindingFactor::from_bytes([9u8; 32]).unwrap(),
                )
                .as_bytes(),
                features: 0,
                fee: 0,
                lock_height: 0,
            }],
            coinbase: CoinbaseScanMetadata {
                output_commitment: [0u8; 33],
                explicit_value: 0,
                kernel_excess: [0u8; 33],
            },
            total_fees_noms: 0,
            protocol_version: 1,
            range_proof_serialization_version: 1,
        }
    }

    struct Fixture {
        blocks: Vec<ScanBlock>,
        received: [u8; 33],
        change: [u8; 33],
        coinbase: [u8; 33],
    }

    fn fixture() -> Fixture {
        let root = derive_recovery_root(&SEED, chain()).unwrap();
        let received =
            build_recoverable_output(&root, chain(), 1_000, 0, 1, OutputRecoveryDomain::Received)
                .unwrap();
        let change =
            build_recoverable_output(&root, chain(), 600, 0, 2, OutputRecoveryDomain::Change)
                .unwrap();
        let coinbase =
            build_recoverable_output(&root, chain(), 5_000, 0, 3, OutputRecoveryDomain::Coinbase)
                .unwrap();
        let received_commitment = *received.output.commitment.as_bytes();
        let change_commitment = *change.output.commitment.as_bytes();
        let coinbase_commitment = *coinbase.output.commitment.as_bytes();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        let blocks = vec![
            block(
                1,
                h1,
                [0u8; 32],
                vec![scan_output(&received, 1, h1, 0, false)],
                vec![],
            ),
            block(
                2,
                h2,
                h1,
                vec![scan_output(&change, 2, h2, 0, false)],
                vec![ScanInput {
                    spent_commitment: received_commitment,
                }],
            ),
            block(
                3,
                h3,
                h2,
                vec![scan_output(&coinbase, 3, h3, 0, true)],
                vec![],
            ),
        ];
        Fixture {
            blocks,
            received: received_commitment,
            change: change_commitment,
            coinbase: coinbase_commitment,
        }
    }

    #[test]
    fn authoritative_seed_only_restore_recovers_received_change_coinbase_and_spent_state() {
        let fixture = fixture();
        let restored = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks).unwrap();
        assert_eq!(restored.outputs().count(), 3);
        assert_eq!(
            restored.get(&fixture.received).unwrap().spent_at_height,
            Some(2)
        );
        assert_eq!(restored.get(&fixture.change).unwrap().value, 600);
        assert_eq!(restored.get(&fixture.coinbase).unwrap().value, 5_000);
        assert!(restored.get(&fixture.coinbase).unwrap().is_coinbase);
        assert_eq!(restored.unspent_outputs().count(), 2);
    }

    #[test]
    fn restored_output_builds_a_valid_spend() {
        let fixture = fixture();
        let restored = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks).unwrap();
        let input = restored.get(&fixture.change).unwrap().clone();
        let root = derive_recovery_root(&SEED, chain()).unwrap();
        let output =
            build_recoverable_output(&root, chain(), 500, 0, 4, OutputRecoveryDomain::Change)
                .unwrap();
        let mut builder = SpendBuilder::new(&chain().chain_id);
        builder.add_inputs(vec![input]).unwrap();
        builder.add_recoverable_output(output).unwrap();
        builder.fee(100);
        let tx = builder.build().unwrap();
        assert!(tx.outputs[0].recovery_capsule().unwrap().is_some());
    }

    #[test]
    fn wrong_seed_network_chain_and_unrelated_outputs_are_not_claimed() {
        let fixture = fixture();
        assert_eq!(
            restore_from_canonical_scan(&[0x32; 64], chain(), &fixture.blocks)
                .unwrap()
                .outputs()
                .count(),
            0
        );
        let wrong_network = RecoveryChainContext {
            network_magic: 1,
            ..chain()
        };
        assert_eq!(
            restore_from_canonical_scan(&SEED, wrong_network, &fixture.blocks)
                .unwrap()
                .outputs()
                .count(),
            0
        );
        let wrong_chain = RecoveryChainContext {
            chain_id: [8u8; 32],
            ..chain()
        };
        assert_eq!(
            restore_from_canonical_scan(&SEED, wrong_chain, &fixture.blocks)
                .unwrap()
                .outputs()
                .count(),
            0
        );
    }

    #[test]
    fn tampering_and_capsule_substitution_fail_closed() {
        let fixture = fixture();
        let mut tampered = fixture.blocks.clone();
        tampered[0].outputs[0].recovery_capsule[40] ^= 1;
        assert_eq!(
            restore_from_canonical_scan(&SEED, chain(), &tampered)
                .unwrap()
                .outputs()
                .count(),
            2
        );

        let mut substituted = fixture.blocks.clone();
        substituted[1].outputs[0].recovery_capsule =
            substituted[0].outputs[0].recovery_capsule.clone();
        assert_eq!(
            restore_from_canonical_scan(&SEED, chain(), &substituted)
                .unwrap()
                .outputs()
                .count(),
            2
        );
    }

    #[test]
    fn gaps_and_reorg_discontinuity_fail_closed() {
        let fixture = fixture();
        let mut gap = fixture.blocks.clone();
        gap[1].height = 3;
        assert!(matches!(
            restore_from_canonical_scan(&SEED, chain(), &gap),
            Err(RestoreError::Continuity(_))
        ));
        let mut reorg = fixture.blocks.clone();
        reorg[2].previous_block_hash = [1u8; 32];
        assert!(matches!(
            restore_from_canonical_scan(&SEED, chain(), &reorg),
            Err(RestoreError::Continuity(_))
        ));
    }

    #[test]
    fn canonical_reorg_replay_removes_disconnected_output() {
        let fixture = fixture();
        let original = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks).unwrap();
        assert_eq!(original.outputs().count(), 3);
        let canonical_after_reorg = fixture.blocks[..2].to_vec();
        let replayed = restore_from_canonical_scan(&SEED, chain(), &canonical_after_reorg).unwrap();
        assert_eq!(replayed.outputs().count(), 2);
        assert!(replayed.get(&fixture.coinbase).is_none());
    }

    #[test]
    fn clean_restore_is_deterministic_fifty_times() {
        let fixture = fixture();
        let expected = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks).unwrap();
        for _ in 0..50 {
            let actual = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn boundary_values_multiple_outputs_and_all_private_domains_restore() {
        let root = derive_recovery_root(&SEED, chain()).unwrap();
        let cases = [
            (0, OutputRecoveryDomain::Received),
            (1, OutputRecoveryDomain::Change),
            (
                dom_crypto::MAX_PROVABLE_VALUE,
                OutputRecoveryDomain::SelfTransfer,
            ),
            (77, OutputRecoveryDomain::Received),
            (88, OutputRecoveryDomain::Change),
        ];
        let hash = [8u8; 32];
        let mut outputs = Vec::new();
        for (position, (value, domain)) in cases.into_iter().enumerate() {
            let material =
                build_recoverable_output(&root, chain(), value, 2, position as u64, domain)
                    .unwrap();
            outputs.push(scan_output(&material, 0, hash, position as u32, false));
        }
        let restored = restore_from_canonical_scan(
            &SEED,
            chain(),
            &[block(0, hash, [0u8; 32], outputs, vec![])],
        )
        .unwrap();
        assert_eq!(restored.outputs().count(), cases.len());
        assert!(restored
            .outputs()
            .any(|output| output.value == dom_crypto::MAX_PROVABLE_VALUE));
        assert!(restored
            .outputs()
            .any(|output| output.domain == OutputRecoveryDomain::SelfTransfer));
    }

    #[test]
    fn interrupted_resume_and_repeated_clean_scan_converge() {
        let fixture = fixture();
        let prefix = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks[..2]).unwrap();
        assert_eq!(prefix.outputs().count(), 2);
        let resumed = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks).unwrap();
        let repeated = restore_from_canonical_scan(&SEED, chain(), &fixture.blocks).unwrap();
        assert_eq!(resumed, repeated);
        assert_eq!(resumed.outputs().count(), 3);
    }

    #[test]
    fn tampered_proof_commitment_and_output_kind_are_not_accepted() {
        let fixture = fixture();
        let mut proof = fixture.blocks.clone();
        proof[0].outputs[0].range_proof[10] ^= 1;
        assert!(matches!(
            restore_from_canonical_scan(&SEED, chain(), &proof),
            Err(RestoreError::Crypto(_))
        ));

        let mut commitment = fixture.blocks.clone();
        commitment[0].outputs[0].commitment = fixture.change;
        let restored = restore_from_canonical_scan(&SEED, chain(), &commitment).unwrap();
        assert!(restored.get(&fixture.received).is_none());

        let mut kind = fixture.blocks.clone();
        kind[0].outputs[0].is_coinbase = true;
        let restored = restore_from_canonical_scan(&SEED, chain(), &kind).unwrap();
        assert!(restored.get(&fixture.received).is_none());
    }
}

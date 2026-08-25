//! The Scriptless projections of a DOM transaction.
//!
//! Two pure functions the laboratory lineage had placed inside
//! `dom-consensus`. They are OFF-CHAIN adapters: neither alters DOM
//! transaction serialization, and neither participates in consensus
//! validation — the original comment on the template said exactly that, and
//! it is transcribed with the code below.
//!
//! Because the node is mainnet and immutable, they live beside it. They read
//! only public fields of `dom_consensus::Transaction` and the node's own
//! public limits and kernel tag, so the bytes they produce are a function of
//! the node's canonical types and nothing else.
//!
//! NAR-002; Interop Foundation Document §2.2.

use dom_consensus::{Transaction, TransactionKernel};
use dom_core::{DomError, MAX_INPUTS_PER_TX, MAX_KERNELS_PER_TX, MAX_OUTPUTS_PER_TX};

/// Build the exact non-signature transaction-template projection assigned by
/// NAR-002. This is an off-chain Scriptless adapter and does not alter DOM
/// transaction serialization or consensus validation.
pub fn scriptless_transaction_template_bytes_v1(tx: &Transaction) -> Result<Vec<u8>, DomError> {
    if tx.inputs.len() > MAX_INPUTS_PER_TX
        || tx.outputs.len() > MAX_OUTPUTS_PER_TX
        || tx.kernels.len() > MAX_KERNELS_PER_TX
    {
        return Err(DomError::Invalid(
            "Scriptless template exceeds transaction count limits".into(),
        ));
    }
    let input_count = u32::try_from(tx.inputs.len())
        .map_err(|_| DomError::Invalid("Scriptless input count exceeds u32".into()))?;
    let output_count = u32::try_from(tx.outputs.len())
        .map_err(|_| DomError::Invalid("Scriptless output count exceeds u32".into()))?;
    let kernel_count = u32::try_from(tx.kernels.len())
        .map_err(|_| DomError::Invalid("Scriptless kernel count exceeds u32".into()))?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"DOMSCTT1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&input_count.to_le_bytes());
    for input in &tx.inputs {
        bytes.extend_from_slice(input.commitment.as_bytes());
    }
    bytes.extend_from_slice(&output_count.to_le_bytes());
    for output in &tx.outputs {
        if output.proof.len() > dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE {
            return Err(DomError::Invalid(
                "Scriptless output proof exceeds canonical envelope limit".into(),
            ));
        }
        let proof_len = u32::try_from(output.proof.len())
            .map_err(|_| DomError::Invalid("Scriptless output proof exceeds u32".into()))?;
        bytes.extend_from_slice(output.commitment.as_bytes());
        bytes.extend_from_slice(&proof_len.to_le_bytes());
        bytes.extend_from_slice(&output.proof);
    }
    bytes.extend_from_slice(&kernel_count.to_le_bytes());
    for kernel in &tx.kernels {
        bytes.push(kernel.features);
        bytes.extend_from_slice(&kernel.fee.noms().to_le_bytes());
        bytes.extend_from_slice(&kernel.lock_height.to_le_bytes());
        bytes.extend_from_slice(kernel.excess.as_bytes());
    }
    bytes.extend_from_slice(&tx.offset);
    Ok(bytes)
}

/// Return the unchanged authoritative DOM kernel-message digest.
pub fn scriptless_kernel_message_digest_v1(kernel: &TransactionKernel) -> dom_core::Hash256 {
    let mut body = [0u8; 17];
    body[0] = kernel.features;
    body[1..9].copy_from_slice(&kernel.fee.noms().to_le_bytes());
    body[9..17].copy_from_slice(&kernel.lock_height.to_le_bytes());
    dom_crypto::blake2b_256_tagged(dom_core::TAG_KERNEL_MSG, &body)
}

#[cfg(test)]
mod frozen {
    use super::*;
    use dom_consensus::{TransactionInput, TransactionOutput};
    use dom_core::Amount;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};

    /// A real on-curve commitment derived deterministically, so the vectors
    /// below depend on this module's projection rather than on random
    /// material — and remain valid points the node would accept.
    fn commitment(value: u64, blind: u8) -> Commitment {
        let mut bytes = [0u8; 32];
        bytes[31] = blind;
        Commitment::commit(
            value,
            &BlindingFactor::from_bytes(bytes).expect("a fixed nonzero blinding is valid"),
        )
    }

    fn fixture() -> Transaction {
        Transaction {
            inputs: vec![TransactionInput {
                commitment: commitment(7, 0x11),
            }],
            outputs: vec![TransactionOutput {
                commitment: commitment(9, 0x22),
                proof: vec![0xab; 8],
            }],
            kernels: vec![TransactionKernel {
                features: 0,
                fee: Amount::from_noms(1_234).expect("fixed fee is in range"),
                lock_height: 42,
                excess: commitment(11, 0x33),
                excess_signature: [0x44; 65],
            }],
            offset: [0x55; 32],
        }
    }

    /// The template's shape is normative: magic, version, then each section
    /// counted before its members. A reordering or a widened field changes
    /// these bytes, and this vector is what refuses it.
    #[test]
    fn template_bytes_are_frozen() {
        let bytes = scriptless_transaction_template_bytes_v1(&fixture())
            .expect("the fixture is within every count limit");

        assert_eq!(&bytes[..8], b"DOMSCTT1", "template magic moved");
        assert_eq!(&bytes[8..10], &1u16.to_le_bytes(), "template version moved");
        assert_eq!(
            bytes.len(),
            8 + 2 + 4 + 33 + 4 + (33 + 4 + 8) + 4 + (1 + 8 + 8 + 33) + 32,
            "template length changed: a field was added, dropped or resized"
        );
        assert_eq!(
            dom_crypto::blake2b_256(&bytes).as_bytes(),
            &FROZEN_TEMPLATE_DIGEST,
            "the frozen template projection changed"
        );
    }

    /// The kernel digest must stay the node's own tagged hash over exactly
    /// features, fee and lock height — the excess is deliberately absent.
    #[test]
    fn kernel_digest_is_the_nodes_tagged_hash() {
        let kernel = &fixture().kernels[0];
        let mut body = [0u8; 17];
        body[0] = kernel.features;
        body[1..9].copy_from_slice(&kernel.fee.noms().to_le_bytes());
        body[9..17].copy_from_slice(&kernel.lock_height.to_le_bytes());

        assert_eq!(
            scriptless_kernel_message_digest_v1(kernel),
            dom_crypto::blake2b_256_tagged(dom_core::TAG_KERNEL_MSG, &body),
            "the digest stopped being the node's tagged kernel hash"
        );
    }

    /// Frozen in this workspace on the fixture above. This is the laboratory's
    /// own additive vector: no outside authority pins it, and every property
    /// checkable independently of the constant is asserted separately above.
    const FROZEN_TEMPLATE_DIGEST: [u8; 32] = [
    0x1e, 0xa7, 0x61, 0x0f, 0x8f, 0xe5, 0x90, 0x80,
    0x9c, 0x53, 0x37, 0xe6, 0x6b, 0xd1, 0x98, 0x49,
    0xd1, 0x01, 0x1a, 0x97, 0x7e, 0x65, 0x39, 0xfe,
    0x61, 0xbd, 0xb9, 0x81, 0xac, 0xc9, 0xce, 0x1b,
];
}

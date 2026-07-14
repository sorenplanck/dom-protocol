//! dom-tx — Transaction building and validation.
#![deny(unsafe_code)]

pub mod slate;

use dom_consensus::{
    validate_balance_equation, validate_transaction_structure, Transaction, TransactionInput,
    TransactionKernel, TransactionOutput,
};
use dom_core::{Amount, DomError, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{range_proof_prove_bytes, schnorr_sign, SecretKey};
use thiserror::Error;

/// Errors that can occur in transaction operations.
#[derive(Debug, Error)]
pub enum TxError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid output: {0}")]
    InvalidOutput(String),

    #[error("invalid fee: {0}")]
    InvalidFee(String),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<DomError> for TxError {
    fn from(e: DomError) -> Self {
        match e {
            DomError::Malformed(msg) => TxError::Serialization(msg),
            DomError::Invalid(msg) => TxError::InvalidTransaction(msg),
            DomError::TemporarilyInvalid(msg) => TxError::InvalidTransaction(msg),
            DomError::Orphan(msg) => TxError::InvalidTransaction(msg),
            DomError::PolicyRejected(msg) => TxError::InvalidTransaction(msg),
            DomError::PeerMisbehavior { message, .. } => TxError::InvalidTransaction(message),
            DomError::Internal(msg) => TxError::Crypto(msg),
        }
    }
}

/// Trait for wallet-owned outputs that can be spent as transaction inputs.
pub trait InputSource {
    fn commitment(&self) -> [u8; 33];
    fn value(&self) -> u64;
    fn blinding(&self) -> [u8; 32];
    fn block_height(&self) -> u64;
    fn is_coinbase(&self) -> bool;
}

#[derive(Clone)]
struct BuilderInput {
    commitment: Commitment,
    value: u64,
    blinding: BlindingFactor,
}

#[derive(Clone)]
struct BuilderOutput {
    value: u64,
    blinding: BlindingFactor,
    canonical: Option<TransactionOutput>,
}

/// Wallet V3 output material. The blinding is returned only to the wallet
/// process; the transaction carries the commitment, proof, and encrypted
/// recovery capsule.
pub struct RecoverableOutputMaterial {
    pub value: u64,
    pub blinding: BlindingFactor,
    pub output: TransactionOutput,
}

/// Create one canonical Wallet V3 recoverable output.
#[allow(clippy::too_many_arguments)]
pub fn build_recoverable_output(
    root: &dom_crypto::recovery::RecoveryRoot,
    chain: dom_crypto::recovery::RecoveryChainContext,
    value: u64,
    account: u32,
    derivation_index: u64,
    domain: dom_crypto::recovery::OutputRecoveryDomain,
) -> Result<RecoverableOutputMaterial, TxError> {
    if value > dom_crypto::MAX_PROVABLE_VALUE {
        return Err(TxError::InvalidOutput(format!(
            "output value {value} exceeds MAX_PROVABLE_VALUE {}",
            dom_crypto::MAX_PROVABLE_VALUE
        )));
    }
    let blinding = BlindingFactor::random();
    let commitment = Commitment::commit(value, &blinding);
    let capsule = dom_crypto::recovery::create_recovery_capsule(
        root,
        chain,
        commitment.as_bytes(),
        dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        value,
        account,
        derivation_index,
        domain,
        &blinding,
    )
    .map_err(|error| TxError::Crypto(format!("recovery capsule creation failed: {error}")))?;
    let (proof, proof_commitment) =
        dom_crypto::range_proof_prove_bytes_with_extra_commit(value, &blinding, capsule.as_bytes())
            .map_err(|error| TxError::Crypto(format!("range proof generation failed: {error}")))?;
    if proof_commitment != *commitment.as_bytes() {
        return Err(TxError::Crypto(
            "range proof constructor commitment mismatch".into(),
        ));
    }
    let output = TransactionOutput::with_recovery_capsule(commitment, proof, &capsule)?;
    Ok(RecoverableOutputMaterial {
        value,
        blinding,
        output,
    })
}

/// Builder for standard Mimblewimble spend transactions.
///
/// The transaction created by this builder satisfies:
///
/// `sum(outputs) - sum(inputs) + fee*H = kernel_excess + offset*G`
///
/// with:
///
/// `kernel_excess = sum(output_blindings) - sum(input_blindings) - offset`
///
/// The `dom-crypto::pedersen::verify_balance_equation` implementation in this
/// workspace applies the fee term on the left side, which is algebraically the
/// form required for a spend where `sum(inputs) = sum(outputs) + fee`.
pub struct SpendBuilder {
    chain_id: [u8; 32],
    inputs: Vec<BuilderInput>,
    outputs: Vec<BuilderOutput>,
    fee: u64,
    lock_height: u64,
}

impl SpendBuilder {
    /// Create a new spend builder bound to a chain id.
    pub fn new(chain_id: &[u8; 32]) -> Self {
        Self {
            chain_id: *chain_id,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            lock_height: 0,
        }
    }

    /// Add spendable wallet outputs as transaction inputs.
    pub fn add_inputs<I: InputSource>(&mut self, inputs: Vec<I>) -> Result<(), TxError> {
        if inputs.is_empty() {
            return Err(TxError::InvalidInput(
                "transaction must contain at least one input".into(),
            ));
        }

        for input in inputs {
            let commitment = Commitment::from_compressed_bytes(&input.commitment())
                .map_err(|e| TxError::InvalidInput(format!("invalid input commitment: {e}")))?;

            let blinding = BlindingFactor::from_bytes(input.blinding())
                .map_err(|e| TxError::InvalidInput(format!("invalid input blinding: {e}")))?;

            self.inputs.push(BuilderInput {
                commitment,
                value: input.value(),
                blinding,
            });
        }

        Ok(())
    }

    /// Add a transaction output.
    ///
    /// A Bulletproof range proof is generated during `build()`.
    pub fn add_output(&mut self, amount: u64, blinding: BlindingFactor) -> Result<(), TxError> {
        if amount == 0 {
            return Err(TxError::InvalidOutput(
                "zero-value outputs are not allowed".into(),
            ));
        }

        Amount::from_noms(amount)
            .map_err(|e| TxError::InvalidOutput(format!("invalid output amount: {e}")))?;

        self.outputs.push(BuilderOutput {
            value: amount,
            blinding,
            canonical: None,
        });

        Ok(())
    }

    /// Add a canonical Wallet V3 output. Wallet V3 production code must use
    /// this method instead of the legacy proof-only `add_output` method.
    pub fn add_recoverable_output(
        &mut self,
        material: RecoverableOutputMaterial,
    ) -> Result<(), TxError> {
        if material.value == 0 {
            return Err(TxError::InvalidOutput(
                "zero-value outputs are not allowed".into(),
            ));
        }
        self.outputs.push(BuilderOutput {
            value: material.value,
            blinding: material.blinding,
            canonical: Some(material.output),
        });
        Ok(())
    }

    /// Set the transaction fee in noms.
    pub fn fee(&mut self, fee: u64) {
        self.fee = fee;
    }

    /// Optional lock height for future extension.
    ///
    /// This implementation emits plain kernels only, so non-zero lock heights
    /// are rejected in `build()`.
    pub fn lock_height(&mut self, lock_height: u64) {
        self.lock_height = lock_height;
    }

    /// Build a complete transaction.
    pub fn build(self) -> Result<Transaction, TxError> {
        self.validate_builder_state()?;

        let input_sum = checked_sum(self.inputs.iter().map(|i| i.value))
            .map_err(|e| TxError::InvalidInput(format!("input value overflow: {e}")))?;

        let output_sum = checked_sum(self.outputs.iter().map(|o| o.value))
            .map_err(|e| TxError::InvalidOutput(format!("output value overflow: {e}")))?;

        let required = output_sum
            .checked_add(self.fee)
            .ok_or_else(|| TxError::InvalidFee("output sum + fee overflow".into()))?;

        if input_sum != required {
            return Err(TxError::InvalidTransaction(format!(
                "unbalanced values: inputs={} outputs={} fee={} expected inputs=outputs+fee={}",
                input_sum, output_sum, self.fee, required
            )));
        }

        let tx_inputs = self
            .inputs
            .iter()
            .map(|i| TransactionInput {
                commitment: i.commitment.clone(),
            })
            .collect::<Vec<_>>();

        let mut tx_outputs = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            if let Some(canonical) = &output.canonical {
                tx_outputs.push(canonical.clone());
                continue;
            }
            // Generate commitment first
            let commitment = Commitment::commit(output.value, &output.blinding);

            // Then generate the final bounded aggregate range proof bytes.
            let (proof, _commitment_bytes) =
                range_proof_prove_bytes(output.value, &output.blinding)
                    .map_err(|e| TxError::Crypto(format!("range proof generation failed: {e}")))?;

            tx_outputs.push(TransactionOutput { commitment, proof });
        }

        // Random offset for graph privacy. Without this, kernel_excess equals
        // sum(output_blindings) - sum(input_blindings) directly, making transaction
        // graphs linkable. The offset randomizes the excess so observers cannot
        // correlate inputs and outputs by arithmetic.
        let offset = *BlindingFactor::random().as_bytes();

        let excess_blinding = self.compute_kernel_excess_blinding(&offset)?;
        let excess = Commitment::commit(0, &excess_blinding);

        let kernel_message = kernel_message(KERNEL_FEAT_PLAIN, self.fee, 0)?;
        let signing_key = SecretKey::from_bytes(excess_blinding.as_bytes())
            .map_err(|e| TxError::Crypto(format!("invalid kernel signing key: {e}")))?;

        let sig = schnorr_sign(&signing_key, kernel_message.as_bytes(), &self.chain_id)
            .map_err(|e| TxError::Crypto(format!("kernel Schnorr signature failed: {e}")))?;

        let kernel = TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(self.fee)
                .map_err(|e| TxError::InvalidFee(format!("invalid fee amount: {e}")))?,
            lock_height: 0,
            excess,
            excess_signature: sig.to_bytes(),
        };

        let tx = Transaction {
            inputs: tx_inputs,
            outputs: tx_outputs,
            kernels: vec![kernel],
            offset,
        };

        validate_transaction_structure(&tx)?;
        validate_balance_equation(&tx)?;

        Ok(tx)
    }

    fn validate_builder_state(&self) -> Result<(), TxError> {
        if self.inputs.is_empty() {
            return Err(TxError::InvalidInput(
                "transaction must contain at least one input".into(),
            ));
        }

        if self.outputs.is_empty() {
            return Err(TxError::InvalidOutput(
                "transaction must contain at least one output".into(),
            ));
        }

        if self.lock_height != 0 {
            return Err(TxError::InvalidTransaction(
                "SpendBuilder currently emits plain kernels; lock_height must be zero".into(),
            ));
        }

        Amount::from_noms(self.fee)
            .map_err(|e| TxError::InvalidFee(format!("invalid fee amount: {e}")))?;

        Ok(())
    }

    fn compute_kernel_excess_blinding(&self, offset: &[u8; 32]) -> Result<BlindingFactor, TxError> {
        let mut acc = self.outputs[0].blinding.clone();

        for output in self.outputs.iter().skip(1) {
            acc = acc
                .add(&output.blinding)
                .map_err(|e| TxError::Crypto(format!("output blinding sum failed: {e}")))?;
        }

        for input in &self.inputs {
            acc = acc
                .sub(&input.blinding)
                .map_err(|e| TxError::Crypto(format!("input blinding subtraction failed: {e}")))?
                .require_nonzero()
                .map_err(|e| TxError::Crypto(format!("kernel excess became zero: {e}")))?;
        }

        if *offset != [0u8; 32] {
            let offset_bf = BlindingFactor::from_bytes(*offset)
                .map_err(|e| TxError::Crypto(format!("invalid offset scalar: {e}")))?;
            acc = acc
                .sub(&offset_bf)
                .map_err(|e| TxError::Crypto(format!("offset subtraction failed: {e}")))?
                .require_nonzero()
                .map_err(|e| TxError::Crypto(format!("kernel excess became zero: {e}")))?;
        }

        Ok(acc)
    }
}

fn checked_sum<I>(values: I) -> Result<u64, &'static str>
where
    I: IntoIterator<Item = u64>,
{
    values
        .into_iter()
        .try_fold(0u64, |acc, v| acc.checked_add(v).ok_or("u64 overflow"))
}

fn kernel_message(features: u8, fee: u64, lock_height: u64) -> Result<dom_core::Hash256, TxError> {
    Amount::from_noms(fee).map_err(|e| TxError::InvalidFee(format!("invalid fee: {e}")))?;

    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(features);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());

    Ok(blake2b_256_tagged(TAG_KERNEL_MSG, &data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::schnorr_verify;

    #[derive(Clone)]
    struct TestInput {
        commitment: [u8; 33],
        value: u64,
        blinding: [u8; 32],
    }

    impl TestInput {
        fn new(value: u64, blinding: &BlindingFactor) -> Self {
            let commitment = Commitment::commit(value, blinding);
            Self {
                commitment: *commitment.as_bytes(),
                value,
                blinding: *blinding.as_bytes(),
            }
        }
    }

    impl InputSource for TestInput {
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
            0
        }

        fn is_coinbase(&self) -> bool {
            false
        }
    }

    #[test]
    fn build_exact_spend_transaction() {
        let chain_id = [7u8; 32];

        let input_bf = BlindingFactor::random();
        let output_bf = BlindingFactor::random();

        let input = TestInput::new(1_000, &input_bf);

        let mut builder = SpendBuilder::new(&chain_id);
        builder.add_inputs(vec![input]).unwrap();
        builder.add_output(900, output_bf).unwrap();
        builder.fee(100);

        let tx = builder.build().unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.kernels.len(), 1);
        assert_eq!(tx.kernels[0].fee.noms(), 100);

        validate_transaction_structure(&tx).unwrap();
        validate_balance_equation(&tx).unwrap();

        let msg = kernel_message(KERNEL_FEAT_PLAIN, 100, 0).unwrap();
        let sig =
            dom_crypto::SchnorrSignature::from_bytes(&tx.kernels[0].excess_signature).unwrap();
        let pk =
            dom_crypto::PublicKey::from_compressed_bytes(tx.kernels[0].excess.as_bytes()).unwrap();

        assert!(schnorr_verify(&sig, &pk, &chain_id, msg.as_bytes()).unwrap());
    }

    #[test]
    fn rejects_value_mismatch_without_change_output() {
        let chain_id = [8u8; 32];

        let input_bf = BlindingFactor::random();
        let output_bf = BlindingFactor::random();

        let input = TestInput::new(1_000, &input_bf);

        let mut builder = SpendBuilder::new(&chain_id);
        builder.add_inputs(vec![input]).unwrap();
        builder.add_output(800, output_bf).unwrap();
        builder.fee(100);

        let err = builder.build().unwrap_err().to_string();
        assert!(err.contains("unbalanced values"));
    }

    #[test]
    fn rejects_empty_inputs() {
        let chain_id = [9u8; 32];
        let output_bf = BlindingFactor::random();

        let mut builder = SpendBuilder::new(&chain_id);
        builder.add_output(100, output_bf).unwrap();
        builder.fee(1);

        assert!(builder.build().is_err());
    }

    // ===================================================================
    // dom-shield: KAV / invariant / Lens-B vectors that require access to
    // private items (`kernel_message`, `checked_sum`, builder internals).
    // These live in the src `#[cfg(test)]` module by necessity (integration
    // tests cannot reach private fns). No production logic is altered.
    // ===================================================================

    // -- KAV: kernel_message byte-freeze ---------------------------------
    //
    // Freezes the exact pre-image layout `features ‖ fee_le ‖ lock_height_le`
    // hashed under TAG_KERNEL_MSG. The expected hash is recomputed here from
    // the PUBLIC primitive (blake2b_256_tagged) over the byte layout asserted
    // by RFC, NOT copied from `kernel_message`'s own output — so a silent
    // reordering / endianness / tag change in `kernel_message` is caught.
    #[test]
    fn kav_kernel_message_byte_freeze() {
        let features = KERNEL_FEAT_PLAIN;
        // A distinctive in-range fee whose LE byte pattern is non-palindromic,
        // so endianness/reordering bugs are detectable. Must be <= MAX_SUPPLY.
        let fee: u64 = 0x0001_0203_0405_0607;
        let lock_height: u64 = 0; // plain kernels: lock_height is always 0

        let mut expected_preimage = Vec::with_capacity(1 + 8 + 8);
        expected_preimage.push(features);
        expected_preimage.extend_from_slice(&fee.to_le_bytes());
        expected_preimage.extend_from_slice(&lock_height.to_le_bytes());
        assert_eq!(
            expected_preimage.len(),
            17,
            "kernel message pre-image must be exactly 1+8+8 bytes"
        );

        let expected = blake2b_256_tagged(TAG_KERNEL_MSG, &expected_preimage);
        let actual = kernel_message(features, fee, lock_height).unwrap();
        assert_eq!(
            actual.as_bytes(),
            expected.as_bytes(),
            "kernel_message drifted from features‖fee_le‖lock_height_le under TAG_KERNEL_MSG"
        );
    }

    // KAV-drift: a different domain tag MUST produce a different digest, i.e.
    // the kernel message is genuinely domain-separated. Guards against a
    // refactor that drops or swaps TAG_KERNEL_MSG.
    #[test]
    fn kav_kernel_message_is_domain_separated() {
        let preimage = {
            let mut v = Vec::new();
            v.push(KERNEL_FEAT_PLAIN);
            v.extend_from_slice(&100u64.to_le_bytes());
            v.extend_from_slice(&0u64.to_le_bytes());
            v
        };
        let tagged = kernel_message(KERNEL_FEAT_PLAIN, 100, 0).unwrap();
        let untagged = blake2b_256_tagged("DOM:not-the-kernel-tag", &preimage);
        assert_ne!(
            tagged.as_bytes(),
            untagged.as_bytes(),
            "kernel_message must be domain-separated under TAG_KERNEL_MSG"
        );
    }

    // KAV-drift: fee endianness is little-endian and load-bearing. Swapping a
    // fee's byte order must change the digest (catches a to_be_bytes regress).
    #[test]
    fn kav_kernel_message_fee_endianness_matters() {
        // Two in-range fees that are byte-reverses of each other within the
        // low bytes: 0x0102 (258) vs 0x0201 (513). Distinct LE encodings.
        let a = kernel_message(KERNEL_FEAT_PLAIN, 0x0102, 0).unwrap();
        let b = kernel_message(KERNEL_FEAT_PLAIN, 0x0201, 0).unwrap();
        assert_ne!(
            a.as_bytes(),
            b.as_bytes(),
            "fee must be folded into the kernel message as distinct LE bytes"
        );
    }

    // -- KAV-negativo: SpendBuilder rejections ---------------------------

    // amount == 0 is rejected at add_output (zero-value output ban).
    #[test]
    fn kav_neg_rejects_zero_value_output() {
        let mut builder = SpendBuilder::new(&[1u8; 32]);
        let err = builder
            .add_output(0, BlindingFactor::random())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("zero-value outputs"),
            "expected zero-value rejection, got: {err}"
        );
    }

    // amount > MAX_SUPPLY_NOMS is rejected at add_output (Amount bound).
    #[test]
    fn kav_neg_rejects_output_over_max_supply() {
        let mut builder = SpendBuilder::new(&[1u8; 32]);
        let over = dom_core::MAX_SUPPLY_NOMS + 1;
        assert!(
            builder.add_output(over, BlindingFactor::random()).is_err(),
            "output above MAX_SUPPLY_NOMS must be rejected"
        );
    }

    // Non-zero lock_height is rejected in build() — SpendBuilder only emits
    // PLAIN kernels, so a "height-locked" spend dressed as a plain kernel must
    // not be silently downgraded.
    #[test]
    fn kav_neg_rejects_nonzero_lock_height_as_plain_kernel() {
        let input_bf = BlindingFactor::random();
        let output_bf = BlindingFactor::random();
        let mut builder = SpendBuilder::new(&[2u8; 32]);
        builder
            .add_inputs(vec![TestInput::new(1_000, &input_bf)])
            .unwrap();
        builder.add_output(900, output_bf).unwrap();
        builder.fee(100);
        builder.lock_height(144);

        let err = builder.build().unwrap_err().to_string();
        assert!(
            err.contains("lock_height must be zero"),
            "non-zero lock_height must be rejected for plain kernels, got: {err}"
        );
    }

    // Even when fee makes inputs == outputs + fee, a non-zero lock height
    // still must NOT silently set kernel.lock_height: the build is rejected
    // before any kernel is emitted. (Defends against a future relaxation that
    // forgets to also stamp the kernel feature bit.)
    #[test]
    fn kav_neg_balanced_but_locked_still_rejected() {
        let input_bf = BlindingFactor::random();
        let output_bf = BlindingFactor::random();
        let mut builder = SpendBuilder::new(&[3u8; 32]);
        builder
            .add_inputs(vec![TestInput::new(500, &input_bf)])
            .unwrap();
        builder.add_output(500, output_bf).unwrap();
        builder.fee(0);
        builder.lock_height(1);
        assert!(builder.build().is_err());
    }

    // -- invariant: balance enforced by build() --------------------------

    // inputs < outputs + fee (deficit) is rejected.
    #[test]
    fn inv_rejects_input_deficit() {
        let input_bf = BlindingFactor::random();
        let output_bf = BlindingFactor::random();
        let mut builder = SpendBuilder::new(&[4u8; 32]);
        builder
            .add_inputs(vec![TestInput::new(900, &input_bf)])
            .unwrap();
        builder.add_output(900, output_bf).unwrap();
        builder.fee(100); // need 1000, have 900
        let err = builder.build().unwrap_err().to_string();
        assert!(err.contains("unbalanced values"), "got: {err}");
    }

    // inputs > outputs + fee (would mint value to the kernel) is rejected.
    #[test]
    fn inv_rejects_input_surplus_no_inflation() {
        let input_bf = BlindingFactor::random();
        let output_bf = BlindingFactor::random();
        let mut builder = SpendBuilder::new(&[5u8; 32]);
        builder
            .add_inputs(vec![TestInput::new(2_000, &input_bf)])
            .unwrap();
        builder.add_output(900, output_bf).unwrap();
        builder.fee(100); // need 1000, have 2000 -> surplus must be rejected
        let err = builder.build().unwrap_err().to_string();
        assert!(err.contains("unbalanced values"), "got: {err}");
    }

    // -- invariant: checked_sum overflow ---------------------------------

    // checked_sum saturates to an error rather than wrapping. Two u64::MAX/2+1
    // values overflow u64.
    #[test]
    fn inv_checked_sum_detects_overflow() {
        let half = u64::MAX / 2 + 1;
        assert!(
            checked_sum([half, half]).is_err(),
            "checked_sum must reject u64 overflow"
        );
        assert_eq!(checked_sum([1u64, 2, 3]).unwrap(), 6);
        assert_eq!(checked_sum(std::iter::empty::<u64>()).unwrap(), 0);
    }

    // output_sum + fee overflow path: outputs that individually pass but whose
    // (sum + fee) overflows u64 must be rejected without wrapping. We drive it
    // through build() so the checked_add in `required` is exercised. Using
    // MAX_SUPPLY_NOMS-bounded values means the per-output Amount check passes
    // but consensus balance still rejects; the explicit overflow arithmetic is
    // unit-tested above via checked_sum. Here we assert the build refuses a
    // fee that pushes required past input_sum.
    #[test]
    fn inv_output_sum_plus_fee_no_wrap() {
        // Build a balanced tx, then bump fee by u64::MAX to force the
        // checked_add(required) / balance check to reject instead of wrap.
        let input_bf = BlindingFactor::random();
        let output_bf = BlindingFactor::random();
        let mut builder = SpendBuilder::new(&[6u8; 32]);
        builder
            .add_inputs(vec![TestInput::new(1_000, &input_bf)])
            .unwrap();
        builder.add_output(1_000, output_bf).unwrap();
        builder.fee(u64::MAX); // output_sum + fee overflows OR Amount rejects
        assert!(
            builder.build().is_err(),
            "fee=u64::MAX must not wrap output_sum+fee into a valid balance"
        );
    }

    // -- invariant: zero-excess rejection (require_nonzero) --------------
    //
    // If output_blinding == input_blinding and offset is forced to zero, the
    // kernel excess scalar would be zero (an identity excess that breaks the
    // Schnorr binding). compute_kernel_excess_blinding must reject via
    // require_nonzero. We call it directly with a zero offset to deterministically
    // hit the require_nonzero guard (build() uses a random offset and cannot be
    // steered to this state).
    #[test]
    fn inv_compute_excess_rejects_zero_scalar() {
        let bf = BlindingFactor::random();
        let mut builder = SpendBuilder::new(&[7u8; 32]);
        // one input and one output sharing the SAME blinding -> excess == 0
        builder
            .add_inputs(vec![TestInput::new(1_000, &bf)])
            .unwrap();
        builder.add_output(1_000, bf.clone()).unwrap();
        let zero_offset = [0u8; 32];
        let res = builder.compute_kernel_excess_blinding(&zero_offset);
        assert!(
            res.is_err(),
            "kernel excess of zero must be rejected by require_nonzero"
        );
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("zero"),
            "expected zero-excess rejection, got: {msg}"
        );
    }

    // Non-degenerate excess (distinct blindings) is accepted with zero offset:
    // proves the rejection above is specific to the zero scalar, not a blanket
    // failure of the zero-offset path.
    #[test]
    fn inv_compute_excess_accepts_nonzero_scalar() {
        let in_bf = BlindingFactor::from_bytes([1u8; 32]).unwrap();
        let out_bf = BlindingFactor::from_bytes([2u8; 32]).unwrap();
        let mut builder = SpendBuilder::new(&[7u8; 32]);
        builder
            .add_inputs(vec![TestInput::new(1_000, &in_bf)])
            .unwrap();
        builder.add_output(1_000, out_bf).unwrap();
        assert!(builder.compute_kernel_excess_blinding(&[0u8; 32]).is_ok());
    }

    // -- Lens B (funds-safety): offset escapes Zeroizing ----------------
    //
    // STATIC-REVIEW PROBE (documented finding, not a behavioral assertion).
    //
    // In build(): `let offset = *BlindingFactor::random().as_bytes();`
    // dereferences and COPIES the 32 secret bytes out of the Zeroizing
    // BlindingFactor into a plain `[u8; 32]`. That copy is then moved into
    // Transaction.offset (a public, non-zeroizing field) and also re-derived
    // into a BlindingFactor inside compute_kernel_excess_blinding. The plain
    // [u8;32] stack/heap copy is NOT zeroized on drop.
    //
    // NOTE ON SEVERITY: the transaction offset is, by Mimblewimble design,
    // PUBLIC slate/chain data (it ships in Transaction.offset and on-chain).
    // So this particular intermediate is not a SECRET leak in the usual sense
    // — leaking the offset does not reveal a spend key. It IS, however, a
    // non-zeroized scalar intermediate and worth recording per Lens B.
    // This cannot be asserted behaviorally (we cannot inspect freed memory in
    // safe Rust), so it is recorded as an #[ignore] static-review marker.
    #[test]
    #[ignore = "static-review: offset = *BlindingFactor::random().as_bytes() copies secret bytes out of Zeroizing into a plain [u8;32] (Transaction.offset is public by design; recorded, not behaviorally testable)"]
    fn lensb_offset_escapes_zeroizing_static_review() {
        // Intentionally empty: see #[ignore] note. Documented finding.
    }

    // STATIC-REVIEW PROBE: compute_kernel_excess_blinding intermediates.
    // `acc` is a BlindingFactor (Zeroize + ZeroizeOnDrop), and each `.add`/
    // `.sub`/`.require_nonzero` returns a fresh Zeroizing BlindingFactor; the
    // shadowed previous `acc` is dropped (and thus zeroized) on reassignment.
    // The `offset_bf` re-derived from the plain [u8;32] offset is also a
    // Zeroizing BlindingFactor. The ONLY non-zeroized intermediate on this
    // path is the plain `offset` array covered above. The accumulator chain
    // itself is zeroized by construction (ZeroizeOnDrop on BlindingFactor).
    // Recorded as bounded-by-construction; no behavioral test (cannot inspect
    // freed memory in safe Rust).
    #[test]
    #[ignore = "static-review: compute_kernel_excess_blinding accumulator is Zeroizing/ZeroizeOnDrop by construction; only the public `offset` [u8;32] (above) is non-zeroized"]
    fn lensb_kernel_excess_accumulator_zeroized_static_review() {
        // Intentionally empty: see #[ignore] note. Bounded-by-construction.
    }
}

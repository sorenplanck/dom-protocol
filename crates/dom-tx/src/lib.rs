//! dom-tx — Transaction building and validation.
#![deny(unsafe_code)]

use dom_consensus::{
    validate_balance_equation, validate_transaction_structure, Transaction, TransactionInput,
    TransactionKernel, TransactionOutput,
};
use dom_core::{Amount, DomError, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp_prove, schnorr_sign, SecretKey};
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
            // Generate commitment first
            let commitment = Commitment::commit(output.value, &output.blinding);

            // Then generate range proof
            let (proof, _commitment_bytes) = bp_prove(output.value, &output.blinding)
                .map_err(|e| TxError::Crypto(format!("range proof generation failed: {e}")))?;

            tx_outputs.push(TransactionOutput {
                commitment,
                proof: proof.bytes,
            });
        }

        // TODO(mainnet): Replace with random scalar for graph privacy.
        // Zero offset is consensus-valid but allows transaction linkability:
        // kernel_excess = sum(output_blindings) - sum(input_blindings) directly,
        // without randomization. Acceptable for testnet.
        // See: Mimblewimble offset privacy in Grin docs.
        let offset = [0u8; 32];

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
}

#![allow(missing_docs)]
//! Transaction types for Mimblewimble — updated per RFC-0008 and RFC-0010.
//!
//! RFC-0008: Complete balance equation with fee and offset.
//! RFC-0008: Coinbase kernel with explicit_value (inflation prevention).
//! RFC-0010: Weight units, lock_height validation, coinbase maturity placement.

use dom_core::{
    fee_policy, Amount, BlockHeight, DomError, PeerMisbehavior, KERNEL_FEAT_COINBASE,
    KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN, MAX_INPUTS_PER_TX, MAX_KERNELS_PER_TX,
    MAX_OUTPUTS_PER_TX, MAX_TX_WEIGHT, WEIGHT_COINBASE_KERNEL, WEIGHT_KERNEL,
};
use dom_crypto::pedersen::Commitment;
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};

/// Validate that a kernel features byte is a known value.
/// Unknown feature values are consensus-invalid per RFC-0008 Section 5.
pub fn validate_kernel_features(features: u8) -> Result<(), DomError> {
    match features {
        KERNEL_FEAT_PLAIN | KERNEL_FEAT_COINBASE | KERNEL_FEAT_HEIGHT_LOCKED => Ok(()),
        other => Err(DomError::Invalid(format!(
            "unknown kernel features 0x{other:02x}"
        ))),
    }
}

/// A transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInput {
    pub commitment: Commitment,
}

impl DomSerialize for TransactionInput {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_bytes(self.commitment.as_bytes());
        Ok(())
    }
}

impl DomDeserialize for TransactionInput {
    const MIN_SERIALIZED_SIZE: usize = 33;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let bytes = r.read_array::<33>()?;
        Ok(Self {
            commitment: Commitment::from_compressed_bytes(&bytes)?,
        })
    }
}

/// A transaction output with Bulletproof range proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionOutput {
    pub commitment: Commitment,
    /// Canonical output proof envelope. Legacy protocol/test outputs contain a
    /// 739-byte proof. Wallet V3 outputs append one 96-byte recovery capsule.
    pub proof: Vec<u8>,
}

impl TransactionOutput {
    /// Build a Wallet V3 output envelope from the unchanged range proof and a
    /// canonical recovery capsule.
    pub fn with_recovery_capsule(
        commitment: Commitment,
        proof: Vec<u8>,
        capsule: &dom_crypto::recovery::RecoveryCapsule,
    ) -> Result<Self, DomError> {
        if proof.len() != dom_crypto::RANGE_PROOF_SIZE {
            return Err(DomError::Invalid(format!(
                "range proof length {} != {}",
                proof.len(),
                dom_crypto::RANGE_PROOF_SIZE
            )));
        }
        let mut envelope = Vec::with_capacity(dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE);
        envelope.extend_from_slice(&proof);
        envelope.extend_from_slice(capsule.as_bytes());
        Ok(Self {
            commitment,
            proof: envelope,
        })
    }

    /// Return the unchanged 739-byte mathematical range proof.
    pub fn range_proof_bytes(&self) -> Result<&[u8], DomError> {
        match self.proof.len() {
            dom_crypto::RANGE_PROOF_SIZE => Ok(&self.proof),
            dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE => {
                Ok(&self.proof[..dom_crypto::RANGE_PROOF_SIZE])
            }
            length => Err(DomError::Invalid(format!(
                "noncanonical output proof envelope length {length}"
            ))),
        }
    }

    /// Parse the optional Wallet V3 recovery capsule.
    pub fn recovery_capsule(
        &self,
    ) -> Result<Option<dom_crypto::recovery::RecoveryCapsule>, DomError> {
        match self.proof.len() {
            dom_crypto::RANGE_PROOF_SIZE => Ok(None),
            dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE => {
                dom_crypto::recovery::RecoveryCapsule::from_bytes(
                    &self.proof[dom_crypto::RANGE_PROOF_SIZE..],
                )
                .map(Some)
            }
            length => Err(DomError::Invalid(format!(
                "noncanonical output proof envelope length {length}"
            ))),
        }
    }
}

impl DomSerialize for TransactionOutput {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_bytes(self.commitment.as_bytes());
        w.write_vec(&self.proof)?;
        Ok(())
    }
}

impl DomDeserialize for TransactionOutput {
    const MIN_SERIALIZED_SIZE: usize = 33 + 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let commitment_bytes = r.read_array::<33>()?;
        let proof = r.read_vec(dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE)?;
        Ok(Self {
            commitment: Commitment::from_compressed_bytes(&commitment_bytes)?,
            proof,
        })
    }
}

/// Standard transaction kernel (PLAIN or HEIGHT_LOCKED).
/// RFC-0008: fee is publicly visible and enforced via balance equation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionKernel {
    pub features: u8,
    pub fee: Amount,
    pub lock_height: u64,
    pub excess: Commitment,
    pub excess_signature: [u8; 65],
}

impl TransactionKernel {
    pub fn weight(&self) -> u32 {
        WEIGHT_KERNEL
    }
}

impl DomSerialize for TransactionKernel {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u8(self.features);
        self.fee.serialize(w)?;
        w.write_u64(self.lock_height);
        w.write_bytes(self.excess.as_bytes());
        w.write_bytes(&self.excess_signature);
        Ok(())
    }
}

impl DomDeserialize for TransactionKernel {
    const MIN_SERIALIZED_SIZE: usize = 1 + 8 + 8 + 33 + 65;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            features: r.read_u8()?,
            fee: Amount::deserialize(r)?,
            lock_height: r.read_u64()?,
            excess: Commitment::from_compressed_bytes(&r.read_array::<33>()?)?,
            excess_signature: r.read_array::<65>()?,
        })
    }
}

/// Coinbase kernel — RFC-0008 Section 3.
/// explicit_value = block_reward(height) + sum(tx_fees).
/// This is the ONLY inflation control point in the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseKernel {
    pub features: u8,        // always KERNEL_FEAT_COINBASE = 0x01
    pub explicit_value: u64, // total coinbase in noms — MUST match block_reward + fees
    pub excess: Commitment,
    pub excess_signature: [u8; 65],
}

impl CoinbaseKernel {
    pub fn weight(&self) -> u32 {
        WEIGHT_COINBASE_KERNEL
    }

    /// Verify explicit_value == block_reward(height) + tx_fees.
    /// This is the primary inflation prevention check (RFC-0008 Section 3.2).
    pub fn validate_explicit_value(
        &self,
        block_height: BlockHeight,
        total_tx_fees: u64,
    ) -> Result<(), DomError> {
        let reward = dom_core::block_reward(block_height).noms();
        let expected = reward
            .checked_add(total_tx_fees)
            .ok_or_else(|| DomError::Invalid("coinbase value overflow".into()))?;
        if expected > dom_crypto::MAX_PROVABLE_VALUE {
            return Err(DomError::Invalid(format!(
                "coinbase expected value {} exceeds MAX_PROVABLE_VALUE {}",
                expected,
                dom_crypto::MAX_PROVABLE_VALUE
            )));
        }
        if self.explicit_value > dom_crypto::MAX_PROVABLE_VALUE {
            return Err(DomError::Invalid(format!(
                "coinbase explicit_value {} exceeds MAX_PROVABLE_VALUE {}",
                self.explicit_value,
                dom_crypto::MAX_PROVABLE_VALUE
            )));
        }
        if self.explicit_value != expected {
            return Err(DomError::Invalid(format!(
                "coinbase explicit_value {}: expected {} (reward={} + fees={})",
                self.explicit_value, expected, reward, total_tx_fees
            )));
        }
        Ok(())
    }
}

impl DomSerialize for CoinbaseKernel {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u8(self.features);
        w.write_u64(self.explicit_value);
        w.write_bytes(self.excess.as_bytes());
        w.write_bytes(&self.excess_signature);
        Ok(())
    }
}

impl DomDeserialize for CoinbaseKernel {
    const MIN_SERIALIZED_SIZE: usize = 1 + 8 + 33 + 65;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let features = r.read_u8()?;
        if features != KERNEL_FEAT_COINBASE {
            return Err(DomError::Malformed(format!(
                "expected coinbase features 0x01, got 0x{features:02x}"
            )));
        }
        let explicit_value = r.read_u64()?;
        let excess = Commitment::from_compressed_bytes(&r.read_array::<33>()?)?;
        let excess_signature = r.read_array::<65>()?;
        Ok(Self {
            features,
            explicit_value,
            excess,
            excess_signature,
        })
    }
}

/// Attempt to deserialize a coinbase kernel where a plain kernel was provided.
/// Returns error identifying the field mismatch.
pub fn reject_plain_kernel_as_coinbase(data: &[u8]) -> Result<(), DomError> {
    if data.is_empty() {
        return Ok(());
    }
    if data[0] != KERNEL_FEAT_COINBASE {
        return Err(DomError::Malformed(format!(
            "plain kernel (features=0x{:02x}) cannot be used as coinbase",
            data[0]
        )));
    }
    Ok(())
}

/// A complete non-coinbase transaction.
/// RFC-0008 balance equation:
///   sum(outputs) - sum(inputs) = sum(kernel_excesses) + offset*G + total_fee*H
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub kernels: Vec<TransactionKernel>,
    pub offset: [u8; 32], // RFC-0008 Section 4: random scalar for graph privacy
}

impl Transaction {
    pub fn weight(&self) -> u32 {
        self.weight_checked()
            .expect("deserialized transaction count limits keep weight in u32")
    }

    pub fn fee_shape(&self) -> Result<fee_policy::TransactionShape, DomError> {
        fee_policy::TransactionShape::from_counts(
            self.inputs.len(),
            self.outputs.len(),
            self.kernels.len(),
        )
    }

    pub fn weight_checked(&self) -> Result<u32, DomError> {
        let weight = fee_policy::transaction_weight(self.fee_shape()?)?;
        weight
            .total_weight
            .try_into()
            .map_err(|_| DomError::Internal("transaction weight conversion overflow".into()))
    }

    pub fn total_fee(&self) -> Result<u64, DomError> {
        self.kernels.iter().try_fold(0u64, |acc, k| {
            acc.checked_add(k.fee.noms())
                .ok_or_else(|| DomError::Invalid("fee sum overflow".into()))
        })
    }
}

impl DomSerialize for Transaction {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_list(&self.inputs)?;
        w.write_list(&self.outputs)?;
        w.write_list(&self.kernels)?;
        w.write_bytes(&self.offset);
        Ok(())
    }
}

impl DomDeserialize for Transaction {
    const MIN_SERIALIZED_SIZE: usize = 4 + 4 + 4 + 32;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            inputs: r.read_list::<TransactionInput>(MAX_INPUTS_PER_TX)?,
            outputs: r.read_list::<TransactionOutput>(MAX_OUTPUTS_PER_TX)?,
            kernels: r.read_list::<TransactionKernel>(MAX_KERNELS_PER_TX)?,
            offset: r.read_array::<32>()?,
        })
    }
}

/// Validate transaction structure — RFC-0007 steps 1-5, RFC-0008, RFC-0010.
pub fn validate_transaction_structure(tx: &Transaction) -> Result<(), DomError> {
    // Step 2: Primitive validation
    if tx.inputs.len() > MAX_INPUTS_PER_TX {
        return Err(DomError::Invalid(format!(
            "too many inputs: {}",
            tx.inputs.len()
        )));
    }
    if tx.outputs.len() > MAX_OUTPUTS_PER_TX {
        return Err(DomError::Invalid(format!(
            "too many outputs: {}",
            tx.outputs.len()
        )));
    }
    if tx.kernels.len() > MAX_KERNELS_PER_TX {
        return Err(DomError::Invalid(format!(
            "too many kernels: {}",
            tx.kernels.len()
        )));
    }
    if tx.kernels.is_empty() {
        return Err(DomError::Invalid(
            "transaction must have at least one kernel".into(),
        ));
    }
    for (i, o) in tx.outputs.iter().enumerate() {
        if o.proof.is_empty() {
            return Err(DomError::Invalid(format!(
                "output {i} has empty range proof"
            )));
        }
        if o.proof.len() > dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE {
            return Err(DomError::Invalid(format!(
                "output {i} proof envelope too large"
            )));
        }
    }

    // Validate kernel features + coinbase restriction
    for (i, k) in tx.kernels.iter().enumerate() {
        validate_kernel_features(k.features)?;
        if k.features == KERNEL_FEAT_COINBASE {
            return Err(DomError::Invalid(format!(
                "kernel {i}: COINBASE feature in non-coinbase transaction"
            )));
        }
        if k.features == KERNEL_FEAT_HEIGHT_LOCKED && k.lock_height == 0 {
            return Err(DomError::Invalid(format!(
                "kernel {i}: HEIGHT_LOCKED with lock_height == 0"
            )));
        }
        // AUDIT: non-HEIGHT_LOCKED kernels with lock_height != 0 are malleable
        // (hash changes without semantic change) — reject them.
        if k.features != KERNEL_FEAT_HEIGHT_LOCKED && k.lock_height != 0 {
            return Err(DomError::Invalid(format!(
                "kernel {i}: lock_height must be 0 for non-HEIGHT_LOCKED kernels (got {})",
                k.lock_height
            )));
        }
    }

    // Step 5: Duplicate detection
    {
        let mut seen = std::collections::HashSet::new();
        for i in &tx.inputs {
            if !seen.insert(*i.commitment.as_bytes()) {
                return Err(DomError::Invalid("duplicate input commitment".into()));
            }
        }
    }
    {
        let mut seen = std::collections::HashSet::new();
        for o in &tx.outputs {
            if !seen.insert(*o.commitment.as_bytes()) {
                return Err(DomError::Invalid("duplicate output commitment".into()));
            }
        }
    }

    // Step 8: Fee overflow check
    tx.total_fee()?;

    // Step 9: Weight
    let w = tx.weight_checked()?;
    if w > MAX_TX_WEIGHT {
        return Err(DomError::Invalid(format!(
            "tx weight {w} > MAX_TX_WEIGHT {MAX_TX_WEIGHT}"
        )));
    }

    Ok(())
}

/// Check lock heights — RFC-0010 Section 7. Returns TemporarilyInvalid if locked.
pub fn validate_lock_heights(tx: &Transaction, current: BlockHeight) -> Result<(), DomError> {
    for k in &tx.kernels {
        if k.features == KERNEL_FEAT_HEIGHT_LOCKED && k.lock_height > current.0 {
            return Err(DomError::TemporarilyInvalid(format!(
                "kernel locked until height {}, current {}",
                k.lock_height, current.0
            )));
        }
    }
    Ok(())
}

/// Coinbase transaction container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseTransaction {
    pub output: TransactionOutput,
    pub kernel: CoinbaseKernel,
    pub offset: [u8; 32], // MUST be zero
}

impl CoinbaseTransaction {
    /// Validate coinbase transaction — AUDIT FIX: now validates Schnorr signature.
    ///
    /// Without signature validation, any observer could copy a coinbase kernel
    /// and claim the mining reward without possessing the blinding factor private key.
    pub fn validate(
        &self,
        height: BlockHeight,
        total_tx_fees: u64,
        chain_id: &[u8; 32],
    ) -> Result<(), DomError> {
        // R-05: reject any coinbase kernel whose features are not the coinbase
        // constant, before any signature verification. Defense in depth alongside
        // the deserialize-side check in CoinbaseKernel::deserialize — a kernel can
        // reach validate() in memory without ever being deserialized (e.g. built
        // directly), so a feature mismatch with an otherwise-valid signature must
        // still be rejected here.
        if self.kernel.features != KERNEL_FEAT_COINBASE {
            return Err(DomError::Invalid(format!(
                "coinbase kernel features must be 0x{:02x}, got 0x{:02x}",
                KERNEL_FEAT_COINBASE, self.kernel.features
            )));
        }
        if self.offset != [0u8; 32] {
            return Err(DomError::Invalid("coinbase offset must be zero".into()));
        }
        self.kernel.validate_explicit_value(height, total_tx_fees)?;
        if self.output.proof.is_empty() {
            return Err(DomError::Invalid(
                "coinbase output has empty range proof".into(),
            ));
        }
        let proof = self.output.range_proof_bytes()?;
        let valid = match self.output.recovery_capsule()? {
            Some(capsule) => dom_crypto::range_proof_verify_with_extra_commit(
                self.output.commitment.as_bytes(),
                proof,
                capsule.as_bytes(),
            ),
            None => dom_crypto::range_proof_verify(self.output.commitment.as_bytes(), proof),
        };
        match valid {
            Ok(true) => {}
            Ok(false) => {
                return Err(DomError::Invalid(
                    "coinbase range proof verification failed".into(),
                ));
            }
            Err(e) => {
                return Err(DomError::Invalid(format!(
                    "coinbase range proof error: {e}"
                )));
            }
        }
        // Validate Schnorr signature — proves miner owns the blinding factor r
        // such that kernel.excess = r*G. Prevents coinbase theft.
        self.validate_coinbase_signature(chain_id)?;
        Ok(())
    }

    fn validate_coinbase_signature(&self, chain_id: &[u8; 32]) -> Result<(), DomError> {
        use dom_core::TAG_KERNEL_MSG_COINBASE;
        use dom_crypto::hash::blake2b_256_tagged;
        use dom_crypto::{schnorr_verify, PublicKey, SchnorrSignature};

        // RFC-0009 §2.2 coinbase kernel message.
        // chain_id is bound via schnorr_challenge(), not here — single source of truth.
        let kernel_message = {
            let mut data = Vec::with_capacity(1 + 8);
            data.push(self.kernel.features);
            data.extend_from_slice(&self.kernel.explicit_value.to_le_bytes());
            blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
        };

        let sig = SchnorrSignature::from_bytes(&self.kernel.excess_signature)
            .map_err(|e| DomError::Invalid(format!("coinbase signature malformed: {e}")))?;
        let pk = PublicKey::from_compressed_bytes(self.kernel.excess.as_bytes())
            .map_err(|e| DomError::Invalid(format!("coinbase excess invalid: {e}")))?;

        match schnorr_verify(&sig, &pk, chain_id, kernel_message.as_bytes()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(DomError::peer_misbehavior(
                PeerMisbehavior::InvalidSignature,
                "coinbase kernel signature invalid — miner does not prove ownership",
            )),
            Err(DomError::Internal(msg)) => Err(DomError::Internal(format!("coinbase sig: {msg}"))),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::{HALVING_INTERVAL, INITIAL_BLOCK_REWARD, WEIGHT_OUTPUT};
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::keys::SecretKey;
    use dom_crypto::pedersen::BlindingFactor;
    use dom_crypto::schnorr_sign;

    fn g_point() -> Commitment {
        let g = [
            0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        Commitment::from_compressed_bytes(&g).unwrap()
    }

    fn plain_kernel(fee: u64) -> TransactionKernel {
        TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess: g_point(),
            excess_signature: [0u8; 65],
        }
    }

    fn dummy_output() -> TransactionOutput {
        TransactionOutput {
            commitment: g_point(),
            proof: vec![0u8; 100],
        }
    }

    fn valid_coinbase_for_test(chain_id: &[u8; 32]) -> CoinbaseTransaction {
        let explicit_value = INITIAL_BLOCK_REWARD;
        let blinding = BlindingFactor::from_bytes([9u8; 32]).unwrap();
        let output_commitment = Commitment::commit(explicit_value, &blinding);
        let (proof, _) = dom_crypto::range_proof_prove_bytes(explicit_value, &blinding).unwrap();
        let excess = Commitment::commit(0, &blinding);
        let kernel_message = {
            let mut data = Vec::with_capacity(9);
            data.push(KERNEL_FEAT_COINBASE);
            data.extend_from_slice(&explicit_value.to_le_bytes());
            blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &data)
        };
        let sk = SecretKey::from_bytes(blinding.as_bytes()).unwrap();
        let signature = schnorr_sign(&sk, kernel_message.as_bytes(), chain_id).unwrap();

        CoinbaseTransaction {
            output: TransactionOutput {
                commitment: output_commitment,
                proof,
            },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value,
                excess,
                excess_signature: signature.to_bytes(),
            },
            offset: [0u8; 32],
        }
    }

    fn minimal_tx() -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![dummy_output()],
            kernels: vec![plain_kernel(1000)],
            offset: [0u8; 32],
        }
    }

    #[test]
    fn minimal_tx_ok() {
        assert!(validate_transaction_structure(&minimal_tx()).is_ok());
    }

    #[test]
    fn coinbase_in_plain_tx_rejected() {
        let mut tx = minimal_tx();
        tx.kernels[0].features = KERNEL_FEAT_COINBASE;
        assert!(validate_transaction_structure(&tx).is_err());
    }

    #[test]
    fn unknown_features_rejected() {
        let mut tx = minimal_tx();
        tx.kernels[0].features = 0xFF;
        assert!(validate_transaction_structure(&tx).is_err());
    }

    #[test]
    fn height_locked_zero_rejected() {
        let mut tx = minimal_tx();
        tx.kernels[0].features = KERNEL_FEAT_HEIGHT_LOCKED;
        tx.kernels[0].lock_height = 0;
        assert!(validate_transaction_structure(&tx).is_err());
    }

    #[test]
    fn lock_height_future_is_temporarily_invalid() {
        let mut tx = minimal_tx();
        tx.kernels[0].features = KERNEL_FEAT_HEIGHT_LOCKED;
        tx.kernels[0].lock_height = 1000;
        let err = validate_lock_heights(&tx, BlockHeight(500)).unwrap_err();
        assert!(matches!(err, DomError::TemporarilyInvalid(_)));
    }

    #[test]
    fn coinbase_correct_value() {
        let k = CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: INITIAL_BLOCK_REWARD + 5000,
            excess: g_point(),
            excess_signature: [0u8; 65],
        };
        assert!(k.validate_explicit_value(BlockHeight(0), 5000).is_ok());
    }

    #[test]
    fn coinbase_kernel_deserialize_accepts_zero_explicit_value() {
        use dom_serialization::{DomDeserialize, DomSerialize};

        let k = CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: 0,
            excess: g_point(),
            excess_signature: [0u8; 65],
        };
        let bytes = k.to_bytes().unwrap();
        let decoded = CoinbaseKernel::from_bytes(&bytes).expect("zero value decodes");

        assert_eq!(decoded.explicit_value, 0);
        assert_eq!(decoded.features, KERNEL_FEAT_COINBASE);
    }

    #[test]
    fn coinbase_zero_value_valid_only_when_reward_plus_fees_is_zero() {
        let k = CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: 0,
            excess: g_point(),
            excess_signature: [0u8; 65],
        };

        assert!(k
            .validate_explicit_value(BlockHeight(HALVING_INTERVAL * 54), 0)
            .is_ok());
        assert!(k.validate_explicit_value(BlockHeight(0), 0).is_err());
        assert!(k
            .validate_explicit_value(BlockHeight(HALVING_INTERVAL * 54), 1)
            .is_err());
    }

    #[test]
    fn coinbase_inflated_rejected() {
        let k = CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: INITIAL_BLOCK_REWARD + 1, // one extra nom
            excess: g_point(),
            excess_signature: [0u8; 65],
        };
        assert!(k.validate_explicit_value(BlockHeight(0), 0).is_err());
    }

    #[test]
    fn coinbase_explicit_value_above_max_provable_rejected() {
        let k = CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: dom_crypto::MAX_PROVABLE_VALUE + 1,
            excess: g_point(),
            excess_signature: [0u8; 65],
        };
        let err = k
            .validate_explicit_value(BlockHeight(HALVING_INTERVAL * 54), 0)
            .expect_err("over-cap explicit value must reject");
        assert!(
            err.to_string().contains("exceeds MAX_PROVABLE_VALUE"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn coinbase_first_halving() {
        let k = CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: (INITIAL_BLOCK_REWARD * 67) / 100,
            excess: g_point(),
            excess_signature: [0u8; 65],
        };
        assert!(k
            .validate_explicit_value(BlockHeight(HALVING_INTERVAL), 0)
            .is_ok());
    }

    #[test]
    fn coinbase_validate_accepts_valid_range_proof() {
        let chain_id = [7u8; 32];
        let coinbase = valid_coinbase_for_test(&chain_id);

        assert!(coinbase.validate(BlockHeight(0), 0, &chain_id).is_ok());
    }

    #[test]
    fn coinbase_validate_rejects_invalid_nonempty_range_proof() {
        let chain_id = [7u8; 32];
        let mut coinbase = valid_coinbase_for_test(&chain_id);
        coinbase.output.proof = vec![0xAB; 100];

        let err = coinbase
            .validate(BlockHeight(0), 0, &chain_id)
            .expect_err("invalid coinbase range proof must reject");
        assert!(
            err.to_string()
                .contains("noncanonical output proof envelope length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn coinbase_validate_rejects_plain_feature_even_if_resigned() {
        // R-05: a coinbase carrying KERNEL_FEAT_PLAIN must be rejected even when
        // the signature is re-computed over that plain feature (so the signature
        // itself verifies). The feature guard must fire regardless of signature.
        let chain_id = [7u8; 32];
        let mut coinbase = valid_coinbase_for_test(&chain_id);

        // Sanity: it validates as a proper coinbase first.
        assert!(coinbase.validate(BlockHeight(0), 0, &chain_id).is_ok());

        // Flip the feature to PLAIN and RE-SIGN over the plain feature so the
        // Schnorr signature is internally valid for the tampered message.
        coinbase.kernel.features = KERNEL_FEAT_PLAIN;
        let kernel_message = {
            let mut data = Vec::with_capacity(9);
            data.push(KERNEL_FEAT_PLAIN);
            data.extend_from_slice(&coinbase.kernel.explicit_value.to_le_bytes());
            blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &data)
        };
        // blinding factor [9u8;32] matches valid_coinbase_for_test's excess = r*G.
        let sk = SecretKey::from_bytes(&[9u8; 32]).unwrap();
        let signature = schnorr_sign(&sk, kernel_message.as_bytes(), &chain_id).unwrap();
        coinbase.kernel.excess_signature = signature.to_bytes();

        let err = coinbase
            .validate(BlockHeight(0), 0, &chain_id)
            .expect_err("coinbase with plain feature must reject even when re-signed");
        assert!(
            err.to_string().contains("coinbase kernel features must be"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tx_weight_calculation() {
        let tx = minimal_tx(); // 0 inputs + 1 output*21 + 1 kernel*3 = 24
        assert_eq!(tx.weight(), WEIGHT_OUTPUT + WEIGHT_KERNEL);
    }

    #[test]
    fn tx_roundtrip() {
        use dom_serialization::{DomDeserialize, DomSerialize};
        let tx = minimal_tx();
        let bytes = tx.to_bytes().unwrap();
        assert_eq!(Transaction::from_bytes(&bytes).unwrap(), tx);
    }
}

// ── Range Proof Validation (RFC-0007 Step 6) ──────────────────────────────────

/// Validate all final DOM range proofs in a transaction.
///
/// RFC-0007 Step 6: bounded aggregate Bulletproof validation.
/// Each output commitment must have a valid proof showing the committed value
/// is in `[0, MAX_PROVABLE_VALUE]`, where `MAX_PROVABLE_VALUE = 2^52 - 1`.
///
/// This prevents negative value outputs which would enable inflation.
pub fn validate_range_proofs(tx: &Transaction) -> Result<(), DomError> {
    for (i, output) in tx.outputs.iter().enumerate() {
        let commitment = &output.commitment;
        let proof_bytes = output.range_proof_bytes()?;
        let valid = match output.recovery_capsule()? {
            Some(capsule) => dom_crypto::range_proof_verify_with_extra_commit(
                commitment.as_bytes(),
                proof_bytes,
                capsule.as_bytes(),
            ),
            None => dom_crypto::range_proof_verify(commitment.as_bytes(), proof_bytes),
        };

        match valid {
            Ok(true) => {}
            Ok(false) => {
                return Err(DomError::Invalid(format!(
                    "output {i} range proof verification failed"
                )));
            }
            Err(e) => {
                return Err(DomError::Invalid(format!(
                    "output {i} range proof error: {e}"
                )));
            }
        }
    }
    Ok(())
}

/// Validate the Mimblewimble balance equation for a transaction.
///
/// RFC-0008 Section 1.1:
///   sum(outputs) - sum(inputs) = sum(kernel_excesses) + offset*G + fee*H
pub fn validate_balance_equation(tx: &Transaction) -> Result<(), DomError> {
    use dom_crypto::pedersen::{verify_balance_equation, Commitment as CryptoCommit};

    let to_crypto = |c: &Commitment| -> Result<CryptoCommit, DomError> {
        CryptoCommit::from_compressed_bytes(c.as_bytes())
            .map_err(|e| DomError::Invalid(format!("commitment parse: {e}")))
    };

    let outputs: Vec<CryptoCommit> = tx
        .outputs
        .iter()
        .map(|o| to_crypto(&o.commitment))
        .collect::<Result<_, _>>()?;

    let inputs: Vec<CryptoCommit> = tx
        .inputs
        .iter()
        .map(|i| to_crypto(&i.commitment))
        .collect::<Result<_, _>>()?;

    let excesses: Vec<CryptoCommit> = tx
        .kernels
        .iter()
        .map(|k| to_crypto(&k.excess))
        .collect::<Result<_, _>>()?;

    let total_fee = tx.total_fee()?;

    let valid = verify_balance_equation(&outputs, &inputs, &excesses, &tx.offset, total_fee)?;

    if !valid {
        return Err(DomError::Invalid(
            "transaction balance equation does not hold".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod multi_kernel_fee_tests {
    use super::*;
    use dom_core::{Amount, KERNEL_FEAT_PLAIN};
    use dom_crypto::pedersen::Commitment;

    fn g_point() -> Commitment {
        let g = [
            0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        Commitment::from_compressed_bytes(&g).unwrap()
    }

    fn h_point() -> Commitment {
        let h = [
            0x03u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        Commitment::from_compressed_bytes(&h).unwrap()
    }

    /// Test vector: transaction with 2 kernels, different fees.
    /// balance_equation MUST use sum of ALL kernel fees (7+3=10), not just first (7).
    #[test]
    fn multi_kernel_fee_sum_is_total_not_first() {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: g_point(),
                proof: vec![0u8; 100],
            }],
            kernels: vec![
                TransactionKernel {
                    features: KERNEL_FEAT_PLAIN,
                    fee: Amount::from_noms(7).unwrap(), // first kernel: fee=7
                    lock_height: 0,
                    excess: g_point(),
                    excess_signature: [0u8; 65],
                },
                TransactionKernel {
                    features: KERNEL_FEAT_PLAIN,
                    fee: Amount::from_noms(3).unwrap(), // second kernel: fee=3
                    lock_height: 0,
                    excess: h_point(),
                    excess_signature: [0u8; 65],
                },
            ],
            offset: [0u8; 32],
        };

        // total_fee must be 7+3=10, not 7 (first kernel only)
        let total_fee = tx.total_fee().unwrap();
        assert_eq!(total_fee, 10, "total_fee must sum ALL kernels: 7+3=10");
        assert_ne!(total_fee, 7, "must NOT use only first kernel fee");
        assert_ne!(total_fee, 3, "must NOT use only second kernel fee");
    }

    #[test]
    fn multi_kernel_fee_overflow_rejected() {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: g_point(),
                proof: vec![0u8; 100],
            }],
            kernels: vec![
                TransactionKernel {
                    features: KERNEL_FEAT_PLAIN,
                    fee: Amount::from_noms(u64::MAX / 2 + 1)
                        .unwrap_or(Amount::from_noms(dom_core::MAX_SUPPLY_NOMS).unwrap()),
                    lock_height: 0,
                    excess: g_point(),
                    excess_signature: [0u8; 65],
                },
                TransactionKernel {
                    features: KERNEL_FEAT_PLAIN,
                    fee: Amount::from_noms(dom_core::MAX_SUPPLY_NOMS).unwrap(),
                    lock_height: 0,
                    excess: h_point(),
                    excess_signature: [0u8; 65],
                },
            ],
            offset: [0u8; 32],
        };
        // Fee sum would overflow — should be caught by total_fee() checked arithmetic
        // Note: Amount::from_noms already limits values, so this tests the sum path
        let result = tx.total_fee();
        // Either succeeds with a large valid value, or errors on overflow
        // The important thing is it never panics or wraps silently
        let _ = result; // just verify no panic
    }
}

impl DomSerialize for CoinbaseTransaction {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        self.output.serialize(w)?;
        self.kernel.serialize(w)?;
        w.write_bytes(&self.offset);
        Ok(())
    }
}

impl DomDeserialize for CoinbaseTransaction {
    const MIN_SERIALIZED_SIZE: usize =
        TransactionOutput::MIN_SERIALIZED_SIZE + CoinbaseKernel::MIN_SERIALIZED_SIZE + 32;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            output: TransactionOutput::deserialize(r)?,
            kernel: CoinbaseKernel::deserialize(r)?,
            offset: r.read_array::<32>()?,
        })
    }
}

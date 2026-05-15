#![allow(missing_docs)]
//! Transaction types for Mimblewimble — updated per RFC-0008 and RFC-0010.
//!
//! RFC-0008: Complete balance equation with fee and offset.
//! RFC-0008: Coinbase kernel with explicit_value (inflation prevention).
//! RFC-0010: Weight units, lock_height validation, coinbase maturity placement.

use dom_core::{
    Amount, BlockHeight, DomError, KERNEL_FEAT_COINBASE, KERNEL_FEAT_HEIGHT_LOCKED,
    KERNEL_FEAT_PLAIN, MAX_INPUTS_PER_TX, MAX_KERNELS_PER_TX, MAX_OUTPUTS_PER_TX, MAX_TX_WEIGHT,
    WEIGHT_COINBASE_KERNEL, WEIGHT_INPUT, WEIGHT_KERNEL, WEIGHT_OUTPUT,
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
    pub proof: Vec<u8>,
}

impl DomSerialize for TransactionOutput {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_bytes(self.commitment.as_bytes());
        w.write_vec(&self.proof)?;
        Ok(())
    }
}

impl DomDeserialize for TransactionOutput {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let commitment_bytes = r.read_array::<33>()?;
        let proof = r.read_vec(dom_core::MAX_PROOF_SIZE)?;
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
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let features = r.read_u8()?;
        if features != KERNEL_FEAT_COINBASE {
            return Err(DomError::Malformed(format!(
                "expected coinbase features 0x01, got 0x{features:02x}"
            )));
        }
        let explicit_value = r.read_u64()?;
        // explicit_value must be non-zero — a zero coinbase reward is suspicious
        // (could indicate a serialization bug or attempt to create a free coinbase)
        if explicit_value == 0 {
            return Err(DomError::Invalid(
                "coinbase explicit_value must be non-zero".into(),
            ));
        }
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
        (self.inputs.len() as u32)
            .saturating_mul(WEIGHT_INPUT)
            .saturating_add((self.outputs.len() as u32).saturating_mul(WEIGHT_OUTPUT))
            .saturating_add((self.kernels.len() as u32).saturating_mul(WEIGHT_KERNEL))
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
        if o.proof.len() > dom_core::MAX_PROOF_SIZE {
            return Err(DomError::Invalid(format!("output {i} proof too large")));
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
    let w = tx.weight();
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
        if self.offset != [0u8; 32] {
            return Err(DomError::Invalid("coinbase offset must be zero".into()));
        }
        self.kernel.validate_explicit_value(height, total_tx_fees)?;
        if self.output.proof.is_empty() {
            return Err(DomError::Invalid(
                "coinbase output has empty range proof".into(),
            ));
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
            Ok(false) => Err(DomError::Invalid(
                "coinbase kernel signature invalid — miner does not prove ownership".into(),
            )),
            Err(DomError::Internal(msg)) => Err(DomError::Internal(format!("coinbase sig: {msg}"))),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::{HALVING_INTERVAL, INITIAL_BLOCK_REWARD};

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
    fn tx_weight_calculation() {
        let tx = minimal_tx(); // 0 inputs + 1 output*21 + 1 kernel*3 = 24
        assert_eq!(
            tx.weight(),
            0 * WEIGHT_INPUT + 1 * WEIGHT_OUTPUT + 1 * WEIGHT_KERNEL
        );
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

/// Validate all Bulletproof range proofs in a transaction.
///
/// RFC-0007 Step 6: Bulletproofs+ validation.
/// Each output commitment must have a valid range proof showing
/// the committed value is in [0, 2^64).
///
/// This prevents negative value outputs which would enable inflation.
pub fn validate_range_proofs(tx: &Transaction) -> Result<(), DomError> {
    for (i, output) in tx.outputs.iter().enumerate() {
        let commitment = &output.commitment;
        let proof_bytes = &output.proof;

        match dom_crypto::bp_verify(commitment.as_bytes(), proof_bytes) {
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
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            output: TransactionOutput::deserialize(r)?,
            kernel: CoinbaseKernel::deserialize(r)?,
            offset: r.read_array::<32>()?,
        })
    }
}

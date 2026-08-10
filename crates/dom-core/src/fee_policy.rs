//! Final DOM transaction fee policy.
//!
//! This module is policy, not consensus. Consensus transaction structure still
//! defines the normative weight units and maximum transaction weight; relay,
//! mempool admission, block-template ordering, and Wallet V3 fee requests use
//! this checked policy layer so they cannot drift.

use crate::{
    DomError, MAX_INPUTS_PER_TX, MAX_KERNELS_PER_TX, MAX_OUTPUTS_PER_TX, MAX_TX_WEIGHT,
    MIN_RELAY_FEE_RATE, WEIGHT_INPUT, WEIGHT_KERNEL, WEIGHT_OUTPUT,
};

/// Final fee policy version frozen for Wallet V3.
pub const FEE_POLICY_VERSION: u16 = 1;

/// Smallest DOM currency unit used by transaction fees.
pub const FEE_UNIT: &str = "nom";

/// Fee-rate unit used by relay, mempool, miner ordering, and Wallet V3.
pub const FEE_RATE_UNIT: &str = "noms_per_weight_unit";

/// Static multiplier used for the initial production recommended fee.
pub const RECOMMENDED_FEE_MULTIPLIER: u64 = 2;

/// DOM does not add a separate dust floor in the frozen V3 policy.
pub const DUST_THRESHOLD_NOMS: u64 = 0;

/// Stable fee rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeRate {
    /// Noms paid per transaction weight unit.
    pub noms_per_weight_unit: u64,
}

impl FeeRate {
    /// Minimum relay and mempool admission fee rate.
    pub const fn minimum_relay() -> Self {
        Self {
            noms_per_weight_unit: MIN_RELAY_FEE_RATE,
        }
    }

    /// Recommended fee rate for Wallet V3.
    pub fn recommended() -> Result<Self, DomError> {
        let noms_per_weight_unit = MIN_RELAY_FEE_RATE
            .checked_mul(RECOMMENDED_FEE_MULTIPLIER)
            .ok_or_else(|| DomError::Internal("recommended fee rate overflow".into()))?;
        Ok(Self {
            noms_per_weight_unit,
        })
    }
}

/// Transaction shape used for policy calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionShape {
    /// Number of transaction inputs.
    pub input_count: u32,
    /// Number of transaction outputs.
    pub output_count: u32,
    /// Number of transaction kernels.
    pub kernel_count: u32,
}

impl TransactionShape {
    /// Return whether collection counts satisfy all policy limits.
    #[must_use]
    pub const fn counts_within_limits(inputs: usize, outputs: usize, kernels: usize) -> bool {
        inputs <= MAX_INPUTS_PER_TX
            && outputs <= MAX_OUTPUTS_PER_TX
            && kernels <= MAX_KERNELS_PER_TX
    }

    /// Construct a bounded shape from collection lengths.
    pub fn from_counts(inputs: usize, outputs: usize, kernels: usize) -> Result<Self, DomError> {
        if !Self::counts_within_limits(inputs, outputs, kernels) && inputs > MAX_INPUTS_PER_TX {
            return Err(DomError::Invalid(format!(
                "too many inputs for fee policy: {inputs} > {MAX_INPUTS_PER_TX}"
            )));
        }
        if !Self::counts_within_limits(inputs, outputs, kernels) && outputs > MAX_OUTPUTS_PER_TX {
            return Err(DomError::Invalid(format!(
                "too many outputs for fee policy: {outputs} > {MAX_OUTPUTS_PER_TX}"
            )));
        }
        if !Self::counts_within_limits(inputs, outputs, kernels) && kernels > MAX_KERNELS_PER_TX {
            return Err(DomError::Invalid(format!(
                "too many kernels for fee policy: {kernels} > {MAX_KERNELS_PER_TX}"
            )));
        }
        Ok(Self {
            input_count: inputs
                .try_into()
                .map_err(|_| DomError::Internal("input count conversion overflow".into()))?,
            output_count: outputs
                .try_into()
                .map_err(|_| DomError::Internal("output count conversion overflow".into()))?,
            kernel_count: kernels
                .try_into()
                .map_err(|_| DomError::Internal("kernel count conversion overflow".into()))?,
        })
    }
}

/// Checked transaction weight breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionWeight {
    /// Weight contributed by inputs.
    pub input_weight: u64,
    /// Weight contributed by outputs.
    pub output_weight: u64,
    /// Weight contributed by kernels.
    pub kernel_weight: u64,
    /// Total transaction weight.
    pub total_weight: u64,
}

/// Complete fee calculation breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBreakdown {
    /// Shape used for calculation.
    pub shape: TransactionShape,
    /// Weight breakdown.
    pub weight: TransactionWeight,
    /// Minimum relay and mempool admission fee in noms.
    pub minimum_fee_noms: u64,
    /// Recommended Wallet V3 fee in noms.
    pub recommended_fee_noms: u64,
    /// Effective minimum fee rate.
    pub minimum_fee_rate: FeeRate,
    /// Effective recommended fee rate.
    pub recommended_fee_rate: FeeRate,
    /// Policy version.
    pub policy_version: u16,
    /// Dust floor in noms.
    pub dust_threshold_noms: u64,
}

/// Compute checked transaction weight for a bounded shape.
pub fn transaction_weight(shape: TransactionShape) -> Result<TransactionWeight, DomError> {
    let input_weight = u64::from(shape.input_count)
        .checked_mul(u64::from(WEIGHT_INPUT))
        .ok_or_else(|| DomError::Internal("input weight overflow".into()))?;
    let output_weight = u64::from(shape.output_count)
        .checked_mul(u64::from(WEIGHT_OUTPUT))
        .ok_or_else(|| DomError::Internal("output weight overflow".into()))?;
    let kernel_weight = u64::from(shape.kernel_count)
        .checked_mul(u64::from(WEIGHT_KERNEL))
        .ok_or_else(|| DomError::Internal("kernel weight overflow".into()))?;
    let partial = input_weight
        .checked_add(output_weight)
        .ok_or_else(|| DomError::Internal("transaction weight overflow".into()))?;
    let total_weight = partial
        .checked_add(kernel_weight)
        .ok_or_else(|| DomError::Internal("transaction weight overflow".into()))?;
    Ok(TransactionWeight {
        input_weight,
        output_weight,
        kernel_weight,
        total_weight,
    })
}

/// Compute the minimum fee for a weight at the supplied rate.
pub fn minimum_fee_for_weight(weight: u64, fee_rate: FeeRate) -> Result<u64, DomError> {
    weight
        .checked_mul(fee_rate.noms_per_weight_unit)
        .ok_or_else(|| DomError::Internal("minimum fee overflow".into()))
}

/// Compute the complete final policy breakdown for a shape.
pub fn fee_breakdown(shape: TransactionShape) -> Result<FeeBreakdown, DomError> {
    let weight = transaction_weight(shape)?;
    let minimum_fee_rate = FeeRate::minimum_relay();
    let recommended_fee_rate = FeeRate::recommended()?;
    let minimum_fee_noms = minimum_fee_for_weight(weight.total_weight, minimum_fee_rate)?;
    let recommended_fee_noms = minimum_fee_for_weight(weight.total_weight, recommended_fee_rate)?;
    Ok(FeeBreakdown {
        shape,
        weight,
        minimum_fee_noms,
        recommended_fee_noms,
        minimum_fee_rate,
        recommended_fee_rate,
        policy_version: FEE_POLICY_VERSION,
        dust_threshold_noms: DUST_THRESHOLD_NOMS,
    })
}

/// Return the deterministic floor fee rate for an actual fee and weight.
#[allow(clippy::arithmetic_side_effects, clippy::integer_division)]
pub fn actual_fee_rate(fee_noms: u64, weight: u64) -> Result<FeeRate, DomError> {
    if weight == 0 {
        return Ok(FeeRate {
            noms_per_weight_unit: 0,
        });
    }
    Ok(FeeRate {
        noms_per_weight_unit: fee_noms / weight,
    })
}

/// Validate relay and mempool admission fee for the supplied shape.
pub fn validate_minimum_fee(
    fee_noms: u64,
    shape: TransactionShape,
) -> Result<FeeBreakdown, DomError> {
    let breakdown = fee_breakdown(shape)?;
    if fee_noms < breakdown.minimum_fee_noms {
        return Err(DomError::PolicyRejected(format!(
            "fee {} < minimum relay fee {}",
            fee_noms, breakdown.minimum_fee_noms
        )));
    }
    Ok(breakdown)
}

/// Convert the checked total weight into the legacy `u32` consensus type.
pub fn total_weight_u32(shape: TransactionShape) -> Result<u32, DomError> {
    let weight = transaction_weight(shape)?;
    if weight.total_weight > u64::from(MAX_TX_WEIGHT) {
        return Err(DomError::Invalid(format!(
            "tx weight {} > MAX_TX_WEIGHT {}",
            weight.total_weight, MAX_TX_WEIGHT
        )));
    }
    weight
        .total_weight
        .try_into()
        .map_err(|_| DomError::Internal("transaction weight conversion overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(input_count: u32, output_count: u32, kernel_count: u32) -> TransactionShape {
        TransactionShape {
            input_count,
            output_count,
            kernel_count,
        }
    }

    #[test]
    fn empty_shape_has_zero_weight_and_fee() {
        let breakdown = fee_breakdown(shape(0, 0, 0)).expect("breakdown");
        assert_eq!(breakdown.weight.total_weight, 0);
        assert_eq!(breakdown.minimum_fee_noms, 0);
        assert_eq!(breakdown.recommended_fee_noms, 0);
    }

    #[test]
    fn one_input_one_output_one_kernel_uses_consensus_weight() {
        let breakdown = fee_breakdown(shape(1, 1, 1)).expect("breakdown");
        assert_eq!(
            breakdown.weight.total_weight,
            u64::from(WEIGHT_INPUT) + u64::from(WEIGHT_OUTPUT) + u64::from(WEIGHT_KERNEL)
        );
        assert_eq!(
            breakdown.minimum_fee_noms,
            breakdown.weight.total_weight * MIN_RELAY_FEE_RATE
        );
    }

    #[test]
    fn multiple_inputs_and_outputs_are_deterministic() {
        let breakdown = fee_breakdown(shape(3, 2, 1)).expect("breakdown");
        assert_eq!(breakdown.weight.input_weight, 3);
        assert_eq!(breakdown.weight.output_weight, 42);
        assert_eq!(breakdown.weight.kernel_weight, 3);
        assert_eq!(breakdown.weight.total_weight, 48);
    }

    #[test]
    fn exact_minimum_fee_is_accepted_and_minus_one_is_rejected() {
        let shape = shape(1, 1, 1);
        let minimum = fee_breakdown(shape).expect("breakdown").minimum_fee_noms;
        assert!(validate_minimum_fee(minimum, shape).is_ok());
        assert!(matches!(
            validate_minimum_fee(minimum - 1, shape),
            Err(DomError::PolicyRejected(_))
        ));
    }

    #[test]
    fn recommended_fee_is_static_double_minimum() {
        let breakdown = fee_breakdown(shape(2, 2, 1)).expect("breakdown");
        assert_eq!(
            breakdown.recommended_fee_noms,
            breakdown.minimum_fee_noms * RECOMMENDED_FEE_MULTIPLIER
        );
    }

    #[test]
    fn actual_fee_rate_rounds_down_for_reporting() {
        let rate = actual_fee_rate(1_001, 2).expect("rate");
        assert_eq!(rate.noms_per_weight_unit, 500);
    }

    #[test]
    fn count_limits_fail_closed() {
        assert!(TransactionShape::from_counts(MAX_INPUTS_PER_TX + 1, 0, 0).is_err());
        assert!(TransactionShape::from_counts(0, MAX_OUTPUTS_PER_TX + 1, 0).is_err());
        assert!(TransactionShape::from_counts(0, 0, MAX_KERNELS_PER_TX + 1).is_err());
    }

    #[test]
    fn maximum_permitted_counts_stay_bounded() {
        let shape = TransactionShape::from_counts(
            MAX_INPUTS_PER_TX,
            MAX_OUTPUTS_PER_TX,
            MAX_KERNELS_PER_TX,
        )
        .expect("shape");
        let weight = transaction_weight(shape).expect("weight");
        assert!(weight.total_weight > u64::from(MAX_TX_WEIGHT));
    }

    #[test]
    fn multiplication_overflow_is_explicit() {
        let err = minimum_fee_for_weight(
            u64::MAX,
            FeeRate {
                noms_per_weight_unit: 2,
            },
        )
        .expect_err("overflow");
        assert!(matches!(err, DomError::Internal(_)));
    }

    #[test]
    fn deterministic_fee_vectors_repeat_fifty_times() {
        for _ in 0..50 {
            let breakdown = fee_breakdown(shape(2, 3, 1)).expect("breakdown");
            assert_eq!(breakdown.weight.total_weight, 68);
            assert_eq!(breakdown.minimum_fee_noms, 68_000);
            assert_eq!(breakdown.recommended_fee_noms, 136_000);
            assert_eq!(breakdown.policy_version, FEE_POLICY_VERSION);
            assert_eq!(breakdown.dust_threshold_noms, DUST_THRESHOLD_NOMS);
        }
    }
}

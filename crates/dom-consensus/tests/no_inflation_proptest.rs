//! No-inflation consensus invariant — property tests (dom-shield I1, Phase 8.2).
//!
//! Anchor property: **no transaction accepted by `validate_balance_equation`
//! creates value** (`Σ outputs + fee > Σ inputs`). The Mimblewimble balance
//! equation (RFC-0008) `Σout − Σin + fee·H = Σexcess + offset·G` holds *iff*
//! value is conserved (the H-component vanishes) and the blindings balance (the
//! G-component matches) — unless one can write `H` as a multiple of `G`
//! (dlog(G,H), infeasible). These tests drive thousands of randomized cases plus
//! six targeted attack vectors, each of which DOM must REJECT.
//!
//! Test-only: `validate_balance_equation` ignores range proofs and kernel
//! signatures, so outputs carry `proof: vec![]` and kernels `[0u8; 65]` sigs —
//! this isolates the balance invariant.

use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_consensus::validate_balance_equation;
use dom_core::{Amount, DomError, KERNEL_FEAT_PLAIN};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh random (valid, nonzero) blinding factor.
fn bf() -> BlindingFactor {
    BlindingFactor::random()
}

/// A random blinding factor guaranteed distinct from `other` (so a derived
/// `r_out − r_in` excess is nonzero and constructible).
fn bf_distinct(other: &BlindingFactor) -> BlindingFactor {
    loop {
        let candidate = BlindingFactor::random();
        if candidate.as_bytes() != other.as_bytes() {
            return candidate;
        }
    }
}

/// Build a transaction from raw commitments and `(fee_noms, excess)` kernels.
/// Returns `Err` if any fee is outside `Amount`'s valid range (used by the
/// overflow vector to prove graceful rejection rather than panic).
fn build_tx(
    inputs: &[Commitment],
    outputs: &[Commitment],
    kernels: &[(u64, Commitment)],
    offset: [u8; 32],
) -> Result<Transaction, DomError> {
    let mut ks = Vec::with_capacity(kernels.len());
    for (fee, excess) in kernels {
        ks.push(TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(*fee)?,
            lock_height: 0,
            excess: excess.clone(),
            excess_signature: [0u8; 65],
        });
    }
    Ok(Transaction {
        inputs: inputs
            .iter()
            .map(|c| TransactionInput {
                commitment: c.clone(),
            })
            .collect(),
        outputs: outputs
            .iter()
            .map(|c| TransactionOutput {
                commitment: c.clone(),
                proof: vec![],
            })
            .collect(),
        kernels: ks,
        offset,
    })
}

/// Honest, value-conserving 1-in/1-out tx: `v_out + fee == v_in`, single kernel
/// excess `commit(0, r_out − r_in)`, offset 0. By construction it must verify.
fn honest_1in1out(v_in: u64, fee: u64) -> (Transaction, BlindingFactor, BlindingFactor) {
    let v_out = v_in - fee;
    let r_in = bf();
    let r_out = bf_distinct(&r_in);
    let r_excess = r_out
        .sub(&r_in)
        .expect("blinding sub")
        .require_nonzero()
        .expect("nonzero excess");
    let tx = build_tx(
        &[Commitment::commit(v_in, &r_in)],
        &[Commitment::commit(v_out, &r_out)],
        &[(fee, Commitment::commit(0, &r_excess))],
        [0u8; 32],
    )
    .expect("honest fee in range");
    (tx, r_in, r_out)
}

// ---------------------------------------------------------------------------
// Randomized properties (thousands of cases)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Baseline: an honest value-conserving transaction is ACCEPTED.
    #[test]
    fn honest_balanced_tx_is_accepted(
        v_in in 1u64..1_000_000_000u64,
        fee in 0u64..1_000_000u64,
    ) {
        prop_assume!(v_in >= fee);
        let (tx, _r_in, _r_out) = honest_1in1out(v_in, fee);
        prop_assert!(validate_balance_equation(&tx).is_ok());
    }

    /// Vector (a) — inflated output: re-commit one output to `v_out + δ` (δ>0),
    /// leaving the excess and fee intact. The H-component becomes `δ·H ≠ 0`.
    #[test]
    fn inflated_output_is_rejected(
        v_in in 1u64..1_000_000_000u64,
        fee in 0u64..1_000_000u64,
        delta in 1u64..1_000_000_000u64,
    ) {
        prop_assume!(v_in >= fee);
        let v_out = v_in - fee;
        let r_in = bf();
        let r_out = bf_distinct(&r_in);
        let r_excess = r_out.sub(&r_in).unwrap().require_nonzero().unwrap();
        // Same r_out, but the committed value is inflated by delta.
        let tx = build_tx(
            &[Commitment::commit(v_in, &r_in)],
            &[Commitment::commit(v_out.wrapping_add(delta), &r_out)],
            &[(fee, Commitment::commit(0, &r_excess))],
            [0u8; 32],
        ).unwrap();
        prop_assert!(validate_balance_equation(&tx).is_err());
    }

    /// Vector (b) — broken G-component: value is conserved but the kernel excess
    /// uses a WRONG (independent random) blinding, so `Σexcess ≠ r_out − r_in`.
    #[test]
    fn broken_g_component_is_rejected(
        v_in in 1u64..1_000_000_000u64,
        fee in 0u64..1_000_000u64,
    ) {
        prop_assume!(v_in >= fee);
        let v_out = v_in - fee;
        let r_in = bf();
        let r_out = bf_distinct(&r_in);
        let wrong_excess = bf(); // unrelated to r_out - r_in
        let tx = build_tx(
            &[Commitment::commit(v_in, &r_in)],
            &[Commitment::commit(v_out, &r_out)],
            &[(fee, Commitment::commit(0, &wrong_excess))],
            [0u8; 32],
        ).unwrap();
        prop_assert!(validate_balance_equation(&tx).is_err());
    }

    /// ANCHOR PROPERTY (strongest): for arbitrary values + an arbitrary
    /// (correct-or-wrong) excess, IF the tx is accepted THEN value is conserved
    /// (`v_out + fee == v_in`). Most random combinations are rejected; the rare
    /// accepted ones MUST be balanced — a tx can never be accepted while
    /// inflating.
    #[test]
    fn anchor_accept_implies_value_conserved(
        v_in in 1u64..1_000_000_000u64,
        fee in 0u64..1_000_000u64,
        v_out in 0u64..2_000_000_000u64,
        use_correct_excess in any::<bool>(),
    ) {
        let r_in = bf();
        let r_out = bf_distinct(&r_in);
        let r_excess = r_out.sub(&r_in).unwrap().require_nonzero().unwrap();
        let excess_bf = if use_correct_excess { r_excess } else { bf() };
        let tx = build_tx(
            &[Commitment::commit(v_in, &r_in)],
            &[Commitment::commit(v_out, &r_out)],
            &[(fee, Commitment::commit(0, &excess_bf))],
            [0u8; 32],
        ).unwrap();
        if validate_balance_equation(&tx).is_ok() {
            prop_assert_eq!(
                v_out.checked_add(fee),
                Some(v_in),
                "accepted tx must conserve value (no inflation)"
            );
        }
    }

    /// Vector (f) — malicious offset: an inflated tx with an attacker-chosen
    /// `offset != 0`. The offset only shifts the G-component (`+offset·G`); an
    /// inflation lives in the H-component, so no offset can rescue it.
    #[test]
    fn malicious_offset_cannot_mask_inflation(
        v_in in 1u64..1_000_000_000u64,
        fee in 0u64..1_000_000u64,
        delta in 1u64..1_000_000u64,
        offset_seed in 1u8..=255u8,
    ) {
        prop_assume!(v_in >= fee);
        let v_out = v_in - fee;
        let r_in = bf();
        let r_out = bf_distinct(&r_in);
        let r_excess = r_out.sub(&r_in).unwrap().require_nonzero().unwrap();
        // A valid nonzero offset scalar (small, < group order) chosen by the
        // "attacker". Built in the low byte so it is always in range — `[seed; 32]`
        // would exceed the secp256k1 group order for high seeds.
        let mut offset = [0u8; 32];
        offset[31] = offset_seed;
        let tx = build_tx(
            &[Commitment::commit(v_in, &r_in)],
            &[Commitment::commit(v_out.wrapping_add(delta), &r_out)],
            &[(fee, Commitment::commit(0, &r_excess))],
            offset,
        ).unwrap();
        prop_assert!(validate_balance_equation(&tx).is_err());
    }
}

// ---------------------------------------------------------------------------
// Targeted structural attack vectors
// ---------------------------------------------------------------------------

/// Vector (c) — multi-kernel fee leak (the historical `multi_kernel_fee` bug):
/// two kernels with fees `f1, f2 (>0)`. The tx is built so it would balance ONLY
/// if the verifier used a single kernel's fee (`v_out + f1 == v_in`) — under the
/// correct `total_fee = f1 + f2` the H-component is `f2·H ≠ 0`. Must be REJECTED;
/// acceptance would mean the fee-sum leaked.
#[test]
fn multi_kernel_fee_leak_is_rejected() {
    let v_in: u64 = 1_000_000;
    let f1: u64 = 7;
    let f2: u64 = 3;
    let v_out = v_in - f1; // leak-balanced (ignores f2), NOT correct-balanced

    let r_in = bf();
    let r_out = bf_distinct(&r_in);
    // Split the correct G-component (r_out - r_in) across the two kernel excesses.
    let diff = r_out.sub(&r_in).unwrap().require_nonzero().unwrap();
    let e2 = bf_distinct(&diff);
    let e1 = diff.sub_nonzero(&e2).unwrap(); // e1 + e2 = r_out - r_in

    let tx = build_tx(
        &[Commitment::commit(v_in, &r_in)],
        &[Commitment::commit(v_out, &r_out)],
        &[
            (f1, Commitment::commit(0, &e1)),
            (f2, Commitment::commit(0, &e2)),
        ],
        [0u8; 32],
    )
    .unwrap();

    // Sanity: total_fee is the SUM, not the first kernel.
    assert_eq!(tx.total_fee().unwrap(), f1 + f2);
    assert!(
        validate_balance_equation(&tx).is_err(),
        "fee-sum must not leak: a kernel-fee-leak balance must be rejected"
    );
}

/// Vector (d) — overflow / extreme values: out-of-range fees are rejected by
/// `Amount` (no panic), extreme committed values never panic, and EC addition
/// does not wrap mod 2^64, so a "wrap-around" inflation cannot look balanced.
#[test]
fn overflow_and_extreme_values_no_panic_and_rejected() {
    // Out-of-range fee rejected gracefully (no panic).
    assert!(
        Amount::from_noms(u64::MAX).is_err(),
        "Amount must reject u64::MAX fee gracefully"
    );
    // Extreme committed value must not panic.
    let r = bf();
    let _extreme = Commitment::commit(u64::MAX, &r);

    // Claiming u64::MAX of value out of an input of 1 cannot balance — commitment
    // sums are EC points (no u64 wrap), so the H-component is enormous, not zero.
    let r_in = bf();
    let r_out = bf_distinct(&r_in);
    let r_excess = r_out.sub(&r_in).unwrap().require_nonzero().unwrap();
    let tx = build_tx(
        &[Commitment::commit(1, &r_in)],
        &[Commitment::commit(u64::MAX, &r_out)],
        &[(0, Commitment::commit(0, &r_excess))],
        [0u8; 32],
    )
    .unwrap();
    assert!(
        validate_balance_equation(&tx).is_err(),
        "wrap-around inflation must be rejected"
    );
}

/// Vector (e) — degenerate / missing excess: a value-conserving tx whose excess
/// contribution is removed (no kernels at all → `Σexcess = identity`). With
/// `r_out ≠ r_in` the G-component is nonzero, so the equation cannot close.
/// Must be REJECTED, never accepted. Also confirms the zero-blinding guard.
#[test]
fn degenerate_excess_is_rejected() {
    // The primitive guard: a zero blinding factor is rejected outright, so a
    // `commit(0, zero)` "identity-like" excess cannot even be constructed.
    assert!(BlindingFactor::from_bytes([0u8; 32]).is_err());

    let v_in: u64 = 500_000;
    let fee: u64 = 0;
    let v_out = v_in - fee; // value-conserving
    let r_in = bf();
    let r_out = bf_distinct(&r_in); // r_out != r_in => correct excess is nonzero
    let tx = build_tx(
        &[Commitment::commit(v_in, &r_in)],
        &[Commitment::commit(v_out, &r_out)],
        &[], // NO kernel excess at all (degenerate)
        [0u8; 32],
    )
    .unwrap();
    assert!(
        validate_balance_equation(&tx).is_err(),
        "value-conserving tx with no/degenerate excess must be rejected"
    );
}

//! §16.2 mandatory regression tests for the cover-lock campaign (T1).
//!
//! Master spec §16.2 requires, verbatim: "teste de regressão falha se o
//! builder descartar silenciosamente um lock já satisfeito" — a satisfied
//! non-zero lock height must never be normalized back to a PLAIN kernel by
//! any step of the slate pipeline. These tests pin that property end to end
//! (build → respond → finalize → consensus checks), plus the §16.2
//! indistinguishability requirement that the campaign introduces "nenhuma
//! diferença fora de altura, bytes criptográficos aleatórios e dados normais
//! da transação".

mod common;

use common::{make_input, TEST_CHAIN_ID};
use dom_consensus::{
    validate_balance_equation, validate_lock_heights, validate_range_proofs,
    validate_transaction_structure,
};
use dom_core::{BlockHeight, DomError, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_slate::{
    build_send_with_lock_height, finalize, respond_receive, slate_kernel_features,
    CoverLockOutcomeV1, CoverLockPolicyV1, ValidatedChainSnapshotV1,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Full round-trip with an explicit lock height, returning the finalized tx.
fn locked_roundtrip(lock_height: u64) -> dom_consensus::transaction::Transaction {
    let amount = 40_000u64;
    let fee = 500u64;
    let change = 9_500u64;
    let input = make_input(amount + fee + change, 0x11);
    let sender = build_send_with_lock_height(
        &[input],
        change,
        amount,
        fee,
        TEST_CHAIN_ID,
        lock_height,
    )
    .expect("build_send_with_lock_height");
    let response = respond_receive(sender.slate.clone(), &TEST_CHAIN_ID).expect("respond_receive");
    finalize(
        &response.slate,
        &sender.excess_blinding,
        &sender.nonce,
        &TEST_CHAIN_ID,
    )
    .expect("finalize")
}

#[test]
fn a_satisfied_lock_is_never_silently_normalized_to_plain() {
    // The wallet-side mirror first: every nonzero height maps to the
    // HEIGHT_LOCKED feature, zero to PLAIN — including the small distances of
    // the refund-overlap zone the drawn window exists to reach.
    assert_eq!(slate_kernel_features(0), KERNEL_FEAT_PLAIN);
    for height in [1u64, 2, 6, 97, 1_000_000] {
        assert_eq!(
            slate_kernel_features(height),
            KERNEL_FEAT_HEIGHT_LOCKED,
            "lock {height} must stay HEIGHT_LOCKED"
        );
    }

    // And through the whole pipeline: the finalized kernel still carries the
    // feature and the exact height — no step dropped or normalized it.
    let tx = locked_roundtrip(97);
    assert_eq!(tx.kernels.len(), 1);
    assert_eq!(tx.kernels[0].features, KERNEL_FEAT_HEIGHT_LOCKED);
    assert_eq!(tx.kernels[0].lock_height, 97);
}

#[test]
fn a_satisfied_cover_lock_is_immediately_valid_and_an_unsatisfied_one_waits() {
    let tx = locked_roundtrip(97);

    // §16.2: the cover lock is satisfied at construction, so it enters the
    // next block with no artificial wait — immediately valid at the tip it
    // was sampled from and at the exact lock height (O-03 semantics).
    assert!(validate_lock_heights(&tx, BlockHeight(100)).is_ok());
    assert!(validate_lock_heights(&tx, BlockHeight(97)).is_ok());

    // Below the lock the consensus answer is TemporarilyInvalid — the
    // no-reputation-punishment rejection O-03 proved — never a hard reject.
    assert!(matches!(
        validate_lock_heights(&tx, BlockHeight(96)),
        Err(DomError::TemporarilyInvalid(_))
    ));
}

#[test]
fn a_cover_locked_transaction_passes_the_same_structural_checks_as_plain() {
    // §16.2: the campaign introduces no difference beyond the height field —
    // the HEIGHT_LOCKED transaction crosses the exact same structure, range
    // proof, and balance validators an ordinary PLAIN transfer crosses.
    let tx = locked_roundtrip(42);
    validate_transaction_structure(&tx).expect("structure");
    validate_range_proofs(&tx).expect("range proofs");
    validate_balance_equation(&tx).expect("balance");
}

#[test]
fn the_policy_drawn_height_flows_into_a_valid_height_locked_transaction() {
    // Integration of the §16.2 skeleton: sample_satisfied_height at the
    // validated tip → build_send_with_lock_height → finalized kernel carries
    // the drawn height and is immediately valid at that tip.
    let mut rng = StdRng::seed_from_u64(0x5343_4f56_4552_0002);
    let policy = CoverLockPolicyV1::new(6, 1000).expect("policy");
    let tip = 100u64;
    let snapshot = ValidatedChainSnapshotV1::from_validated_height(tip);

    let lock_height = match policy
        .cover_lock_for_send(&snapshot, &mut rng)
        .expect("cover draw")
    {
        CoverLockOutcomeV1::Cover(height) => height,
        CoverLockOutcomeV1::NotSelected => unreachable!("R3 policy always selects"),
    };
    assert!((1..=tip).contains(&lock_height));
    assert!(tip - lock_height <= 6, "inside the frozen public window");

    let tx = locked_roundtrip(lock_height);
    assert_eq!(tx.kernels[0].features, KERNEL_FEAT_HEIGHT_LOCKED);
    assert_eq!(tx.kernels[0].lock_height, lock_height);
    assert!(validate_lock_heights(&tx, BlockHeight(tip)).is_ok());
}

//! Regression guard for the role byte space.
//!
//! Started life as a probe demonstrating that `ROLE_SOLANA_CONDITION_LOCK`
//! collided with `ROLE_XMR_REFUND_SHARE` (both were byte 2): an XMR refund
//! proof verified unchanged as a Solana condition-lock proof. The registry in
//! `xmr-dleq-sigma` now owns the space and the Solana role is byte 3, so this
//! file asserts the opposite of what it was born proving.

use solana_route_secret::ROLE_SOLANA_CONDITION_LOCK;
use xmr_dleq_sigma::{verify_bound, ROLES_V1, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND};
use xmr_refund_adaptor::XmrRefundSecret;

#[test]
fn every_role_is_distinct() {
    assert_ne!(ROLE_SOLANA_CONDITION_LOCK, ROLE_XMR_REFUND_SHARE);
    assert_ne!(ROLE_SOLANA_CONDITION_LOCK, ROLE_XMR_SHARED_SPEND);
    assert!(ROLES_V1
        .iter()
        .any(|(byte, _)| *byte == ROLE_SOLANA_CONDITION_LOCK));
}

#[test]
fn an_xmr_refund_proof_no_longer_verifies_as_a_solana_condition_lock() {
    let mut rng = rand::thread_rng();
    let settlement = [0x11; 32];
    let context = [0x22; 32];

    // Minted for the XMR refund path, and for nothing else.
    let refund =
        XmrRefundSecret::generate(settlement, context, &mut rng).expect("refund secret generates");

    // Presented to the Solana leg's verifier, unmodified: refused.
    assert!(
        solana_route_secret::verify_counterparty_bundle(refund.proof(), &settlement, &context,)
            .is_err()
    );
    assert!(verify_bound(
        refund.proof(),
        &settlement,
        &context,
        ROLE_SOLANA_CONDITION_LOCK
    )
    .is_err());

    // And the refund path itself still verifies, so the separation is the
    // role byte and nothing else.
    assert!(verify_bound(refund.proof(), &settlement, &context, ROLE_XMR_REFUND_SHARE).is_ok());
}

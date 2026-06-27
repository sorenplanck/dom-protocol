//! proptest-invariante — properties that must hold for ALL valid slate
//! parameterizations the API accepts.
//!
//! INV-1 (signature soundness round-trip): for any (amount, fee, change) within
//! limits, a full build->respond->finalize produces a transaction whose kernel
//! aggregate signature re-verifies against the recomputed aggregate excess and
//! kernel message. (Finalize already verifies internally; this asserts the
//! verification is reproducible by a third party from the public tx alone.)
//!
//! INV-2 (output ordering determinism): `slate_outputs` always emits change
//! before recipient, and the count is exactly `has_change as usize + 1`, with no
//! dependence on map/set iteration order.

mod common;

use dom_crypto::pedersen::Commitment;
use dom_crypto::{schnorr_verify, PublicKey, SchnorrSignature};
use dom_slate::{plain_kernel_message, respond_receive, slate_outputs};
use dom_tx::slate::OutputCommitmentAndProof;
use proptest::prelude::*;

proptest! {
    // Keep cases modest: each one runs real Bulletproof prove + Schnorr.
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn finalized_kernel_signature_independently_reverifies(
        amount in 1u64..1_000_000,
        fee in 0u64..10_000,
        change in 0u64..1_000_000,
    ) {
        let tx = common::full_roundtrip(amount, fee, change);
        prop_assert_eq!(tx.kernels.len(), 1);
        let kernel = &tx.kernels[0];

        // Reconstruct the verifier's view purely from the public transaction.
        let agg_p = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())
            .expect("kernel excess is a valid public key");
        let sig = SchnorrSignature::from_bytes(&kernel.excess_signature)
            .expect("kernel signature parses");
        let msg = plain_kernel_message(kernel.fee.noms(), kernel.lock_height)
            .expect("kernel message");

        let ok = schnorr_verify(&sig, &agg_p, &common::TEST_CHAIN_ID, msg.as_bytes())
            .expect("verify ran");
        prop_assert!(ok, "finalized kernel signature failed independent re-verification");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn output_ordering_is_deterministic_change_first(
        amount in 1u64..1_000_000,
        fee in 0u64..10_000,
        change in 0u64..1_000_000,
    ) {
        let sender = common::build_balanced_send(amount, fee, change);
        let answered = respond_receive(sender.slate.clone(), &common::TEST_CHAIN_ID)
            .expect("respond");
        let recipient_output: OutputCommitmentAndProof =
            answered.slate.recipient_output.clone().expect("recipient output");

        // Build outputs twice; the order and contents must be identical.
        let a = slate_outputs(&answered.slate, recipient_output.clone());
        let b = slate_outputs(&answered.slate, recipient_output.clone());
        prop_assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            prop_assert_eq!(x.commitment.as_bytes(), y.commitment.as_bytes());
            prop_assert_eq!(&x.proof, &y.proof);
        }

        let has_change = answered.slate.sender_change_output.is_some();
        prop_assert_eq!(a.len(), usize::from(has_change) + 1);

        if has_change {
            // First output MUST be the change commitment, last MUST be recipient.
            let change_commitment: &Commitment =
                &answered.slate.sender_change_output.as_ref().unwrap().commitment;
            prop_assert_eq!(a[0].commitment.as_bytes(), change_commitment.as_bytes());
            prop_assert_eq!(
                a[1].commitment.as_bytes(),
                recipient_output.commitment.as_bytes()
            );
        } else {
            prop_assert_eq!(
                a[0].commitment.as_bytes(),
                recipient_output.commitment.as_bytes()
            );
        }
    }
}

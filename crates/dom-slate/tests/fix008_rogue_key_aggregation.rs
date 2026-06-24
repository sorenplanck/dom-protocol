//! FIX-008 reproducer (mirrored into dom-slate) — rogue-key / key-cancellation
//! in the slate excess aggregation.
//!
//! `respond_receive` and `finalize` aggregate the two participants' public
//! excess keys with PLAIN point addition (`schnorr_add_public_keys`,
//! crates/dom-slate/src/lib.rs:267 and :336) — there is NO MuSig key-aggregation
//! coefficient `a_i = H(L, P_i)`. Plain key addition is the classic setting for
//! the rogue-key attack: a malicious participant who sees the other party's
//! public key `P_S` first can choose its own key so the aggregate collapses to a
//! key it fully controls (or to identity).
//!
//! This probe drives the most extreme variant — full CANCELLATION: the attacker
//! sets `P_R = -P_S`, so `agg_p = P_S + P_R = O` (point at infinity). We assert
//! the DEFENSE: the aggregation primitive that finalize relies on must REJECT
//! the identity aggregate. `schnorr_add_public_keys` checks `is_identity` and
//! errors (crates/dom-crypto/src/schnorr.rs:170), so this specific cancellation
//! is caught.
//!
//! NOTE — anti-theater scope: this probe proves only that the *identity*
//! aggregate is rejected. It does NOT prove the slate is free of all rogue-key
//! variants: a key-cancellation that leaves `agg_p != O` (e.g. attacker targets
//! `agg_p = P_attacker` rather than identity) is NOT exercised here, because
//! mounting it requires forging the counterparty's partial signature, which the
//! per-key challenge in `schnorr_partial_sign`/`schnorr_verify`
//! (challenge over `agg_p`) is what would have to be broken. The absence of a
//! key-agg coefficient remains a design observation for human review; this test
//! confirms the one cancellation the code does defend against.

mod common;

use dom_crypto::PublicKey;
use dom_slate::{finalize, respond_receive};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::Group;
use k256::{EncodedPoint, ProjectivePoint};

/// Negate a compressed secp256k1 public key, returning the compressed bytes of
/// `-P`. Computable from the public key ALONE (no secret) — exactly the
/// attacker's capability in a rogue-key attack.
fn negate_public_key(pk: &PublicKey) -> [u8; 33] {
    let bytes = pk.to_compressed_bytes();
    let encoded = EncodedPoint::from_bytes(bytes).expect("valid encoded point");
    let point = ProjectivePoint::from_encoded_point(&encoded).unwrap();
    let neg = -point;
    let neg_bytes = neg.to_affine().to_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(&neg_bytes);
    out
}

#[test]
fn finalize_rejects_recipient_excess_cancelling_sender_excess() {
    // 1. Real sender build.
    let sender = common::build_balanced_send(1_000, 10, 500);

    // 2. Honest recipient response, so all other fields are well-formed.
    let response =
        respond_receive(sender.slate.clone(), &common::TEST_CHAIN_ID).expect("respond_receive");
    let mut slate = response.slate;

    // 3. ATTACK: replace the recipient public excess with -P_sender so the
    //    aggregate excess P_S + P_R collapses to the point at infinity.
    let neg_sender_excess = negate_public_key(&slate.sender_public_excess);
    let rogue_excess =
        PublicKey::from_compressed_bytes(&neg_sender_excess).expect("negated key parses");

    // Sanity: the sum really is identity (so the test exercises cancellation).
    let p_s = ProjectivePoint::from_encoded_point(
        &EncodedPoint::from_bytes(slate.sender_public_excess.to_compressed_bytes()).unwrap(),
    )
    .unwrap();
    let p_r = ProjectivePoint::from_encoded_point(
        &EncodedPoint::from_bytes(rogue_excess.to_compressed_bytes()).unwrap(),
    )
    .unwrap();
    assert!(
        bool::from((p_s + p_r).is_identity()),
        "test precondition: P_S + P_R must be the identity point"
    );

    slate.recipient_public_excess = Some(rogue_excess);

    // 4. Finalize must REJECT (aggregate excess is the point at infinity).
    let result = finalize(
        &slate,
        &sender.excess_blinding,
        &sender.nonce,
        &common::TEST_CHAIN_ID,
    );

    assert!(
        result.is_err(),
        "FIX-008 (cancellation->identity) CONFIRMED: finalize accepted an \
         aggregate excess of the point at infinity. result={result:?}"
    );
}

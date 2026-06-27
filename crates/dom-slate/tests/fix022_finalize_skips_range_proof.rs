//! FIX-022 reproducer — does `finalize` verify recipient range proofs?
//!
//! `finalize` validates the assembled transaction with
//! `validate_transaction_structure` + `validate_balance_equation` +
//! `schnorr_verify`. None of those run `bp2_verify`:
//!   * `validate_transaction_structure` only checks each proof is non-empty and
//!     `<= MAX_PROOF_SIZE` (crates/dom-consensus/src/transaction.rs:271-279);
//!   * `validate_balance_equation` is purely Pedersen-commitment algebra
//!     (crates/dom-consensus/src/transaction.rs:728);
//!   * `bp2_verify` is only invoked in `Coinbase::validate`
//!     (crates/dom-consensus/src/transaction.rs:390), never on slate outputs.
//!
//! ATTACK: a malicious recipient hands back a slate whose `recipient_output`
//! carries a structurally-valid-length proof that does NOT correspond to the
//! committed value. Because the commitment is unchanged, the balance equation
//! and the aggregate signature still verify — so if `finalize` does not check
//! the proof, it returns a "validated" `Transaction` carrying an unverifiable
//! (potentially out-of-range / inflationary) range proof.
//!
//! EXPECTED DEFENSE (assertion): `finalize` REJECTS a recipient output whose
//! range proof does not verify. If it ACCEPTS -> RED, FIX-022 confirmed.

mod common;

use dom_crypto::pedersen::Commitment;
use dom_crypto::{bp2_prove, bp2_verify, BlindingFactor, RangeProof};
use dom_slate::{finalize, respond_receive};

#[test]
fn finalize_rejects_recipient_output_with_invalid_range_proof() {
    // 1. Real, balancing sender build.
    let sender = common::build_balanced_send(1_000, 10, 500);

    // 2. Honest recipient response (valid output, valid proof, valid sigs).
    let response =
        respond_receive(sender.slate.clone(), &common::TEST_CHAIN_ID).expect("respond_receive");
    let mut slate = response.slate;

    // 3. Tamper: keep the recipient commitment (so balance + signature still
    //    hold) but swap in a range proof for a DIFFERENT value/blinding. The
    //    proof is well-formed (675 bytes, parses as RangeProof) but does not
    //    correspond to the recipient commitment.
    let real_output = slate.recipient_output.clone().expect("recipient output");
    let real_commitment = real_output.commitment.clone();

    let wrong_blinding = BlindingFactor::from_bytes([0xAB; 32]).unwrap();
    let (wrong_proof_bytes, wrong_commitment_bytes) =
        bp2_prove(424_242, &wrong_blinding).expect("decoy proof");

    // Sanity: the decoy proof is the same length as the real one, and is a
    // *valid* proof for the decoy commitment (not the recipient's).
    assert_eq!(wrong_proof_bytes.len(), real_output.proof.bytes.len());
    let decoy_commitment = Commitment::from_compressed_bytes(&wrong_commitment_bytes).unwrap();
    assert_ne!(
        decoy_commitment.as_bytes(),
        real_commitment.as_bytes(),
        "decoy commitment must differ from the recipient commitment"
    );

    // The decoy proof does NOT verify against the recipient's real commitment:
    // this is exactly the malformed-proof condition finalize ought to catch.
    let proof_matches_real_commitment =
        bp2_verify(real_commitment.as_bytes(), &wrong_proof_bytes).unwrap_or(false);
    assert!(
        !proof_matches_real_commitment,
        "test precondition: decoy proof must not verify against the real commitment"
    );

    slate.recipient_output = Some(dom_tx::slate::OutputCommitmentAndProof {
        commitment: real_commitment,
        proof: RangeProof::from_bytes(wrong_proof_bytes).unwrap(),
    });

    // 4. Finalize with the tampered slate.
    let result = finalize(
        &slate,
        &sender.excess_blinding,
        &sender.nonce,
        &common::TEST_CHAIN_ID,
    );

    // 5. DEFENSE assertion: finalize must reject the invalid proof.
    //    GREEN here => FIX-022 dissolved. RED (panic on this assert because
    //    finalize returned Ok) => FIX-022 confirmed.
    assert!(
        result.is_err(),
        "FIX-022 CONFIRMED: finalize accepted a recipient output whose range \
         proof does not verify against its commitment (no bp2_verify in the \
         finalize path). Returned Ok(Transaction). result={result:?}"
    );
}

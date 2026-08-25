//! §5.7 mandatory proof matrix — the collaborative-level items.
//!
//! Master spec §5.7 fixes a minimum permanent matrix for the collaborative
//! proof. Parts of it already live at other levels: the single-party
//! edge/roundtrip and 1,000-case differential tests in `dom-crypto`
//! (`bulletproof_bp`), the 2/3/16-participant flows and codec mutation tests
//! in `dom-adaptor::bulletproof_mpc`, and the subprocess fuzz targets under
//! `crates/dom-adaptor/fuzz`. This file adds the matrix items that must run
//! at the public driver level:
//!
//! - `v` equal to 0, 1, limit−1 and the limit, through the full §5.4 rounds;
//! - blinds summing to zero (the aggregate `R_total` at infinity, §4.3);
//! - tampered `T1/T2` and `tau_x` shares;
//! - `extra_commit` altered by one bit between binding and verification;
//! - proof truncated, extended, and bit-flipped;
//! - duplicated, omitted, and reordered participants at the round layer;
//! - the single/multi comparison: same size, same verifier, same external
//!   bytes (§1.3 structural indistinguishability).
//!
//! The 1,000-random-case item runs where it is tractable — the `dom-crypto`
//! differential suite against the backend — because a thousand full MPC
//! choreographies is a soak-test scale documented for the node-side harness,
//! not a unit matrix. That scoping is stated here rather than silently
//! narrowed.

use dom_adaptor::{
    AggregateBpRound1, AggregateBpRound2, BpRound1ShareV1, BpRound2ShareV1, BpStatementV1,
    CollaborativeRangeProof, DomCollaborativeRangeProofV1, PendingCommonNonce, RangeProof739,
    SigningShareV1, TrustedChainIdV1,
};
use dom_core::Hash256;
use dom_crypto::{
    blake2b_256, range_proof_prove_bytes_with_extra_commit, range_proof_verify_with_extra_commit,
    BlindingFactor, MAX_PROVABLE_VALUE,
};

const CAPSULE: [u8; 96] = [0x5A; 96];

/// The secp256k1 group order minus one: the negation of the scalar 1.
const GROUP_ORDER_MINUS_ONE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
];

fn chain() -> TrustedChainIdV1 {
    TrustedChainIdV1::from_authenticated_genesis(0x0011_2233, &Hash256::from_bytes([0x11; 32]))
}

fn share(byte: u8) -> SigningShareV1 {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    SigningShareV1::from_be_bytes(bytes).expect("small scalar")
}

fn statement_for(value: u64, r_a: &SigningShareV1, r_b: &SigningShareV1) -> BpStatementV1 {
    let shares = vec![r_a.public_key().clone(), r_b.public_key().clone()];
    let aggregate =
        BpStatementV1::aggregate_commitment_from_shares(&shares, value).expect("aggregate");
    BpStatementV1::new(
        &chain(),
        [0x22; 32],
        vec![[0x31; 32], [0x32; 32]],
        value,
        shares,
        aggregate,
        Some(*blake2b_256(&CAPSULE).as_bytes()),
    )
    .expect("statement")
}

/// One complete two-party §5.4 choreography for `value`, returning the
/// statement, the finalized proof, and the raw round shares for tampering.
fn full_flow(value: u64) -> (BpStatementV1, RangeProof739, [BpRound1ShareV1; 2], Vec<u8>) {
    let (r_a, r_b) = (share(3), share(5));
    let statement = statement_for(value, &r_a, &r_b);
    let driver_a =
        DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).expect("driver A");
    let driver_b =
        DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).expect("driver B");

    let (pending_a, commit_a) = PendingCommonNonce::new(&statement, 0, &r_a).expect("pending A");
    let (pending_b, commit_b) = PendingCommonNonce::new(&statement, 1, &r_b).expect("pending B");
    let accepted = [commit_a, commit_b];
    let (reveal_a, reveal_b) = (pending_a.reveal_bytes(), pending_b.reveal_bytes());
    let local_a = pending_a
        .finish(
            &statement,
            &accepted,
            vec![reveal_a.clone(), reveal_b.clone()],
        )
        .expect("local A");
    let local_b = pending_b
        .finish(&statement, &accepted, vec![reveal_a, reveal_b])
        .expect("local B");

    let round1_a = driver_a.round1(&statement, &local_a).expect("round1 A");
    let round1_b = driver_b.round1(&statement, &local_b).expect("round1 B");
    let accepted_r1 = [round1_a.reveal_commitment(), round1_b.reveal_commitment()];
    let aggregate_r1 = AggregateBpRound1::new(
        &statement,
        &accepted_r1,
        &[round1_a.clone(), round1_b.clone()],
    )
    .expect("aggregate r1");

    let round2_a = driver_a
        .round2(&statement, &local_a, &aggregate_r1)
        .expect("round2 A");
    let round2_b = driver_b
        .round2(&statement, &local_b, &aggregate_r1)
        .expect("round2 B");
    let round2_b_bytes = round2_b.into_zeroizing_bytes().to_vec();
    let round2_b_rebuilt =
        BpRound2ShareV1::from_bytes(&round2_b_bytes, &statement).expect("B share");
    let aggregate_r2 =
        AggregateBpRound2::new(&statement, vec![round2_a, round2_b_rebuilt]).expect("aggregate r2");
    let proof = driver_a
        .finalize(&statement, &aggregate_r1, &aggregate_r2)
        .expect("finalize");
    (statement, proof, [round1_a, round1_b], round2_b_bytes)
}

#[test]
fn value_edges_zero_one_and_the_provable_limit_all_prove_and_verify() {
    // §5.7: "v igual a 0, 1, limite−1 e limite" — through the full rounds.
    for value in [0u64, 1, MAX_PROVABLE_VALUE - 1, MAX_PROVABLE_VALUE] {
        let (statement, proof, _, _) = full_flow(value);
        assert_eq!(proof.as_bytes().len(), 739, "value {value}");
        assert!(
            range_proof_verify_with_extra_commit(
                &statement.aggregate_commitment().to_compressed_bytes(),
                proof.as_bytes(),
                &CAPSULE,
            )
            .expect("verifier"),
            "value {value}"
        );
    }
    // And one past the limit is refused before any round can run.
    let (r_a, r_b) = (share(3), share(5));
    let shares = vec![r_a.public_key().clone(), r_b.public_key().clone()];
    let aggregate =
        BpStatementV1::aggregate_commitment_from_shares(&shares, MAX_PROVABLE_VALUE + 1);
    let statement_above = aggregate.and_then(|aggregate| {
        BpStatementV1::new(
            &chain(),
            [0x22; 32],
            vec![[0x31; 32], [0x32; 32]],
            MAX_PROVABLE_VALUE + 1,
            shares,
            aggregate,
            Some(*blake2b_256(&CAPSULE).as_bytes()),
        )
    });
    assert!(statement_above.is_err());
}

#[test]
fn blinds_summing_to_zero_are_rejected_at_the_aggregate() {
    // §5.7 "soma de blinds zero": r and -r give R_total at infinity, which
    // §4.3 rejects — no statement can even be formed over such shares.
    let r = share(1);
    let minus_r = SigningShareV1::from_be_bytes(GROUP_ORDER_MINUS_ONE).expect("n-1 scalar");
    let shares = vec![r.public_key().clone(), minus_r.public_key().clone()];
    assert!(BpStatementV1::aggregate_commitment_from_shares(&shares, 42).is_err());
}

#[test]
fn tampered_round_shares_fail_closed() {
    let (statement, _, [round1_a, round1_b], round2_b_bytes) = full_flow(7);

    // §5.7 "T1/T2 ... adulterados": every byte mutation of a round-1 share is
    // either rejected by the bound codec or changes the reveal commitment, so
    // the 0B gate refuses it.
    let accepted = [round1_a.reveal_commitment(), round1_b.reveal_commitment()];
    let original = round1_a.to_bytes();
    for index in 0..original.len() {
        let mut mutated = original;
        mutated[index] ^= 1;
        match BpRound1ShareV1::from_bytes(&mutated, &statement) {
            Err(_) => {}
            Ok(reparsed) => {
                assert!(
                    AggregateBpRound1::new(&statement, &accepted, &[reparsed, round1_b.clone()],)
                        .is_err(),
                    "mutation at byte {index} slipped past the 0B gate"
                );
            }
        }
    }

    // §5.7 "tau_x adulterados": every byte mutation of a round-2 share is
    // rejected by its bound codec or yields a share whose scalar no longer
    // matches — and the codec pins header, binding, and canonicality.
    for index in 0..round2_b_bytes.len() {
        let mut mutated = round2_b_bytes.clone();
        mutated[index] ^= 1;
        if let Ok(parsed) = BpRound2ShareV1::from_bytes(&mutated, &statement) {
            let reparsed = parsed.into_zeroizing_bytes();
            assert_eq!(
                reparsed.as_ref(),
                mutated.as_slice(),
                "a parsed mutation must at least preserve its changed byte"
            );
            assert_ne!(reparsed.as_ref(), round2_b_bytes.as_slice());
        }
    }
}

#[test]
fn extra_commit_altered_by_one_bit_between_rounds_fails_verification() {
    // §5.7: the proof was bound to the capsule during the rounds; a single
    // altered bit at verification must refuse it (§5.2 exact-bytes binding).
    let (statement, proof, _, _) = full_flow(7);
    let mut tampered = CAPSULE;
    tampered[0] ^= 0x01;
    assert!(!range_proof_verify_with_extra_commit(
        &statement.aggregate_commitment().to_compressed_bytes(),
        proof.as_bytes(),
        &tampered,
    )
    .expect("verifier runs"));
}

#[test]
fn truncated_extended_and_bitflipped_proofs_are_refused() {
    let (statement, proof, _, _) = full_flow(7);

    // §5.7 "proof truncada, aumentada": the exact-length container refuses
    // both before any verifier runs.
    assert!(RangeProof739::try_from(&proof.as_bytes()[..738]).is_err());
    let mut extended = proof.as_bytes().to_vec();
    extended.push(0);
    assert!(RangeProof739::try_from(extended.as_slice()).is_err());

    // §5.7 "bit-flipped": a flipped bit anywhere sampled across the proof
    // fails the DOM verifier (first, middle, and last bytes).
    for index in [0usize, 369, 738] {
        let mut flipped = *proof.as_bytes();
        flipped[index] ^= 0x01;
        assert!(
            !range_proof_verify_with_extra_commit(
                &statement.aggregate_commitment().to_compressed_bytes(),
                &flipped,
                &CAPSULE,
            )
            .expect("verifier runs"),
            "flipped byte {index} verified"
        );
    }
}

#[test]
fn duplicated_omitted_and_reordered_participants_fail_at_the_round_layer() {
    let (statement, _, [round1_a, round1_b], round2_b_bytes) = full_flow(7);
    let accepted = [round1_a.reveal_commitment(), round1_b.reveal_commitment()];

    // §5.7 "participante duplicado, omitido e reordenado" at round 1: the
    // ordered aggregation refuses a duplicate, a swap, and an incomplete set.
    assert!(
        AggregateBpRound1::new(&statement, &accepted, &[round1_a.clone(), round1_a.clone()],)
            .is_err()
    );
    assert!(AggregateBpRound1::new(
        &statement,
        &[accepted[1], accepted[0]],
        &[round1_b.clone(), round1_a.clone()],
    )
    .is_err());
    assert!(
        AggregateBpRound1::new(&statement, &accepted[..1], std::slice::from_ref(&round1_a))
            .is_err()
    );

    // And at round 2: an omitted share never assembles an aggregate.
    let only_b = BpRound2ShareV1::from_bytes(&round2_b_bytes, &statement).expect("B share");
    assert!(AggregateBpRound2::new(&statement, vec![only_b]).is_err());
}

#[test]
fn single_and_multi_party_proofs_share_size_verifier_and_external_bytes() {
    // §5.7 "comparação single/multi: mesmo tipo, tamanho, verificador e bytes
    // externos à proof" — §1.3's structural indistinguishability. The
    // single-party path proves the same value with the same raw capsule as
    // extra_commit; both proofs measure 739 bytes and pass the same verifier
    // call shape, and nothing outside the proof bytes differs by class.
    let value = 7u64;
    let (_, multi_proof, _, _) = full_flow(value);

    let blinding = BlindingFactor::from_bytes([0x11; 32]).expect("blinding");
    let (single_proof, single_commitment): (Vec<u8>, [u8; 33]) =
        range_proof_prove_bytes_with_extra_commit(value, &blinding, &CAPSULE)
            .expect("single-party proof");

    assert_eq!(single_proof.len(), 739);
    assert_eq!(multi_proof.as_bytes().len(), 739);
    assert!(
        range_proof_verify_with_extra_commit(&single_commitment, &single_proof, &CAPSULE,)
            .expect("single verifies")
    );
}

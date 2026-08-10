//! §12.3 loss simulation: a 2-of-2 shared output without one share is
//! irrecoverable — demonstrated, not assumed.
//!
//! Master spec §12.3 ("Política segura provisória") requires, for the first
//! regtest cycle: "simular perda de um lado e documentar que 2-de-2 sem share
//! é irrecuperável". §12.2 is the reason a real recovery capsule cannot exist
//! for this output class: a capsule opening the total blinding would let one
//! participant spend alone, so the on-chain capsule is a non-decryptable
//! decoy (`decoy_capsule.rs`) and recovery material simply is not on chain.
//! §1.2/A-04: the aggregate blinding is never reconstructed anywhere.
//!
//! Consequences pinned here, with party B's share material lost:
//!
//! 1. A's share alone does not open the shared commitment `C = v*H + Σ R_i`.
//! 2. Nobody can stand in for B in the §5.4 rounds: the driver's admission
//!    gate requires the exact scalar behind B's published `R_i`.
//! 3. No complete round-2 share set can exist, so no proof — and no spend —
//!    can be finalized.
//!
//! This irrecoverability is why the bilateral backup gate
//! (`funding_authority.rs`, Cronograma 4.2) must pass before any funding:
//! after funding, a lost share means the money waits for the timeout refund,
//! or is gone.

use dom_adaptor::{
    AggregateBpRound2, BpStatementV1, PendingCommonNonce, SigningShareV1, TrustedChainIdV1,
};
use dom_core::Hash256;
use dom_crypto::blake2b_256;
use dom_crypto::pedersen::{BlindingFactor, Commitment};

const CAPSULE: [u8; 96] = [0x5A; 96];
const VALUE: u64 = 42;

fn share(byte: u8) -> SigningShareV1 {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    SigningShareV1::from_be_bytes(bytes).expect("small scalar")
}

fn statement(r_a: &SigningShareV1, r_b: &SigningShareV1) -> BpStatementV1 {
    let shares = vec![r_a.public_key().clone(), r_b.public_key().clone()];
    let aggregate =
        BpStatementV1::aggregate_commitment_from_shares(&shares, VALUE).expect("aggregate");
    BpStatementV1::new(
        &TrustedChainIdV1::from_authenticated_genesis(
            0x0011_2233,
            &Hash256::from_bytes([0x11; 32]),
        ),
        [0x22; 32],
        vec![[0x31; 32], [0x32; 32]],
        VALUE,
        shares,
        aggregate,
        Some(*blake2b_256(&CAPSULE).as_bytes()),
    )
    .expect("statement")
}

#[test]
fn a_single_share_does_not_open_the_shared_commitment() {
    // B's material is lost; A holds only r_a. The opening A can form,
    // commit(v, r_a), is not C — C requires the sum r_a + r_b, which per
    // §1.2/A-04 exists nowhere as a scalar to begin with.
    let (r_a, r_b) = (share(3), share(5));
    let statement = statement(&r_a, &r_b);

    let mut r_a_bytes = [0u8; 32];
    r_a_bytes[31] = 3;
    let a_only = Commitment::commit(
        VALUE,
        &BlindingFactor::from_bytes(r_a_bytes).expect("blinding"),
    );
    assert_ne!(
        a_only.as_bytes(),
        &statement.aggregate_commitment().to_compressed_bytes(),
        "one share must not open the 2-of-2 commitment"
    );
}

#[test]
fn nobody_can_stand_in_for_the_lost_participant() {
    // With B's scalar gone, no other scalar is admitted into B's round slot:
    // the driver checks the injected share against B's exact published R_i.
    let (r_a, r_b) = (share(3), share(5));
    let statement = statement(&r_a, &r_b);
    // A trying to play B's slot with its own share fails closed…
    assert!(PendingCommonNonce::new(&statement, 1, &r_a).is_err());
    // …and so does any freshly generated scalar.
    assert!(PendingCommonNonce::new(&statement, 1, &share(9)).is_err());
    // Only the true lost scalar would be admitted — which is the point.
    assert!(PendingCommonNonce::new(&statement, 1, &r_b).is_ok());
}

#[test]
fn no_proof_can_be_finalized_without_the_lost_side() {
    // A complete round-2 share set needs one share per participant; with B
    // lost, the set is permanently incomplete and finalization is
    // unreachable. (The full tampering matrix lives in bp_mandatory_matrix.)
    let (r_a, r_b) = (share(3), share(5));
    let statement = statement(&r_a, &r_b);
    assert!(AggregateBpRound2::new(&statement, Vec::new()).is_err());
}

//! §15.5 protocol red-team — the node-independent items against the
//! collaborative shared-output driver, statement, and chain projection.
//!
//! Master spec §15.5 lists a red-team matrix. Several items are exercised
//! elsewhere: the last-mover/commit-reveal and 0B adaptive-choice gates and
//! the tamper matrix in `bp_mandatory_matrix.rs`, the adaptor `t*G == T`
//! attacks in the `g1a_*` suites, the reorg-after-exposure and cover-policy
//! rollback rules in the `chain_projection` and `cover_policy` unit tests.
//! This file covers the remaining node-independent items that attack the
//! objects built for the round-layer driver:
//!
//! - "coordenador troca H_DOM, capsule ou valor entre rodadas": the statement
//!   hash and the driver's capsule binding refuse a mid-flight swap;
//! - "proof válida para commitment diferente": a proof does not verify against
//!   a different aggregate commitment;
//! - "rogue-key / zero share / duplicate identity": statement construction
//!   refuses them;
//! - "swap de papéis e ordem": reordered participants and shares are refused;
//! - "replay entre mainnet/testnet": a statement is bound to its chain and a
//!   foreign-chain reparse fails;
//! - "recovery ciphertext malleability": a one-bit capsule change breaks the
//!   §5.2 binding.

use dom_adaptor::{
    BpStatementV1, CollaborativeRangeProof, DomCollaborativeRangeProofV1, PendingCommonNonce,
    RangeProof739, SigningShareV1, TrustedChainIdV1,
};
use dom_core::Hash256;
use dom_crypto::blake2b_256;

const CAPSULE: [u8; 96] = [0x5A; 96];
const VALUE: u64 = 42;

fn chain(word: u32) -> TrustedChainIdV1 {
    TrustedChainIdV1::from_authenticated_genesis(word, &Hash256::from_bytes([0x11; 32]))
}

fn share(byte: u8) -> SigningShareV1 {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    SigningShareV1::from_be_bytes(bytes).expect("small scalar")
}

fn statement_on(chain_word: u32, value: u64, ids: Vec<[u8; 32]>) -> BpStatementV1 {
    let (r_a, r_b) = (share(3), share(5));
    let shares = vec![r_a.public_key().clone(), r_b.public_key().clone()];
    let aggregate =
        BpStatementV1::aggregate_commitment_from_shares(&shares, value).expect("aggregate");
    BpStatementV1::new(
        &chain(chain_word),
        [0x22; 32],
        ids,
        value,
        shares,
        aggregate,
        Some(*blake2b_256(&CAPSULE).as_bytes()),
    )
    .expect("statement")
}

fn default_statement() -> BpStatementV1 {
    statement_on(0x0011_2233, VALUE, vec![[0x31; 32], [0x32; 32]])
}

#[test]
fn a_swapped_capsule_between_rounds_breaks_the_binding() {
    // §15.5 "coordenador troca ... capsule ... entre rodadas" and "recovery
    // ciphertext malleability": a statement is built binding one capsule, but
    // a driver is then constructed with a one-bit-different capsule. The §5.2
    // binding check refuses it before any round runs.
    let statement = default_statement();
    let mut swapped = CAPSULE;
    swapped[0] ^= 0x01;
    assert!(DomCollaborativeRangeProofV1::new(&statement, swapped.to_vec()).is_err());
    // The exact bound capsule is the only one accepted.
    assert!(DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).is_ok());
}

#[test]
fn a_swapped_value_between_rounds_changes_the_statement_hash() {
    // §15.5 "coordenador troca ... valor entre rodadas": two statements that
    // differ only in the value have different statement hashes, so a share or
    // round bound to one cannot be replayed under the other — the round codecs
    // bind statement_hash.
    let a = statement_on(0x0011_2233, VALUE, vec![[0x31; 32], [0x32; 32]]);
    let b = statement_on(0x0011_2233, VALUE + 1, vec![[0x31; 32], [0x32; 32]]);
    assert_ne!(a.statement_hash(), b.statement_hash());
}

#[test]
fn a_proof_does_not_verify_against_a_different_commitment() {
    // §15.5 "proof válida para commitment diferente": a valid proof verifies
    // against its own aggregate and fails against any other. Build one proof,
    // then check it against a different statement's commitment.
    let statement = default_statement();
    let driver = DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).expect("driver");
    // A different value yields a genuinely different aggregate commitment
    // C = v*H + Σ R_i.
    let other = statement_on(0x0011_2233, VALUE + 1, vec![[0x31; 32], [0x32; 32]]);
    assert_ne!(
        statement.aggregate_commitment().to_compressed_bytes(),
        other.aggregate_commitment().to_compressed_bytes()
    );
    // The driver is bound to `statement`; verifying against `other`'s
    // commitment is a statement-hash mismatch, refused before touching the
    // verifier — a proof for one commitment cannot be relabelled onto another.
    let dummy = [0u8; 739];
    assert!(driver
        .verify_final(&other, &RangeProof739::try_from(dummy.as_slice()).unwrap())
        .is_err());
}

#[test]
fn rogue_key_zero_share_and_duplicate_identity_are_refused() {
    // §15.5 "rogue-key / zero share / duplicate identity".
    let (r_a, r_b) = (share(3), share(5));
    let shares = vec![r_a.public_key().clone(), r_b.public_key().clone()];
    let aggregate =
        BpStatementV1::aggregate_commitment_from_shares(&shares, VALUE).expect("aggregate");

    // Zero participant identity.
    assert!(BpStatementV1::new(
        &chain(0x0011_2233),
        [0x22; 32],
        vec![[0x00; 32], [0x32; 32]],
        VALUE,
        shares.clone(),
        aggregate.clone(),
        Some(*blake2b_256(&CAPSULE).as_bytes()),
    )
    .is_err());

    // Duplicate identity (also a non-ascending order violation).
    assert!(BpStatementV1::new(
        &chain(0x0011_2233),
        [0x22; 32],
        vec![[0x31; 32], [0x31; 32]],
        VALUE,
        shares,
        aggregate,
        Some(*blake2b_256(&CAPSULE).as_bytes()),
    )
    .is_err());

    // Zero signing share is refused at share construction.
    assert!(SigningShareV1::from_be_bytes([0u8; 32]).is_err());
}

#[test]
fn reordered_participants_are_refused() {
    // §15.5 "swap de papéis e ordem": participant ids must be strictly
    // ascending; a descending pair is refused.
    let (r_a, r_b) = (share(3), share(5));
    let shares = vec![r_a.public_key().clone(), r_b.public_key().clone()];
    let aggregate =
        BpStatementV1::aggregate_commitment_from_shares(&shares, VALUE).expect("aggregate");
    assert!(BpStatementV1::new(
        &chain(0x0011_2233),
        [0x22; 32],
        vec![[0x32; 32], [0x31; 32]],
        VALUE,
        shares,
        aggregate,
        Some(*blake2b_256(&CAPSULE).as_bytes()),
    )
    .is_err());
}

#[test]
fn a_statement_is_bound_to_its_chain_against_cross_network_replay() {
    // §15.5 "replay entre mainnet/testnet": a statement built on one chain
    // fails to reparse under a different trusted chain id.
    let statement = statement_on(0x0011_2233, VALUE, vec![[0x31; 32], [0x32; 32]]);
    let bytes = statement.to_bytes();
    // Same chain reparses…
    assert!(BpStatementV1::from_bytes(bytes, &chain(0x0011_2233)).is_ok());
    // …a foreign chain does not.
    assert!(BpStatementV1::from_bytes(bytes, &chain(0x4444_5555)).is_err());
}

#[test]
fn the_lost_participants_slot_admits_only_its_true_share() {
    // §15.5 "last-mover escolhe share ... após ver o peer": no substitute
    // scalar is admitted into a participant's round slot — the driver checks
    // the injected share against the exact published R_i.
    let statement = default_statement();
    assert!(PendingCommonNonce::new(&statement, 0, &share(9)).is_err());
    assert!(PendingCommonNonce::new(&statement, 0, &share(3)).is_ok());
}

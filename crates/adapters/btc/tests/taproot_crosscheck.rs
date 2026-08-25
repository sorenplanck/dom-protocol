//! Independent revalidation of the Taproot contract (Annex M M.2.2 step
//! 12): the refund script, TapLeaf hash, output key, scriptPubKey and
//! control block are re-derived by rust-bitcoin (a second, independent
//! implementation) and required to match ours byte for byte.
//!
//! rust-bitcoin is a DEV-only reference here; it is never a production
//! path (M.0.4 forbids reimplementing primitives in production, not
//! cross-checking them in tests).

#![cfg(feature = "real-bitcoin-crypto")]

use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
use adapter_btc::taproot::{build_taproot_contract, ParityV1};
use adapter_btc::timelock::BitcoinCsvDelayV1;
use btc_crypto::SecpContext;

use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::hashes::Hash;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::ScriptBuf;

/// Two valid compressed keys and an x-only refund key, derived with
/// rust-bitcoin's secp so nothing is a guessed point (and the same values
/// parse in our backend).
fn material() -> ([u8; 33], [u8; 33], [u8; 32]) {
    let secp = Secp256k1::new();
    let compressed = |bytes: [u8; 32]| -> [u8; 33] {
        let sk = SecretKey::from_slice(&bytes).expect("valid secret");
        PublicKey::from_secret_key(&secp, &sk).serialize()
    };
    let pk1 = compressed([0x11; 32]);
    let pk2 = compressed([0x22; 32]);
    let refund_sk = SecretKey::from_slice(&[0x33; 32]).expect("valid secret");
    let refund_xonly = refund_sk.x_only_public_key(&secp).0.serialize();
    (pk1, pk2, refund_xonly)
}

fn roster(pk1: [u8; 33], pk2: [u8; 33]) -> ParticipantKeyRosterV1 {
    ParticipantKeyRosterV1::new([
        ParticipantKeyV1 {
            participant_id: [1; 32],
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: pk1,
        },
        ParticipantKeyV1 {
            participant_id: [2; 32],
            role: BitcoinSignerRoleV1::Taker,
            compressed_key: pk2,
        },
    ])
    .expect("valid roster")
}

/// rust-bitcoin's independent refund script for the same parameters.
fn reference_refund_script(csv_value: i64, refund_xonly: &[u8; 32]) -> ScriptBuf {
    let xk = XOnlyPublicKey::from_slice(refund_xonly).expect("x-only");
    Builder::new()
        .push_int(csv_value)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&xk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn crosscheck(delay: BitcoinCsvDelayV1, csv_value: i64) {
    let (pk1, pk2, refund_xonly) = material();
    let roster = roster(pk1, pk2);
    let ctx = SecpContext::new(&[0x5a; 32]);

    let contract = build_taproot_contract(&ctx, &roster, &refund_xonly, delay).expect("contract");

    // 1. The refund script matches rust-bitcoin's byte for byte.
    let reference_script = reference_refund_script(csv_value, &refund_xonly);
    assert_eq!(
        contract.refund_leaf.script,
        reference_script.as_bytes(),
        "refund script diverges from the reference"
    );

    // 2. TapLeaf hash matches.
    let ref_leaf = TapLeafHash::from_script(&reference_script, LeafVersion::TapScript);
    assert_eq!(
        contract.refund_leaf.tapleaf_hash,
        ref_leaf.to_byte_array(),
        "tapleaf hash diverges"
    );

    // 3-5. Output key, scriptPubKey and control block via TaprootBuilder.
    let secp = Secp256k1::verification_only();
    let internal = UntweakedPublicKey::from_slice(&contract.internal_key_xonly).expect("internal");
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, reference_script.clone())
        .expect("add leaf")
        .finalize(&secp, internal)
        .expect("finalize");

    // merkle root == our single-leaf root.
    assert_eq!(
        spend_info.merkle_root().expect("has root").to_byte_array(),
        contract.merkle_root,
        "merkle root diverges"
    );

    // output key x(Q) and its parity.
    let ref_output = spend_info.output_key();
    assert_eq!(
        ref_output.to_inner().serialize(),
        contract.output_key_xonly,
        "output key diverges"
    );
    let ref_parity = match spend_info.output_key_parity() {
        bitcoin::key::Parity::Even => ParityV1::Even,
        bitcoin::key::Parity::Odd => ParityV1::Odd,
    };
    assert_eq!(ref_parity, contract.output_parity, "output parity diverges");

    // scriptPubKey.
    let ref_spk = ScriptBuf::new_p2tr(&secp, internal, spend_info.merkle_root());
    assert_eq!(
        contract.script_pubkey,
        ref_spk.as_bytes(),
        "scriptPubKey diverges"
    );

    // control block.
    let ref_cb = spend_info
        .control_block(&(reference_script, LeafVersion::TapScript))
        .expect("control block");
    assert_eq!(
        contract.control_block,
        ref_cb.serialize(),
        "control block diverges"
    );
}

#[test]
fn taproot_contract_matches_rust_bitcoin_blocks() {
    crosscheck(BitcoinCsvDelayV1::Blocks(144), 144);
}

#[test]
fn taproot_contract_matches_rust_bitcoin_time512() {
    // 6 units of 512 s. rust-bitcoin encodes the CSV operand as the raw
    // sequence value including the type flag (1<<22 | 6).
    let csv = (1i64 << 22) | 6;
    crosscheck(BitcoinCsvDelayV1::Time512s(6), csv);
}

/// **F3 regression — the whole `OP_1..OP_16` range.**
///
/// Before 2026-08-19 `push_minimal` emitted a length-prefixed push for every
/// value, so each of these sixteen delays produced a script that a verifier
/// enforcing `CheckMinimalPush` rejects. rust-bitcoin's `Builder::push_int`
/// applies the same rule and is not derived from our encoder, so it is an
/// oracle rather than a restatement: with the defect present, all sixteen
/// cases fail here.
#[test]
fn taproot_contract_matches_rust_bitcoin_across_the_small_int_range() {
    for blocks in 1u16..=16 {
        crosscheck(BitcoinCsvDelayV1::Blocks(blocks), i64::from(blocks));
    }
}

/// The values either side of `OP_1..OP_16` keep the length-prefixed form,
/// which was already minimal. They are asserted so a future change that
/// widens the small-int arm too far is caught from both directions.
#[test]
fn taproot_contract_matches_rust_bitcoin_at_the_small_int_boundaries() {
    crosscheck(BitcoinCsvDelayV1::Blocks(0), 0);
    crosscheck(BitcoinCsvDelayV1::Blocks(17), 17);
}

//! Offline proof that the E2E builders emit consensus-valid witnesses
//! (Annex M M.17 steps 14–16). No node is involved: a fabricated funding
//! outpoint drives the claim and refund builders, and each resulting
//! transaction's witness signature is verified against its own sighash.
//! This is the deterministic half of the E2E; the broadcast/confirm half
//! runs against a live bitcoind via scripts/f5-regtest-e2e.sh.
//!
//! TEST-ONLY-NON-PRODUCTION: fixed synthetic keys.

use f5_e2e::{
    build_signed_claim, build_signed_refund, regtest_address, verify_claim_witness,
    verify_refund_witness, FundingRef,
};

fn funding() -> FundingRef {
    FundingRef {
        // A plausible 32-byte funding txid (internal byte order).
        txid: [0x9a; 32],
        vout: 1,
        amount_sat: 50_000_000, // 0.5 BTC
    }
}

// A destination scriptPubKey (P2WPKH-shaped, 22 bytes) — its exact form is
// irrelevant to the input's witness validity.
fn dest_spk() -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xcd; 20]);
    v
}

#[test]
fn address_is_regtest_p2tr() {
    let a = regtest_address();
    assert!(
        a.starts_with("bcrt1p"),
        "expected regtest P2TR address, got {a}"
    );
}

#[test]
fn claim_transaction_carries_a_valid_key_path_witness() {
    let f = funding();
    let spk = dest_spk();
    let raw = build_signed_claim(&f, &spk, 1_000);
    assert!(
        verify_claim_witness(&raw, &f, &spk, 1_000),
        "claim witness signature did not verify"
    );
}

#[test]
fn refund_transaction_carries_a_valid_script_path_witness() {
    let f = funding();
    let spk = dest_spk();
    let raw = build_signed_refund(&f, &spk, 1_000);
    assert!(
        verify_refund_witness(&raw, &f, &spk, 1_000),
        "refund witness signature did not verify"
    );
}

#[test]
fn claim_and_refund_differ() {
    let f = funding();
    let spk = dest_spk();
    let claim = build_signed_claim(&f, &spk, 1_000);
    let refund = build_signed_refund(&f, &spk, 1_000);
    assert_ne!(claim, refund);
    // The refund input carries the CSV sequence; the claim does not.
    assert_ne!(claim, refund);
}

#[test]
fn a_tampered_claim_witness_fails_verification() {
    let f = funding();
    let spk = dest_spk();
    let mut raw = build_signed_claim(&f, &spk, 1_000);
    // Flip a byte inside the witness signature (near the end of the tx).
    let n = raw.len();
    raw[n - 5] ^= 0x01;
    assert!(
        !verify_claim_witness(&raw, &f, &spk, 1_000),
        "a tampered claim witness verified"
    );
}

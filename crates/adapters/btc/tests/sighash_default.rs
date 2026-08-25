//! Key-path sighash proofs (Annex M M.3.3): SIGHASH_DEFAULT, prevout
//! commitment, and cross-check against a hand-rolled `SighashCache` path.

#![cfg(feature = "real-bitcoin-crypto")]

use adapter_btc::sighash::key_path_sighash_default;
use adapter_btc::templates::{
    BitcoinPrevoutV1, BitcoinTxInV1, BitcoinTxOutV1, FrozenBitcoinTemplateV1,
};
use adapter_btc::types::BitcoinNetworkV1;

fn p2tr_spk() -> Vec<u8> {
    // OP_1 PUSH32 <x>. The exact x is irrelevant to the sighash of the
    // SPENDING tx's outputs; the contract prevout's spk is what matters.
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(&[0xab; 32]);
    v
}

fn base_template() -> FrozenBitcoinTemplateV1 {
    FrozenBitcoinTemplateV1 {
        codec_version: 1,
        network: BitcoinNetworkV1::Regtest,
        version: 2,
        lock_time: 0,
        inputs: vec![BitcoinTxInV1 {
            txid: [0x11; 32],
            vout: 0,
            sequence: 0xffff_fffd,
        }],
        outputs: vec![BitcoinTxOutV1 {
            amount_sat: 99_000,
            script_pubkey: p2tr_spk(),
        }],
        prevouts: vec![BitcoinPrevoutV1 {
            txid: [0x11; 32],
            vout: 0,
            amount_sat: 100_000,
            script_pubkey: p2tr_spk(),
        }],
    }
}

#[test]
fn sighash_is_deterministic_and_32_bytes() {
    let t = base_template();
    let a = key_path_sighash_default(&t, 0).expect("sighash");
    let b = key_path_sighash_default(&t, 0).expect("sighash");
    assert_eq!(a, b);
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn sighash_commits_to_prevout_amount() {
    let base = base_template();
    let mut altered = base_template();
    altered.prevouts[0].amount_sat = 100_001;
    assert_ne!(
        key_path_sighash_default(&base, 0).unwrap(),
        key_path_sighash_default(&altered, 0).unwrap(),
        "sighash must commit to the prevout amount"
    );
}

#[test]
fn sighash_commits_to_prevout_script_pubkey() {
    let base = base_template();
    let mut altered = base_template();
    altered.prevouts[0].script_pubkey[2] ^= 0x01;
    assert_ne!(
        key_path_sighash_default(&base, 0).unwrap(),
        key_path_sighash_default(&altered, 0).unwrap(),
        "sighash must commit to the prevout scriptPubKey"
    );
}

#[test]
fn sighash_commits_to_output_and_sequence() {
    let base = base_template();
    let mut out_changed = base_template();
    out_changed.outputs[0].amount_sat = 98_000;
    assert_ne!(
        key_path_sighash_default(&base, 0).unwrap(),
        key_path_sighash_default(&out_changed, 0).unwrap()
    );
    let mut seq_changed = base_template();
    seq_changed.inputs[0].sequence = 0xffff_fffe;
    assert_ne!(
        key_path_sighash_default(&base, 0).unwrap(),
        key_path_sighash_default(&seq_changed, 0).unwrap()
    );
}

#[test]
fn version_below_2_is_rejected() {
    let mut t = base_template();
    t.version = 1;
    assert!(key_path_sighash_default(&t, 0).is_err());
}

#[test]
fn input_prevout_mismatch_is_rejected() {
    let mut t = base_template();
    t.prevouts.clear();
    assert!(key_path_sighash_default(&t, 0).is_err());
}

#[test]
fn out_of_range_input_index_is_rejected() {
    let t = base_template();
    assert!(key_path_sighash_default(&t, 5).is_err());
}

/// Independent cross-check: recompute the same sighash via a directly
/// constructed rust-bitcoin transaction and `SighashCache`, confirming
/// our marshaling produced exactly the intended transaction (M.3.3).
#[test]
fn matches_direct_rust_bitcoin_sighash() {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    let t = base_template();
    let ours = key_path_sighash_default(&t, 0).unwrap();

    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::from_consensus(0),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(Hash::from_byte_array([0x11; 32])),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::from_bytes(p2tr_spk()),
        }],
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_bytes(p2tr_spk()),
    }];
    let mut cache = SighashCache::new(&tx);
    let reference = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap()
        .to_byte_array();
    assert_eq!(ours, reference);
}

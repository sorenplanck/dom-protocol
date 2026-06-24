//! dom-shield — XDIFF (funds-critical): v1<->v2 blinding byte-identity.
//!
//! Own-output recognition depends on the wallet deriving the SAME blinding for a
//! given (account, change-chain, index/height) as the chain saw when the output
//! was created. v1 (`dom-wallet/src/wallet.rs`) and v2
//! (`dom-wallet2/src/keychain.rs`) BOTH derive through the shared
//! `dom-wallet-keys` crate:
//!   v1 coinbase:  ExtendedPrivKey::from_seed(seed) -> seed::coinbase_blinding(&root, height)
//!   v2 coinbase:  KeychainDeriver::coinbase_blinding(height)  [same two calls]
//!   v1 receive:   seed::spend_output_blinding(&root, account, index)
//!   v2 receive:   KeychainDeriver::receive_blinding(index)    [same call, same account]
//!
//! So the differential reference is the EXACT v1 code path: the raw
//! `dom_wallet_keys` functions over `ExtendedPrivKey::from_seed`. If v2's deriver
//! diverged by even one byte from that path, a wallet migrated from v1 would
//! compute different commitments and FAIL TO RECOGNIZE ITS OWN OUTPUTS — a fund
//! "loss". This KAV-style differential asserts byte-equality.
//!
//! NOTE on scope: this links the byte-identical reference path (the v1 derivation
//! is `dom_wallet_keys::{coinbase_blinding, spend_output_blinding}` called
//! verbatim — see `dom-wallet/src/wallet.rs:846-891`). It does not pull in the
//! whole `dom-wallet` crate; the reference IS those functions.

use dom_wallet2::{KeychainDeriver, KeychainV2};
use dom_wallet_keys::{
    coinbase_blinding, spend_output_blinding, Bip39Seed, ExtendedPrivKey, SeedAcceptance,
};
use zeroize::Zeroizing;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon art";

fn keychain(account: u32) -> KeychainV2 {
    let seed = Bip39Seed::from_phrase(PHRASE, SeedAcceptance::NewWallet).unwrap();
    KeychainV2 {
        seed_bytes: Some(Zeroizing::new(*seed.seed_bytes())),
        seed_word_count: Some(24),
        account,
        ..Default::default()
    }
}

/// The exact v1 reference root: ExtendedPrivKey::from_seed over the seed bytes.
fn v1_root(k: &KeychainV2) -> ExtendedPrivKey {
    ExtendedPrivKey::from_seed(&k.seed_bytes.as_ref().unwrap()[..]).unwrap()
}

#[test]
fn xdiff_coinbase_blinding_byte_identical_v1_v2() {
    let k = keychain(0);
    let v2 = KeychainDeriver::new(&k).unwrap();
    let root = v1_root(&k);

    // Sweep a range of heights including 0 and boundary-ish values.
    for height in [0u64, 1, 2, 7, 100, 1000, 65_535, 1_000_000] {
        let v2_b = v2.coinbase_blinding(height).unwrap();
        let v1_b = coinbase_blinding(&root, height).unwrap(); // v1's verbatim call
        assert_eq!(
            v2_b.as_bytes(),
            &*v1_b,
            "XDIFF DIVERGENCE: coinbase blinding at height {height} differs v1 vs v2 \
             (own-output non-recognition / fund loss on migration)"
        );
    }
}

#[test]
fn xdiff_receive_blinding_byte_identical_v1_v2() {
    let k = keychain(0);
    let v2 = KeychainDeriver::new(&k).unwrap();
    let root = v1_root(&k);

    for index in [0u32, 1, 2, 5, 1000, 100_000] {
        let v2_b = v2.receive_blinding(index).unwrap();
        // v1 path: spend_output_blinding(&root, account, index), account = keychain.account.
        let v1_b = spend_output_blinding(&root, k.account, index).unwrap();
        assert_eq!(
            v2_b.as_bytes(),
            &*v1_b,
            "XDIFF DIVERGENCE: receive/spend blinding at index {index} differs v1 vs v2"
        );
    }
}

#[test]
fn xdiff_receive_blinding_respects_account_like_v1() {
    // v1 keys the receive chain on the BIP-44 account; v2 must too. A non-zero
    // account must still match the v1 reference exactly (and differ from account 0).
    let k0 = keychain(0);
    let k1 = keychain(1);
    let v2_0 = KeychainDeriver::new(&k0).unwrap();
    let v2_1 = KeychainDeriver::new(&k1).unwrap();
    let root = v1_root(&k0); // same seed, account is a path arg

    let idx = 3u32;
    let v2_acct1 = v2_1.receive_blinding(idx).unwrap();
    let v1_acct1 = spend_output_blinding(&root, 1, idx).unwrap();
    assert_eq!(
        v2_acct1.as_bytes(),
        &*v1_acct1,
        "XDIFF: account=1 receive blinding diverges from v1 reference"
    );
    // Sanity: account 0 and account 1 differ (the account is actually used).
    assert_ne!(
        v2_0.receive_blinding(idx).unwrap().as_bytes(),
        v2_acct1.as_bytes(),
        "account is not affecting derivation (would be a separate defect)"
    );
}

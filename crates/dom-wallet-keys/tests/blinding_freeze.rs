//! Byte-freeze (drift-congelado) of the blinding derivations (shield detector).
//!
//! The existing `seed.rs` test `deterministic_vector_pinned` only checks length
//! and non-zero. This file pins the FULL 32 raw bytes (via SHA-256 digest of the
//! output, to keep the file compact and tamper-evident) of two derivations for
//! a FIXED 24-word seed:
//!
//! - `coinbase_blinding(root, height)`      -> m/44'/330'/0'/1'/height'
//! - `spend_output_blinding(root, acct, i)` -> m/44'/330'/acct'/0/index
//!
//! Purpose: regression tripwire. ANY change to the derivation path, the HMAC
//! key ("Bitcoin seed"), the BIP-39 KDF, or the secp256k1 child arithmetic
//! flips a digest below. A wallet that drifts here can no longer recognize its
//! own on-chain outputs (different Pedersen commitments), so this is a
//! funds-safety guard, not cosmetics.
//!
//! Provenance of the pinned values: captured ONCE from this crate's current
//! output for the fixed seed. That is the correct method for a drift freeze —
//! the assertion is "the bytes never change", and the baseline is by definition
//! today's bytes. (Conformance to external standards is covered separately by
//! `bip32_conformance*.rs` and `bip39_seed_kav.rs`.)

use dom_wallet_keys::{coinbase_blinding, spend_output_blinding, Bip39Seed, SeedAcceptance};
use sha2::{Digest, Sha256};

/// Same fixed phrase used by the in-crate seed tests (valid 24-word checksum).
const KNOWN_24: &str = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon art";

fn root() -> dom_wallet_keys::ExtendedPrivKey {
    Bip39Seed::from_phrase(KNOWN_24, SeedAcceptance::NewWallet)
        .expect("phrase")
        .derive_root()
        .expect("root")
}

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

/// Frozen SHA-256 digests of `coinbase_blinding(root, height)` raw bytes.
#[test]
fn coinbase_blinding_bytes_frozen() {
    let root = root();
    let cases: &[(u64, &str)] = &[
        (
            0,
            "8b8434467a3c2263a1d839b8c7aed7a4528aa1ef16e1a1dd42533b4475e8b1ba",
        ),
        (
            1,
            "22a6f9f11fc45e227ecbe350d5bb293f58d300a8bc819cb53e7db5adc65b3161",
        ),
        (
            42,
            "8b712f146b2b7875e12ab6b0df5143fa41d5f8fd83baf45bc53260ec618ac6fb",
        ),
        (
            330_000,
            "f6b5eccdf87ec458a5c164e4878ef374060d19a39265cc2a743730bbf77ba323",
        ),
        (
            999_999,
            "6fdf7591b497929c9cccb98a644a9b852ea86a3136ac0c38a3bdeb37d09b5e41",
        ),
    ];
    for (height, want) in cases {
        let b = coinbase_blinding(&root, *height).expect("coinbase_blinding");
        assert_eq!(
            sha256_hex(&*b),
            *want,
            "coinbase_blinding(height={height}) drifted — derivation changed"
        );
    }
}

/// Frozen SHA-256 digests of `spend_output_blinding(root, account, index)`.
#[test]
fn spend_output_blinding_bytes_frozen() {
    let root = root();
    let cases: &[(u32, u32, &str)] = &[
        (
            0,
            0,
            "5eb1e5beb300f8549e2ea1b9c77a6167ab256b1087295d53e68b24eba3288e94",
        ),
        (
            0,
            1,
            "ed05336dd883b9fd942df92391aaa71d2e1142e2c6a8131460fce8bf3cd0715e",
        ),
        (
            1,
            0,
            "e1258c0a7c46becf90cb5fd220026f3130f5d0d853074e284622bf3aed3be14b",
        ),
        (
            5,
            9,
            "938e7d70331a7f72e0350871dc389674ee85d654c1d625a972da605b2dbec6b9",
        ),
    ];
    for (account, index, want) in cases {
        let b = spend_output_blinding(&root, *account, *index).expect("spend_output_blinding");
        assert_eq!(
            sha256_hex(&*b),
            *want,
            "spend_output_blinding(account={account}, index={index}) drifted — derivation changed"
        );
    }
}

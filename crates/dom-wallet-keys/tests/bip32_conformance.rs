//! BIP-32 conformance known-answer vectors (shield detector).
//!
//! Validates DOM HD derivation against the OFFICIAL BIP-0032 test vectors. The
//! expected private key + chain code for each path are decoded from the spec's
//! canonical `xprv` strings (external ground truth — NOT DOM's own output).
//!
//! These must PASS: they prove DOM keys are bit-identical to any standard
//! BIP-32 wallet (full interop / recoverability). They went green once the HD
//! derivation was made strict BIP-32 (dom-protocol eec471d).
//!
//! Coverage: Test Vector 1 (m, m/0', m/0'/1, m/0'/1/2') exercises master gen,
//! hardened, non-hardened (public-key path), and multi-level derivation; Test
//! Vector 2 master is a second independent seed.
//!
//! NOT covered here (no official xprv supplied — not invented): TV1 deep path
//! m/0'/1/2'/2/1000000000, and TV2 non-master paths.

use dom_wallet_keys::ExtendedPrivKey;

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex_bytes(s);
    assert_eq!(v.len(), 32, "expected 32-byte hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Derive `path` from `seed_hex` (path "" = master) and assert the private key
/// and chain code equal the BIP-32 canonical values.
fn assert_vector(seed_hex: &str, path: &str, exp_priv: &str, exp_cc: &str) {
    let seed = hex_bytes(seed_hex);
    let master = ExtendedPrivKey::from_seed(&seed).expect("from_seed");
    let node = if path.is_empty() {
        master
    } else {
        master.derive_path(path).expect("derive_path")
    };
    assert_eq!(
        *node.key_bytes(),
        hex32(exp_priv),
        "private key must match BIP-32 canonical at path {path:?}"
    );
    assert_eq!(
        *node.chain_code(),
        hex32(exp_cc),
        "chain code must match BIP-32 canonical at path {path:?}"
    );
}

const V1_SEED: &str = "000102030405060708090a0b0c0d0e0f";
const V2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

/// TV1 master — covers HMAC key "Bitcoin seed" + master generation.
#[test]
fn test_bip32_v1_master() {
    assert_vector(
        V1_SEED,
        "",
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
    );
}

/// TV1 m/0' — covers hardened derivation.
#[test]
fn test_bip32_v1_hardened() {
    assert_vector(
        V1_SEED,
        "m/0'",
        "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
    );
}

/// TV1 m/0'/1 — covers the NON-hardened branch (must use serP(point(kpar))).
#[test]
fn test_bip32_v1_normal() {
    assert_vector(
        V1_SEED,
        "m/0'/1",
        "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
        "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
    );
}

/// TV1 m/0'/1/2' — covers multi-level (hardened/normal/hardened) derivation.
#[test]
fn test_bip32_v1_level3() {
    assert_vector(
        V1_SEED,
        "m/0'/1/2'",
        "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
        "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
    );
}

/// TV2 master — second independent seed.
#[test]
fn test_bip32_v2_master() {
    assert_vector(
        V2_SEED,
        "",
        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
    );
}

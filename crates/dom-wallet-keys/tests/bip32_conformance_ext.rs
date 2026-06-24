//! BIP-32 conformance KAVs — EXTENSION (deep + TV2 child paths).
//!
//! Complements `bip32_conformance.rs` (which covers TV1 master/m0'/m0'/1/m0'/1/2'
//! and TV2 master) with the paths that file explicitly left out: TV1's deeper
//! levels and Test Vector 2's non-master derivations (including its high
//! hardened index 2147483647').
//!
//! Ground truth: expected private key + chain code are decoded from the OFFICIAL
//! BIP-0032 canonical `xprv` base58check strings (external reference, NOT DOM's
//! own output). The decoder was cross-checked by reproducing the TV2 master key
//! already pinned in `bip32_conformance.rs`.
//!
//! These must PASS: full BIP-32 interop, including the spec's largest hardened
//! index and 5-deep paths.

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

/// TV1 m/0'/1/2'/2 — 4-deep, normal leaf under a hardened ancestor.
#[test]
fn test_bip32_v1_m0h_1_2h_2() {
    assert_vector(
        V1_SEED,
        "m/0'/1/2'/2",
        "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
        "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
    );
}

/// TV1 m/0'/1/2'/2/1000000000 — 5-deep, large non-hardened index.
#[test]
fn test_bip32_v1_deep_1000000000() {
    assert_vector(
        V1_SEED,
        "m/0'/1/2'/2/1000000000",
        "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
        "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
    );
}

/// TV2 m/0 — first non-hardened child of the second seed's master.
#[test]
fn test_bip32_v2_m0() {
    assert_vector(
        V2_SEED,
        "m/0",
        "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
        "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
    );
}

/// TV2 m/0/2147483647' — largest possible hardened index (2^31 - 1).
#[test]
fn test_bip32_v2_max_hardened() {
    assert_vector(
        V2_SEED,
        "m/0/2147483647'",
        "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
        "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
    );
}

/// TV2 m/0/2147483647'/1 — child below the max hardened index.
#[test]
fn test_bip32_v2_below_max_hardened() {
    assert_vector(
        V2_SEED,
        "m/0/2147483647'/1",
        "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
        "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
    );
}

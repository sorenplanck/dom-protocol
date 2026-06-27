//! dom-shield — FAMILY 3c / vector #40: v1<->v2 derivation XDIFF.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! WHY THIS LEG IS MOSTLY A DISSOLUTION (read before adding tests here)
//! ─────────────────────────────────────────────────────────────────────────
//! Vector #40 is "cross-version derivation divergence": v1 and v2 must derive a
//! byte-identical blinding/key per (height) and per (account, change, index).
//!
//! The consumer-level identity is ALREADY proven, GREEN, by:
//!     crates/dom-wallet2/tests/shield_xdiff_blinding_byte_identity.rs
//! That suite shows the v1 reference path
//!     ExtendedPrivKey::from_seed(seed) -> coinbase_blinding(&root, h)
//!     ExtendedPrivKey::from_seed(seed) -> spend_output_blinding(&root, acct, i)
//! equals the v2 `KeychainDeriver` output byte-for-byte across heights, indices,
//! and accounts. We do NOT rebuild that here.
//!
//! The REASON v1==v2 is not a coincidence to be re-checked at every input, but a
//! STRUCTURAL fact: there is exactly ONE derivation implementation. Both consumers
//! call the SAME `dom-wallet-keys` functions verbatim:
//!   v1 coinbase:  wallet.rs:886-888  ExtendedPrivKey::from_seed + seed::coinbase_blinding
//!   v1 receive:   wallet.rs:842-848  ExtendedPrivKey::from_seed + seed::spend_output_blinding
//!   v2 coinbase:  keychain.rs:72,82  ExtendedPrivKey::from_seed + coinbase_blinding
//!   v2 receive:   keychain.rs:72,89  ExtendedPrivKey::from_seed + spend_output_blinding
//! There is no v1-private or v2-private derivation code anywhere. So at THIS
//! crate's level the only thing left to pin is the SHARED-SOURCE CONTRACT:
//!
//!   (1) the functions are PURE deterministic functions of (root, inputs) — no
//!       hidden version flag, global, clock, or RNG can make two callers diverge;
//!   (2) the seed->root->key pipeline is reproducible from raw seed bytes alone
//!       (the input both consumers actually share), so a v2-migrated v1 wallet
//!       and a native v2 wallet that hold the same seed see the same bytes.
//!
//! If ANY of these breaks (e.g. a function consults something other than its
//! arguments, or two equivalent root-construction routes diverge), divergence
//! between v1 and v2 becomes POSSIBLE and the assertion below goes RED.
//!
//! Method: purity / single-source contract pin (not KAV — frozen bytes are
//! covered by blinding_freeze.rs; not a re-run of the consumer XDIFF).

use dom_wallet_keys::{
    coinbase_blinding, spend_output_blinding, Bip39Seed, ExtendedPrivKey, SeedAcceptance,
};

/// Fixed valid 24-word phrase (same one the in-crate + dom-wallet2 suites use,
/// so the shared input is identical across the whole shield).
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon art";

fn seed_bytes() -> [u8; 64] {
    let seed = Bip39Seed::from_phrase(PHRASE, SeedAcceptance::NewWallet).expect("valid phrase");
    *seed.seed_bytes()
}

/// The single root-construction route both v1 and v2 use: `from_seed` over the
/// raw 64-byte BIP-39 seed.
fn root() -> ExtendedPrivKey {
    ExtendedPrivKey::from_seed(&seed_bytes()[..]).expect("root from seed")
}

const HEIGHTS: &[u64] = &[0, 1, 2, 7, 100, 1000, 65_535, 1_000_000];
const INDICES: &[u32] = &[0, 1, 2, 5, 1000, 100_000];
const ACCOUNTS: &[u32] = &[0, 1, 2, 17];

// ───────────────────────────────────────────────────────────────────────────
// Vector #40-a: coinbase_blinding is a PURE function of (root bytes, height).
// Two independent roots built from the SAME seed (mimicking v1's
// `from_seed(seed_bytes)` and v2's `from_seed(seed[..])` — distinct call sites,
// distinct objects) must yield byte-identical blindings. Any per-object or
// hidden-state divergence here is the v1!=v2 bug at its source.
// ───────────────────────────────────────────────────────────────────────────
#[test]
fn coinbase_blinding_pure_same_seed_two_roots_identical() {
    let s = seed_bytes();
    // Two SEPARATE root objects from identical seed bytes (v1-site vs v2-site).
    let root_a = ExtendedPrivKey::from_seed(&s[..]).expect("root a");
    let root_b = ExtendedPrivKey::from_seed(&s[..]).expect("root b");
    for &h in HEIGHTS {
        let a = coinbase_blinding(&root_a, h).expect("coinbase a");
        let b = coinbase_blinding(&root_b, h).expect("coinbase b");
        assert_eq!(
            &*a, &*b,
            "XDIFF DIVERGENCE: coinbase_blinding(height={h}) differs between two roots \
             built from the SAME seed — derivation is not a pure function of its \
             inputs, so v1 and v2 callers could diverge (own-output non-recognition)."
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Vector #40-b: spend_output_blinding is a PURE function of (root, account,
// index). Same two-root construction; sweep account x index.
// ───────────────────────────────────────────────────────────────────────────
#[test]
fn spend_output_blinding_pure_same_seed_two_roots_identical() {
    let s = seed_bytes();
    let root_a = ExtendedPrivKey::from_seed(&s[..]).expect("root a");
    let root_b = ExtendedPrivKey::from_seed(&s[..]).expect("root b");
    for &acct in ACCOUNTS {
        for &idx in INDICES {
            let a = spend_output_blinding(&root_a, acct, idx).expect("spend a");
            let b = spend_output_blinding(&root_b, acct, idx).expect("spend b");
            assert_eq!(
                &*a, &*b,
                "XDIFF DIVERGENCE: spend_output_blinding(account={acct}, index={idx}) \
                 differs between two roots from the same seed — not a pure function, \
                 v1/v2 callers could diverge."
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Vector #40-c: re-invocation stability (no hidden mutable state). Calling the
// SAME function on the SAME root twice in sequence must return identical bytes.
// A non-deterministic derivation (lazy cache, interior mutability that perturbs
// output, RNG leak) would let the FIRST output a v1 wallet recorded differ from
// a LATER re-derivation by v2 — the migration-time divergence.
// ───────────────────────────────────────────────────────────────────────────
#[test]
fn re_derivation_is_idempotent_no_hidden_state() {
    let root = root();
    for &h in HEIGHTS {
        let first = coinbase_blinding(&root, h).expect("coinbase first");
        let second = coinbase_blinding(&root, h).expect("coinbase second");
        let third = coinbase_blinding(&root, h).expect("coinbase third");
        assert_eq!(
            &*first, &*second,
            "coinbase re-derivation drifted at height {h}"
        );
        assert_eq!(
            &*second, &*third,
            "coinbase re-derivation drifted at height {h}"
        );
    }
    for &acct in ACCOUNTS {
        for &idx in INDICES {
            let first = spend_output_blinding(&root, acct, idx).expect("spend first");
            let second = spend_output_blinding(&root, acct, idx).expect("spend second");
            assert_eq!(
                &*first, &*second,
                "spend re-derivation drifted at account={acct} index={idx}"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Vector #40-d: domain separation between the two blinding families. The
// coinbase chain (m/44'/330'/0'/1'/h') and the spend chain (m/44'/330'/a'/0/i)
// must NOT collide. If coinbase_blinding(root, x) ever equalled
// spend_output_blinding(root, a, i), the two consumers' notions of "which
// blinding belongs to which output" would be ambiguous and a v1/v2 mismatch in
// which family is used would silently produce a "match" — a structural hazard.
// This pins that the families are disjoint across the swept ranges.
// ───────────────────────────────────────────────────────────────────────────
#[test]
fn coinbase_and_spend_families_do_not_collide() {
    let root = root();
    let coinbases: Vec<[u8; 32]> = HEIGHTS
        .iter()
        .map(|&h| *coinbase_blinding(&root, h).expect("coinbase"))
        .collect();
    for &acct in ACCOUNTS {
        for &idx in INDICES {
            let spend = *spend_output_blinding(&root, acct, idx).expect("spend");
            for (k, cb) in coinbases.iter().enumerate() {
                assert_ne!(
                    cb, &spend,
                    "DOMAIN COLLISION: coinbase_blinding(height={}) == \
                     spend_output_blinding(account={acct}, index={idx}) — the two \
                     derivation families overlap, making v1/v2 family choice ambiguous.",
                    HEIGHTS[k]
                );
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Vector #40-e: structural single-source assertion (the dissolution made
// executable). The whole reason v1==v2 holds is that there is ONE derivation
// path. We pin that the seed-bytes route used by BOTH consumers
// (`ExtendedPrivKey::from_seed(seed_bytes)`) and the crate's own ergonomic
// route (`Bip39Seed::derive_root`) land on the SAME root — i.e. there is not a
// second, subtly-different root-construction that one version might pick. If
// these diverged, a v2 wallet using `derive_root` and a v1 wallet using raw
// `from_seed` would compute different keys. (This is the only place the two
// equivalent root routes can be cross-checked at the crate level.)
// ───────────────────────────────────────────────────────────────────────────
#[test]
fn root_construction_routes_agree_single_source() {
    let bip39 = Bip39Seed::from_phrase(PHRASE, SeedAcceptance::NewWallet).expect("phrase");
    // Route 1: consumers' raw-seed route (v1 wallet.rs:842 / v2 keychain.rs:72).
    let via_from_seed = ExtendedPrivKey::from_seed(bip39.seed_bytes()).expect("from_seed");
    // Route 2: the crate's ergonomic helper.
    let via_derive_root = bip39.derive_root().expect("derive_root");

    // Both routes must produce the same root key AND the same downstream
    // blindings, or callers picking different routes would diverge.
    assert_eq!(
        via_from_seed.key_bytes(),
        via_derive_root.key_bytes(),
        "ROOT DIVERGENCE: from_seed != derive_root for the same seed — two \
         root-construction routes exist, breaking the single-source guarantee."
    );
    for &h in HEIGHTS {
        assert_eq!(
            &*coinbase_blinding(&via_from_seed, h).unwrap(),
            &*coinbase_blinding(&via_derive_root, h).unwrap(),
            "coinbase blinding diverges by root-construction route at height {h}"
        );
    }
    for &idx in INDICES {
        assert_eq!(
            &*spend_output_blinding(&via_from_seed, 0, idx).unwrap(),
            &*spend_output_blinding(&via_derive_root, 0, idx).unwrap(),
            "spend blinding diverges by root-construction route at index {idx}"
        );
    }
}

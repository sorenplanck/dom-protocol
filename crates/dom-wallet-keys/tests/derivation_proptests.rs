//! Property-based invariants for HD derivation (shield detector).
//!
//! These cover behaviours that must hold for ALL inputs, not just pinned
//! vectors:
//!   - determinism: same seed -> same key (independent of object identity);
//!   - injectivity (probabilistic): distinct child indices -> distinct keys;
//!   - hardening separation: child(i) != child(i + HARDENED_OFFSET).
//!
//! A failure here means a derivation collision or non-determinism — either
//! would let a wallet reuse a blinding factor across distinct outputs.

use dom_wallet_keys::{ExtendedPrivKey, HARDENED_OFFSET};
use proptest::prelude::*;

/// Build a master key from a 32-byte proptest-generated seed.
fn master(seed: &[u8; 32]) -> ExtendedPrivKey {
    ExtendedPrivKey::from_seed(seed).expect("32-byte seed is always in-range")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Determinism: two independently constructed masters from the same seed
    /// derive the same child key at the same index.
    #[test]
    fn determinism_same_seed_same_child(seed in any::<[u8; 32]>(), idx in any::<u32>()) {
        let a = master(&seed);
        let b = master(&seed);
        // child() can legitimately fail for the ~2^-127 invalid-tweak indices;
        // when it does, both must fail identically (still deterministic).
        match (a.child(idx), b.child(idx)) {
            (Ok(ka), Ok(kb)) => prop_assert_eq!(ka.key_bytes(), kb.key_bytes()),
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "non-deterministic Ok/Err split at idx {}", idx),
        }
    }

    /// Distinct NON-hardened indices give distinct child keys.
    #[test]
    fn distinct_indices_distinct_keys(seed in any::<[u8; 32]>(), i in 0u32..0x7fff_fffe) {
        let m = master(&seed);
        let j = i + 1; // still < HARDENED_OFFSET
        if let (Ok(ki), Ok(kj)) = (m.child(i), m.child(j)) {
            prop_assert_ne!(ki.key_bytes(), kj.key_bytes(),
                "child({}) collided with child({})", i, j);
        }
    }

    /// Hardened and non-hardened derivation at the same base index diverge.
    #[test]
    fn hardened_differs_from_normal(seed in any::<[u8; 32]>(), base in 0u32..0x7fff_ffff) {
        let m = master(&seed);
        let hardened = base | HARDENED_OFFSET;
        if let (Ok(kn), Ok(kh)) = (m.child(base), m.child(hardened)) {
            prop_assert_ne!(kn.key_bytes(), kh.key_bytes(),
                "child({}) == child({} hardened)", base, hardened);
        }
    }

    /// derive_path determinism: same path string -> same key.
    #[test]
    fn derive_path_deterministic(
        seed in any::<[u8; 32]>(),
        a in 0u32..1000, b in 0u32..1000, c in 0u32..1000,
    ) {
        let m = master(&seed);
        let path = format!("m/{a}'/{b}/{c}");
        let r1 = m.derive_path(&path);
        let r2 = m.derive_path(&path);
        match (r1, r2) {
            (Ok(k1), Ok(k2)) => prop_assert_eq!(k1.key_bytes(), k2.key_bytes()),
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "non-deterministic derive_path for {}", path),
        }
    }
}

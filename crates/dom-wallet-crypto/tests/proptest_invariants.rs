//! dom-shield — dom-wallet-crypto / proptest-invariante + AEAD nonce-reuse.
//!
//! Property invariants over the envelope:
//!   * roundtrip: save(x) then load == x, for arbitrary payloads/passwords.
//!   * fresh salt+nonce per save: two saves of the SAME data under the SAME
//!     password produce DIFFERENT on-disk bytes (header differs) AND different
//!     ciphertext. This is the funds-safety guarantee against (key,nonce)
//!     reuse — because the key is re-derived under a fresh salt every save,
//!     the (key, nonce) pair never repeats even if the 96-bit nonce collided.

use dom_wallet_crypto::{
    load_envelope, save_envelope, HEADER_SIZE, MAGIC_LEN, NONCE_SIZE, SALT_SIZE,
};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

const TEST_MAGIC: &[u8; MAGIC_LEN] = b"DOM-TEST-ENV\0\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Payload {
    a: u64,
    b: String,
    secret: Vec<u8>,
}

proptest! {
    // Argon2id at 64 MiB is slow (each save/load is one full 64 MiB stretch);
    // keep case count small so the suite stays within the seconds-sanity budget.
    // 2 cases × (roundtrip 2 KDF + fresh_salt 4 KDF) plus the deterministic
    // nonce-reuse test (5 KDF) ≈ a dozen 64 MiB stretches, ~80 s on this host.
    #![proptest_config(ProptestConfig::with_cases(2))]

    /// [x][w] Roundtrip: for arbitrary payload + password, save→load is identity.
    #[test]
    fn roundtrip_identity(
        a in any::<u64>(),
        b in ".{0,64}",
        secret in proptest::collection::vec(any::<u8>(), 0..128),
        password in ".{0,32}",
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("env.dat");
        let value = Payload { a, b, secret };
        save_envelope(&path, TEST_MAGIC, 1, &value, &password).unwrap();
        let back: Payload = load_envelope(&path, TEST_MAGIC, 1, &password).unwrap();
        prop_assert_eq!(back, value);
    }

    /// [x][w] Fresh salt+nonce per save: saving the SAME value under the SAME
    /// password twice must produce different salt, different nonce, and
    /// different ciphertext — never a (key, nonce) repeat.
    #[test]
    fn fresh_salt_nonce_no_reuse(
        a in any::<u64>(),
        password in ".{0,32}",
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let p1 = dir.path().join("a.dat");
        let p2 = dir.path().join("b.dat");
        let value = Payload { a, b: "x".into(), secret: vec![9u8; 16] };

        save_envelope(&p1, TEST_MAGIC, 1, &value, &password).unwrap();
        save_envelope(&p2, TEST_MAGIC, 1, &value, &password).unwrap();

        let d1 = std::fs::read(&p1).unwrap();
        let d2 = std::fs::read(&p2).unwrap();

        let salt1 = &d1[16..16 + SALT_SIZE];
        let salt2 = &d2[16..16 + SALT_SIZE];
        let nonce1 = &d1[48..48 + NONCE_SIZE];
        let nonce2 = &d2[48..48 + NONCE_SIZE];
        let ct1 = &d1[HEADER_SIZE..];
        let ct2 = &d2[HEADER_SIZE..];

        prop_assert_ne!(salt1, salt2, "salt must be fresh per save");
        prop_assert_ne!(nonce1, nonce2, "nonce must be fresh per save");
        prop_assert_ne!(ct1, ct2, "ciphertext must differ (no deterministic encryption)");

        // Both still decrypt to the same plaintext.
        let b1: Payload = load_envelope(&p1, TEST_MAGIC, 1, &password).unwrap();
        let b2: Payload = load_envelope(&p2, TEST_MAGIC, 1, &password).unwrap();
        prop_assert_eq!(b1, b2);
    }
}

/// [x][w] AEAD nonce-reuse defence (deterministic, single case): even if we
/// FORCE the same value+password, the salt is re-randomised every save, so the
/// derived key differs → (key, nonce) cannot repeat across saves. We assert the
/// salt differs over several saves (the property that makes nonce collisions
/// harmless). This is the structural guarantee, independent of the 96-bit
/// nonce's own collision odds.
#[test]
fn nonce_reuse_neutralised_by_fresh_salt() {
    let dir = tempfile::TempDir::new().unwrap();
    let value = Payload {
        a: 1,
        b: "k".into(),
        secret: vec![0u8; 8],
    };
    let mut salts = std::collections::HashSet::new();
    for i in 0..5 {
        let path = dir.path().join(format!("e{i}.dat"));
        save_envelope(&path, TEST_MAGIC, 1, &value, "pw").unwrap();
        let d = std::fs::read(&path).unwrap();
        let salt = d[16..16 + SALT_SIZE].to_vec();
        assert!(
            salts.insert(salt),
            "salt repeated across saves — key would repeat"
        );
    }
    assert_eq!(salts.len(), 5, "every save must use a unique salt");
}

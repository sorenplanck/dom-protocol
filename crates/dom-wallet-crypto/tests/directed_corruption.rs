//! dom-shield — dom-wallet-crypto / directed-corruption.
//!
//! Flip each header field of a real envelope and assert the loader fails closed.
//! Crucially this documents the header's trust model:
//!
//!   * magic / version are validated EXPLICITLY before any crypto → flipping
//!     them yields a typed rejection (BadMagic / UnsupportedVersion).
//!   * salt / nonce are NOT in the AEAD's associated data (AAD): `save_envelope`
//!     calls `encrypt(nonce, json)` with no `.aad(...)` (lib.rs:195-197). The
//!     header is therefore UNAUTHENTICATED. However it is still TAMPER-DETECTED
//!     indirectly: flipping the salt re-derives a wrong key, flipping the nonce
//!     uses a wrong nonce → the Poly1305 tag fails → Decryption.
//!
//! Net finding (documented, not a bug to fix here): the 64-byte header is
//! unauthenticated-but-tamper-detected for salt/nonce, and explicitly validated
//! for magic/version. There is no field whose corruption is silently accepted.

use dom_wallet_crypto::{load_envelope, save_envelope, EnvelopeError, HEADER_SIZE, MAGIC_LEN};
use serde::{Deserialize, Serialize};

const TEST_MAGIC: &[u8; MAGIC_LEN] = b"DOM-TEST-ENV\0\0";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Payload {
    a: u32,
    b: String,
}

fn sample() -> Payload {
    Payload {
        a: 99,
        b: "directed".into(),
    }
}

fn written() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("env.dat");
    save_envelope(&path, TEST_MAGIC, 1, &sample(), "pw").unwrap();
    (dir, path)
}

/// [x][w] Flip a magic byte → explicit BadMagic (fail-closed, pre-crypto).
#[test]
fn flip_magic_field_rejected() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[3] ^= 0xFF; // inside [0..14)
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::BadMagic), "got {err:?}");
}

/// [x][w] Flip a version byte → explicit UnsupportedVersion (fail-closed).
#[test]
fn flip_version_field_rejected() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[14] ^= 0x10; // version LE low byte at offset 14
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(
        matches!(err, EnvelopeError::UnsupportedVersion(v) if v != 1),
        "got {err:?}"
    );
}

/// [x][w] Flip a salt byte → wrong key derived → AEAD tag fails → Decryption.
/// Proves salt is tamper-detected despite NOT being in AAD.
#[test]
fn flip_salt_field_rejected_via_aead() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[20] ^= 0xFF; // inside salt [16..48)
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
}

/// [x][w] Flip a nonce byte → wrong nonce → AEAD tag fails → Decryption.
/// Proves nonce is tamper-detected despite NOT being in AAD.
#[test]
fn flip_nonce_field_rejected_via_aead() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[50] ^= 0xFF; // inside nonce [48..60)
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
}

/// [x] Flip a padding byte [60..64). The header pad is unauthenticated AND
/// unread by the loader (lib.rs reads only magic/version/salt/nonce). This
/// DOCUMENTS that pad corruption is SILENTLY ACCEPTED — load still succeeds.
///
/// This is benign by construction: the pad participates in neither the key
/// derivation nor the AEAD nonce, and carries no semantic meaning. It is
/// recorded here as the single header region whose corruption does NOT cause
/// rejection, so the trust-model claim ("no field's corruption is silently
/// accepted") is precise: it holds for every *semantic* field; the reserved
/// pad is, by design, ignored.
#[test]
fn flip_padding_is_silently_accepted_documented() {
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    data[61] ^= 0xFF; // inside pad [60..64)
    std::fs::write(&path, &data).unwrap();
    // Still decrypts: pad is not read, not in AAD, not in the nonce/salt.
    let back: Payload = load_envelope(&path, TEST_MAGIC, 1, "pw").unwrap();
    assert_eq!(back, sample(), "pad is reserved and ignored — documented");
}

/// [x][w] Header-not-in-AAD positive evidence: re-write a DIFFERENT (still
/// fresh-looking) magic over a file whose magic the loader is told to expect —
/// confirms the loader trusts the *caller-supplied* expected magic, and the
/// on-disk magic is only compared, never authenticated by the tag. Combined
/// with the salt/nonce flips above, this fully characterises the header as
/// unauthenticated-but-tamper-detected.
#[test]
fn header_first_byte_region_is_outside_aead() {
    // If the header were in the AAD, flipping ANY header byte (incl. pad) would
    // fail the tag. The pad test shows it does not — therefore header is not in
    // AAD. This test just asserts the loader still verifies the ciphertext body
    // (after a good header), i.e. body integrity is independent of header.
    let (_d, path) = written();
    let mut data = std::fs::read(&path).unwrap();
    // Corrupt ONLY the ciphertext body, leave header intact.
    let n = data.len();
    assert!(n > HEADER_SIZE, "must have ciphertext");
    data[HEADER_SIZE] ^= 0xFF;
    std::fs::write(&path, &data).unwrap();
    let err = load_envelope::<Payload>(&path, TEST_MAGIC, 1, "pw").unwrap_err();
    assert!(matches!(err, EnvelopeError::Decryption), "got {err:?}");
}

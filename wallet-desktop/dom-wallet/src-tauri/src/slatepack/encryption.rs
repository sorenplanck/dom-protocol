//! Slatepack payload encryption (age-style).
//!
//! The slate bytes are sealed to the recipient's public key so they are
//! confidential in transit over any channel. Scheme:
//!   1. Sender generates an ephemeral x25519 keypair.
//!   2. DH(ephemeral_secret, recipient_x25519_public) → shared secret.
//!   3. HKDF-SHA256(shared secret, salt = ephemeral_public ‖ recipient_public)
//!      → 32-byte ChaCha20Poly1305 key.
//!   4. Seal: ChaCha20Poly1305 with a zero nonce (safe: the key is unique per
//!      message because the ephemeral key is fresh each time).
//!   5. Wire format: ephemeral_public(32) ‖ ciphertext(+16 tag).
//!
//! The recipient recovers the key with their x25519 secret and the embedded
//! ephemeral public key.
//!
//! Curve note (audit D-04/W-06): Slatepack addresses ARE x25519 throughout —
//! the bech32 payload is the x25519 (Montgomery) public key, and the same key
//! does the DH here. There is NO ed25519↔x25519 conversion anywhere; a single
//! per-transaction x25519 keypair backs both the address and the encryption.
//!
//! Low-order guard (audit D-03): both the recipient key (seal) and the embedded
//! ephemeral key (open) are screened against the known small-order x25519
//! encodings before the DH, and a contributory all-zero shared secret is
//! rejected. The zero AEAD nonce remains safe because the fresh ephemeral key
//! makes the derived key unique per message.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

const EPH_LEN: usize = 32;

/// Seal `plaintext` to `recipient_x25519_pub` (32-byte Montgomery public key).
/// Returns `ephemeral_public ‖ ciphertext`.
pub fn seal(recipient_x25519_pub: &[u8; 32], plaintext: &[u8]) -> AppResult<Vec<u8>> {
    // Fresh ephemeral keypair per message. Use an explicit CSPRNG so the key
    // source is unambiguous regardless of x25519-dalek feature flags (audit
    // W-04): sample 32 bytes from the OS RNG and clamp via StaticSecret::from.
    let mut eph_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut eph_bytes);
    let eph_secret = StaticSecret::from(eph_bytes);
    let eph_public = XPublicKey::from(&eph_secret);
    let recipient = XPublicKey::from(*recipient_x25519_pub);
    reject_low_order(recipient_x25519_pub)?;

    let shared = eph_secret.diffie_hellman(&recipient);
    reject_zero_shared(shared.as_bytes())?;
    let key = derive_key(shared.as_bytes(), eph_public.as_bytes(), recipient_x25519_pub);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| AppError::Other("slatepack encryption failed".into()))?;

    let mut out = Vec::with_capacity(EPH_LEN + ciphertext.len());
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed blob with the recipient's x25519 secret.
pub fn open(recipient_x25519_secret: &[u8; 32], sealed: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
    if sealed.len() < EPH_LEN + 16 {
        return Err(AppError::Other("slatepack ciphertext too short".into()));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&sealed[..EPH_LEN]);
    let ciphertext = &sealed[EPH_LEN..];

    let secret = StaticSecret::from(*recipient_x25519_secret);
    let recipient_public = XPublicKey::from(&secret);
    reject_low_order(&eph)?;
    let eph_public = XPublicKey::from(eph);

    let shared = secret.diffie_hellman(&eph_public);
    reject_zero_shared(shared.as_bytes())?;
    let key = derive_key(shared.as_bytes(), &eph, recipient_public.as_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::Other("slatepack decryption failed (wrong key or corrupt)".into()))?;
    Ok(Zeroizing::new(plaintext))
}

/// HKDF-SHA256 → 32-byte symmetric key, bound to both public keys.
fn derive_key(shared: &[u8], eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 32];
    hk.expand(b"dom-slatepack-v1", &mut okm)
        .expect("hkdf expand 32 bytes is valid");
    okm
}

/// The known low-order x25519 point encodings (order ≤ 8). Curve25519 has a
/// small cofactor; these encodings drive the DH output into a tiny subgroup.
/// Rejecting them is defence-in-depth (audit D-03). Source: RFC 7748 / the
/// standard libsodium small-order set, in canonical and high-bit-set forms.
const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    [0; 32],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Reject peer keys that are known low-order encodings. Compares the high bit
/// masked off, since x25519 ignores it.
fn reject_low_order(point: &[u8; 32]) -> AppResult<()> {
    let mut candidate = *point;
    candidate[31] &= 0x7f;
    for lo in LOW_ORDER_POINTS.iter() {
        let mut l = *lo;
        l[31] &= 0x7f;
        if candidate == l {
            return Err(AppError::Other(
                "rejected low-order x25519 key (possible small-subgroup attack)".into(),
            ));
        }
    }
    Ok(())
}

/// Reject an all-zero (contributory) shared secret, the tell-tale of a
/// degenerate DH even if a low-order encoding slipped past the list.
fn reject_zero_shared(shared: &[u8]) -> AppResult<()> {
    if shared.iter().all(|&b| b == 0) {
        return Err(AppError::Other(
            "rejected degenerate x25519 shared secret".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn seal_open_roundtrip() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let msg = b"a serialized DOM slate would go here";

        let sealed = seal(public.as_bytes(), msg).unwrap();
        let opened = open(&secret.to_bytes(), &sealed).unwrap();
        assert_eq!(&opened[..], msg);
    }

    #[test]
    fn wrong_key_fails() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let other = StaticSecret::random();

        let sealed = seal(public.as_bytes(), b"secret").unwrap();
        assert!(open(&other.to_bytes(), &sealed).is_err());
    }

    #[test]
    fn ciphertext_differs_each_time() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let a = seal(public.as_bytes(), b"x").unwrap();
        let b = seal(public.as_bytes(), b"x").unwrap();
        // Fresh ephemeral key ⇒ different bytes.
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_short_input() {
        let secret = StaticSecret::random();
        assert!(open(&secret.to_bytes(), b"tooshort").is_err());
    }

    #[test]
    fn rejects_low_order_recipient() {
        // Audit D-03: sealing to a known low-order point must be refused.
        let all_zero = [0u8; 32];
        assert!(seal(&all_zero, b"x").is_err());
        let one = {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        };
        assert!(seal(&one, b"x").is_err());
    }
}

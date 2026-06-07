//! Mode B descriptor — blinding-factor encryption.
//!
//! The receive descriptor (DOMRR1) carries the recipient's blinding factor so
//! the sender can build the output. That blinding factor MUST be encrypted with
//! a key only the recipient knows, or an interceptor could learn ownership
//! information (brief, security note). We seal it with ChaCha20Poly1305 under a
//! key derived from the recipient's wallet-scoped secret + a per-descriptor
//! nonce, so only the recipient's wallet can recover it.
//!
//! The owner key is provided by the caller (derived from the wallet master key;
//! see `wallet_manager`). We never hold the master key here.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

/// Encrypt a 32-byte blinding factor. Returns `nonce(12) ‖ ciphertext(48)`.
pub fn encrypt_blinding(owner_key: &[u8; 32], blinding: &[u8; 32]) -> AppResult<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let key = derive(owner_key, &nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), blinding.as_slice())
        .map_err(|_| AppError::Other("descriptor blinding encryption failed".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blinding factor produced by [`encrypt_blinding`].
pub fn decrypt_blinding(owner_key: &[u8; 32], sealed: &[u8]) -> AppResult<Zeroizing<[u8; 32]>> {
    if sealed.len() < 12 + 16 {
        return Err(AppError::Other("descriptor blinding blob too short".into()));
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let key = derive(owner_key, nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| AppError::Other("descriptor blinding decryption failed".into()))?;
    if pt.len() != 32 {
        return Err(AppError::Other("decrypted blinding is not 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(Zeroizing::new(out))
}

fn derive(owner_key: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), owner_key);
    let mut okm = [0u8; 32];
    hk.expand(b"dom-descriptor-blinding-v1", &mut okm)
        .expect("hkdf 32 bytes valid");
    okm
}

/// Transport-wrap the blinding for Mode B so that anyone holding the descriptor
/// (i.e. the sender, who must build the spend) can recover it. The wrapping key
/// derives from the descriptor's own `receiver_pub` — public material carried in
/// the same descriptor — so this is transport obfuscation, not access control.
/// Confidentiality against the channel is Mode A's job; Mode B is for trusted
/// channels and the UI says so. Returns `nonce(12) ‖ ciphertext(48)`.
pub fn wrap_blinding_for_transport(
    receiver_pub: &[u8; 32],
    blinding: &[u8; 32],
) -> AppResult<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let key = derive_transport(receiver_pub, &nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), blinding.as_slice())
        .map_err(|_| AppError::Other("descriptor blinding wrap failed".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Recover a transport-wrapped blinding (sender side).
pub fn unwrap_blinding_from_transport(
    receiver_pub: &[u8; 32],
    wrapped: &[u8],
) -> AppResult<Zeroizing<[u8; 32]>> {
    if wrapped.len() < 12 + 16 {
        return Err(AppError::Other("wrapped blinding too short".into()));
    }
    let (nonce_bytes, ct) = wrapped.split_at(12);
    let key = derive_transport(receiver_pub, nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| {
            AppError::Other("descriptor is invalid or corrupted (blinding unwrap failed)".into())
        })?;
    if pt.len() != 32 {
        return Err(AppError::Other("unwrapped blinding is not 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(Zeroizing::new(out))
}

fn derive_transport(receiver_pub: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(44);
    ikm.extend_from_slice(receiver_pub);
    ikm.extend_from_slice(nonce);
    let hk = Hkdf::<Sha256>::new(Some(nonce), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"dom-descriptor-transport-v1", &mut okm)
        .expect("hkdf 32 bytes valid");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let owner = [9u8; 32];
        let blinding = [3u8; 32];
        let sealed = encrypt_blinding(&owner, &blinding).unwrap();
        let out = decrypt_blinding(&owner, &sealed).unwrap();
        assert_eq!(*out, blinding);
    }

    #[test]
    fn wrong_owner_fails() {
        let sealed = encrypt_blinding(&[1u8; 32], &[2u8; 32]).unwrap();
        assert!(decrypt_blinding(&[8u8; 32], &sealed).is_err());
    }

    #[test]
    fn nonce_makes_ciphertext_unique() {
        let owner = [5u8; 32];
        let a = encrypt_blinding(&owner, &[7u8; 32]).unwrap();
        let b = encrypt_blinding(&owner, &[7u8; 32]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn transport_wrap_roundtrip() {
        // Anyone holding the descriptor (sender) can recover the blinding from
        // the public receiver_pub — that is the point of Mode B.
        let receiver_pub = [11u8; 32];
        let blinding = [4u8; 32];
        let wrapped = wrap_blinding_for_transport(&receiver_pub, &blinding).unwrap();
        let out = unwrap_blinding_from_transport(&receiver_pub, &wrapped).unwrap();
        assert_eq!(*out, blinding);
    }

    #[test]
    fn transport_unwrap_rejects_corrupt() {
        let receiver_pub = [1u8; 32];
        let mut wrapped = wrap_blinding_for_transport(&receiver_pub, &[2u8; 32]).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xff;
        assert!(unwrap_blinding_from_transport(&receiver_pub, &wrapped).is_err());
    }
}

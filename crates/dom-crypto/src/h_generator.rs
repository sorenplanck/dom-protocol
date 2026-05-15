// Allow missing docs during development
#![allow(missing_docs)]
//! H generator for DOM Pedersen commitments — full RFC9380 implementation.

use dom_core::DomError;
use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    AffinePoint, EncodedPoint, Secp256k1,
};
use sha2::Sha256;

const H2C_DST: &[u8] = b"DOM:h2c:secp256k1:v6.1";

const H_COMPRESSED_FINAL: [u8; 33] = [
    0x02, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1, 0x7b,
    0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b, 0x07, 0x8f, 0x09, 0xd5,
    0x50,
];

pub fn h_compressed() -> Result<[u8; 33], DomError> {
    let derived = derive_h_generator()?;
    if derived != H_COMPRESSED_FINAL {
        return Err(DomError::Internal(format!(
            "H_COMPRESSED_FINAL mismatch. Run: cargo test -p dom-crypto print_h_generator -- --nocapture\nDerived: {}\nHardcoded: {}",
            hex::encode(derived),
            hex::encode(H_COMPRESSED_FINAL),
        )));
    }
    verify_h_properties(&derived)?;
    Ok(derived)
}

pub fn derive_h_generator() -> Result<[u8; 33], DomError> {
    let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[b""], &[H2C_DST])
        .map_err(|e| DomError::Internal(format!("hash_to_curve failed: {e}")))?;
    let affine: AffinePoint = point.into();
    let encoded = EncodedPoint::from(affine);
    let compressed = encoded.compress();
    let bytes = compressed.as_bytes();
    if bytes.len() != 33 {
        return Err(DomError::Internal("H encoding error".into()));
    }
    let mut arr = [0u8; 33];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

pub fn verify_h_matches_derivation() -> Result<(), DomError> {
    let derived = derive_h_generator()?;
    if derived != H_COMPRESSED_FINAL {
        return Err(DomError::Internal(format!(
            "H_COMPRESSED_FINAL mismatch!\nhardcoded: {}\nderived:   {}\nUpdate h_generator.rs",
            hex::encode(H_COMPRESSED_FINAL),
            hex::encode(derived),
        )));
    }
    Ok(())
}

pub fn verify_h_properties(h: &[u8; 33]) -> Result<(), DomError> {
    use crate::keys::PublicKey;
    PublicKey::from_compressed_bytes(h)
        .map_err(|e| DomError::Invalid(format!("H not valid curve point: {e}")))?;
    if h[0] != 0x02 && h[0] != 0x03 {
        return Err(DomError::Invalid("H invalid prefix".into()));
    }
    const G: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    if h == &G {
        return Err(DomError::Invalid("H must not equal G".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h_derivation_is_deterministic() {
        let h1 = derive_h_generator().unwrap();
        let h2 = derive_h_generator().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn h_final_matches_derivation() {
        let derived = derive_h_generator().expect("derivation failed");
        assert_eq!(
            derived,
            H_COMPRESSED_FINAL,
            "Update H_COMPRESSED_FINAL to: {}",
            hex::encode(derived)
        );
    }

    #[test]
    fn h_satisfies_all_properties() {
        let h = derive_h_generator().unwrap();
        verify_h_properties(&h).unwrap();
    }

    #[test]
    fn h_not_equal_to_g() {
        let h = derive_h_generator().unwrap();
        let g = [
            0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        assert_ne!(h, g);
    }

    #[test]
    fn print_h_generator() {
        let h = derive_h_generator().unwrap();
        println!("\n=== DOM H Generator ===");
        println!("H hex: {}", hex::encode(h));
        println!("H bytes: {:?}", h);
    }
}

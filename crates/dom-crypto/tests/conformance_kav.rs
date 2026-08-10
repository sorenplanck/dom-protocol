//! KAV conformance — authoritative known-answer vectors against the SPEC,
//! never against the code's own output or memory.
//!
//! Two doors covered here. The third conformance door — RFC-6979 nonce — lives
//! as internal unit tests in src/schnorr.rs (rfc6979_nonce is crate-private and
//! unreachable from an integration test):
//!   schnorr::tests::rfc6979_nonce_core_matches_authoritative_secp256k1_vector
//!   schnorr::tests::fix012_blake2b_prehash_diverges_from_rfc6979_sha256_nonce
//!
//!   (1) **Blake2b-256 vs RFC-7693 / BLAKE2 reference.** DOM's consensus hash is
//!       `blake2b_256` (hash.rs:14): unkeyed BLAKE2b with a 32-byte (256-bit)
//!       digest. The authoritative empty-string digest for unkeyed BLAKE2b-256 is
//!       `0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8`
//!       (published widely; cross-confirmed against the BLAKE2 reference output
//!       size = 32). If DOM's hasher were misconfigured (wrong digest length,
//!       keyed mode, BLAKE2s instead of BLAKE2b, salt/personalization), this KAV
//!       goes RED. The `abc` vector is independently cross-checked with GNU
//!       `b2sum -l 256` and Python's `hashlib.blake2b(digest_size=32)`.
//!
//!   (2) **Hash-to-curve vs RFC-9380 Appendix J.8.1 (secp256k1_XMD:SHA-256_
//!       SSWU_RO_).** DOM derives its Pedersen H generator (h_generator.rs) via
//!       k256's RFC-9380 `hash_from_bytes::<ExpandMsgXmd<Sha256>>` — the same
//!       primitive, but with a DOM-specific DST. The H bytes themselves are
//!       frozen elsewhere (H_COMPRESSED_FINAL); what is NOT yet pinned is that
//!       the *underlying RFC-9380 implementation k256 ships* actually conforms to
//!       the RFC. We pin that directly: re-run k256's hash_to_curve with the RFC's
//!       own DST `QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_` and assert
//!       the resulting affine (x,y) equals the published Appendix J.8.1 vectors.
//!       If k256 bumps a dependency and its H2C drifts from RFC-9380, the DOM H
//!       derivation silently changes and this catches it at the primitive level.
//!
//! Sources (sourced from the spec, not the code):
//!   - BLAKE2b-256(""): published reference digest, output size 32.
//!   - RFC-9380 Appendix J.8.1 vectors: cfrg/draft-irtf-cfrg-hash-to-curve poc
//!     vectors `secp256k1_XMD:SHA-256_SSWU_RO_.json` (= RFC-9380 final).

use dom_crypto::blake2b_256;

// ── (1) Blake2b-256 conformance ─────────────────────────────────────────────

/// Authoritative empty-string digest for unkeyed BLAKE2b with 256-bit output.
const BLAKE2B_256_EMPTY: &str = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
const BLAKE2B_256_ABC: &str = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";

#[test]
fn blake2b_256_empty_matches_authoritative_vector() {
    let got = blake2b_256(b"");
    assert_eq!(
        hex::encode(got.as_bytes()),
        BLAKE2B_256_EMPTY,
        "blake2b_256(\"\") drifted from the authoritative BLAKE2b-256 digest — \
         check digest length (must be 32), keyed/salt/personal must be off, and \
         BLAKE2b (not BLAKE2s)"
    );
}

/// Independently cross-checked `abc` BLAKE2b-256 vector.
#[test]
fn blake2b_256_abc_matches_authoritative_vector() {
    let got = hex::encode(blake2b_256(b"abc").as_bytes());
    assert_eq!(
        got, BLAKE2B_256_ABC,
        "blake2b_256(\"abc\") drifted from the independently cross-checked vector"
    );
}

// ── (2) RFC-9380 secp256k1 hash_to_curve conformance ────────────────────────

mod rfc9380 {
    use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{AffinePoint, ProjectivePoint, Secp256k1};
    use sha2::Sha256;

    /// The RFC-9380 Appendix J.8.1 DST (NOT the DOM DST). Using the RFC's own DST
    /// is what makes the published (x,y) vectors applicable.
    const RFC9380_DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

    /// (msg, expected P.x hex, expected P.y hex) from RFC-9380 Appendix J.8.1.
    const VECTORS: &[(&[u8], &str, &str)] = &[
        (
            b"",
            "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
            "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
        ),
        (
            b"abc",
            "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
            "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
        ),
        (
            b"abcdef0123456789",
            "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
            "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828",
        ),
    ];

    #[test]
    fn k256_hash_to_curve_matches_rfc9380_secp256k1_vectors() {
        for (msg, exp_x, exp_y) in VECTORS {
            let point: ProjectivePoint =
                Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[RFC9380_DST])
                    .expect("hash_to_curve must succeed");
            let affine: AffinePoint = point.into();
            // Uncompressed SEC1: 0x04 || X(32) || Y(32).
            let enc = affine.to_encoded_point(false);
            let bytes = enc.as_bytes();
            assert_eq!(bytes.len(), 65, "expected uncompressed SEC1 (65 bytes)");
            let got_x = hex::encode(&bytes[1..33]);
            let got_y = hex::encode(&bytes[33..65]);
            assert_eq!(
                &got_x,
                exp_x,
                "RFC-9380 secp256k1 H2C x-coord drift for msg={:?}: k256 no longer \
                 conforms to RFC-9380 — DOM H derivation is affected",
                String::from_utf8_lossy(msg)
            );
            assert_eq!(
                &got_y,
                exp_y,
                "RFC-9380 secp256k1 H2C y-coord drift for msg={:?}",
                String::from_utf8_lossy(msg)
            );
        }
    }
}

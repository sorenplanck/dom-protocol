//! Bulletproofs range proofs via secp256k1-zkp.
//!
//! Prova que commitment C encoda v ∈ [0, 2^52) sem revelar v.
//! Range máximo: 2^52 noms ≈ 45M DOM > MAX_SUPPLY_DOM (~32M DOM).
//!
//! O Generator é derivado deterministicamente de H_DOM_X via Tag.
//! Commitment e RangeProof usam o mesmo Generator — binding garantido.

use dom_core::DomError;
use secp256k1_zkp::{
    global::SECP256K1, rand::thread_rng, Generator, PedersenCommitment as ZkpCommit,
    RangeProof as ZkpRangeProof, SecretKey, Tweak,
};

/// H_DOM compressed (RFC9380, DST="DOM:h2c:secp256k1:v6.1").
/// Verificado em h_generator::tests::h_final_matches_derivation.
#[allow(dead_code)]
const H_DOM_COMPRESSED: [u8; 33] = [
    0x02, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1, 0x7b,
    0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b, 0x07, 0x8f, 0x09, 0xd5,
    0x50,
];

/// Coordenada x de H_DOM — usada como Tag para derivar o Generator.
const H_DOM_X: [u8; 32] = [
    0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1, 0x7b, 0x99,
    0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b, 0x07, 0x8f, 0x09, 0xd5, 0x50,
];

/// Valor máximo provável: 2^52 - 1 noms ≈ 45M DOM.
/// Valores acima deste limite estão fora do supply DOM e não precisam de prova.
pub const MAX_PROVABLE_VALUE: u64 = (1u64 << 52) - 1;

/// Legacy borromean range-proof byte cap. This module is the LEGACY borromean
/// path, retired from production (generation and verification now use the
/// standard Bulletproof `bp2_*` path / `bulletproof_bp`). Borromean proofs are
/// ~4166 bytes, so this module keeps its own cap rather than the consensus
/// `dom_core::MAX_PROOF_SIZE` (now sized to the 675-byte Bulletproof). Used only
/// by this module's prove/verify/tests; not a consensus parameter.
const LEGACY_BORROMEAN_MAX_PROOF_SIZE: usize = 6_144;

/// Generator DOM derivado de H_DOM_X via Generator::from_slice (prefix 0x0a).
///
/// Esta é a forma correta de carregar o H canônico do DOM no contexto zkp.
/// `Tag::from(H_X)` produzia um ponto diferente porque o algoritmo de Tag
/// re-deriva via hash, não reconstrói o ponto a partir de X. Usar
/// Generator::from_slice com prefixo 0x0a aceita H_X como coordenada x
/// direta e reconstrói o ponto canônico que coincide com Pedersen via k256.
fn dom_generator() -> Generator {
    let mut h_bytes = [0u8; 33];
    h_bytes[0] = 0x0a;
    h_bytes[1..].copy_from_slice(&H_DOM_X);
    Generator::from_slice(&h_bytes).expect("H_DOM_X is a valid x-coordinate on secp256k1")
}

/// SEC1<->zkp commitment encoding now lives in [`crate::sec1_zkp_bridge`] — the
/// single source of truth shared with the standard-Bulletproof path. These
/// imports preserve the original call sites (`sec1_to_zkp(..)` / `zkp_to_sec1(..)`).
use crate::sec1_zkp_bridge::{sec1_to_zkp, zkp_to_sec1};

#[cfg(test)]
mod format_conversion_tests {
    use super::*;
    use crate::pedersen::{BlindingFactor, Commitment};
    use secp256k1_zkp::{global::SECP256K1, Generator, PedersenCommitment as ZkpCommit, Tweak};

    #[test]
    fn roundtrip_sec1_zkp_sec1_100_samples() {
        for i in 0..100 {
            let r = BlindingFactor::random();
            let original_sec1 = Commitment::commit((i as u64) * 1_000_000, &r);
            let sec1_bytes = *original_sec1.as_bytes();

            let zkp_bytes = sec1_to_zkp(&sec1_bytes).unwrap();
            let recovered_sec1 = zkp_to_sec1(&zkp_bytes).unwrap();

            assert_eq!(
                sec1_bytes, recovered_sec1,
                "Roundtrip SEC1→zkp→SEC1 failed at i={}",
                i
            );
        }
    }

    #[test]
    fn roundtrip_zkp_sec1_zkp_100_samples() {
        let mut h_bytes = [0u8; 33];
        h_bytes[0] = 0x0a;
        h_bytes[1..].copy_from_slice(&H_DOM_X);
        let gen = Generator::from_slice(&h_bytes).unwrap();

        for i in 0..100 {
            let r = BlindingFactor::random();
            let tweak = Tweak::from_slice(r.as_bytes()).unwrap();
            let zkp_commit = ZkpCommit::new(SECP256K1, (i as u64) * 1_000_000, tweak, gen);
            let original_zkp = zkp_commit.serialize();

            let sec1_bytes = zkp_to_sec1(&original_zkp).unwrap();
            let recovered_zkp = sec1_to_zkp(&sec1_bytes).unwrap();

            assert_eq!(
                original_zkp, recovered_zkp,
                "Roundtrip zkp→SEC1→zkp failed at i={}",
                i
            );
        }
    }
}

fn zkp_commit(value: u64, blinding: &[u8; 32]) -> Result<ZkpCommit, DomError> {
    let tweak = Tweak::from_slice(blinding)
        .map_err(|e| DomError::Invalid(format!("blinding inválido: {e}")))?;
    Ok(ZkpCommit::new(SECP256K1, value, tweak, dom_generator()))
}

/// Range proof DOM — prova que v ∈ [0, 2^52).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    /// Bytes serializados do range proof.
    pub bytes: Vec<u8>,
}

impl RangeProof {
    /// Parse e valida range proof a partir de bytes brutos.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, DomError> {
        if bytes.is_empty() {
            return Err(DomError::Malformed("range proof vazio".into()));
        }
        if bytes.len() > LEGACY_BORROMEAN_MAX_PROOF_SIZE {
            return Err(DomError::Malformed(format!(
                "range proof {} bytes > LEGACY_BORROMEAN_MAX_PROOF_SIZE {}",
                bytes.len(),
                LEGACY_BORROMEAN_MAX_PROOF_SIZE
            )));
        }
        Ok(Self { bytes })
    }
}

/// Gera range proof para (value, blinding).
/// Retorna (proof, commitment_bytes[33]).
/// Prove with an explicit nonce — for deterministic proofs (e.g. genesis).
///
/// The 32-byte nonce must be uniformly random in normal use; this variant
/// exists so callers can derive it deterministically when reproducibility
/// across nodes is required.
pub fn prove_with_nonce(
    value: u64,
    blinding: &crate::pedersen::BlindingFactor,
    nonce_bytes: &[u8; 32],
) -> Result<(RangeProof, [u8; 33]), DomError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(format!(
            "value {value} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        )));
    }
    let generator = dom_generator();
    let commit = zkp_commit(value, blinding.as_bytes())?;
    let commit_bytes = commit.serialize();
    let nonce_sk = SecretKey::from_slice(nonce_bytes)
        .map_err(|e| DomError::Invalid(format!("nonce inválido: {e}")))?;
    let tweak = Tweak::from_slice(blinding.as_bytes())
        .map_err(|e| DomError::Invalid(format!("blinding inválido: {e}")))?;
    let proof = ZkpRangeProof::new(
        SECP256K1,
        0,
        commit,
        value,
        tweak,
        b"DOM:bulletproof:v1",
        b"",
        nonce_sk,
        0,
        52,
        generator,
    )
    .map_err(|e| DomError::Internal(format!("range proof falhou: {e}")))?;
    let proof_bytes = proof.serialize();
    let sec1_bytes = zkp_to_sec1(&commit_bytes)?;
    Ok((RangeProof::from_bytes(proof_bytes)?, sec1_bytes))
}

/// Generate a Bulletproof+ range proof for (value, blinding) with a random nonce.
pub fn prove(
    value: u64,
    blinding: &crate::pedersen::BlindingFactor,
) -> Result<(RangeProof, [u8; 33]), DomError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(format!(
            "value {value} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        )));
    }

    let generator = dom_generator();
    let commit = zkp_commit(value, blinding.as_bytes())?;
    let commit_bytes = commit.serialize();

    let nonce_sk = SecretKey::new(&mut thread_rng());
    let tweak = Tweak::from_slice(blinding.as_bytes())
        .map_err(|e| DomError::Invalid(format!("blinding inválido: {e}")))?;

    let proof = ZkpRangeProof::new(
        SECP256K1,
        0,
        commit,
        value,
        tweak,
        b"DOM:bulletproof:v1",
        b"",
        nonce_sk,
        0,
        52,
        generator,
    )
    .map_err(|e| DomError::Internal(format!("range proof falhou: {e}")))?;

    let proof_bytes = proof.serialize();
    let sec1_bytes = zkp_to_sec1(&commit_bytes)?;
    Ok((RangeProof::from_bytes(proof_bytes)?, sec1_bytes))
}

/// Read a range proof's advertised `[min_value, max_value]` bounds directly from
/// its header bytes, via libsecp256k1's `secp256k1_rangeproof_info`.
///
/// This is the overflow-SAFE counterpart to the upstream `RangeProof::verify`,
/// which returns `Range { end: max_value + 1, .. }` and therefore overflows
/// (panics under `overflow-checks = true`; aborts under `panic = "abort"`) for a
/// 64-bit proof reporting `max_value == u64::MAX` (R-07 F-02). `rangeproof_info`
/// hands back the raw bounds with no `+ 1`, so `verify()` can bound-check the
/// proof BEFORE ever calling the panicking upstream path.
///
/// Returns `None` when the proof header cannot be parsed (FFI returns 0); the
/// caller treats that as a malformed/invalid proof.
#[allow(unsafe_code)] // minimal read-only FFI: inspect the proof header, no mutation
fn rangeproof_info_bounds(proof_bytes: &[u8]) -> Option<(u64, u64)> {
    let mut exp: i32 = 0;
    let mut mantissa: i32 = 0;
    let mut min_value: u64 = 0;
    let mut max_value: u64 = 0;
    // SAFETY: every out-param points at a live local; `proof_bytes` is a valid
    // slice of length `proof_bytes.len()`; `secp256k1_context_no_precomp` is the
    // static no-precomputation context this function pointer is documented to
    // accept. `secp256k1_rangeproof_info` only reads `proof_bytes` and writes the
    // four out-params, returning 1 on success / 0 on a malformed proof.
    let ret = unsafe {
        secp256k1_zkp::ffi::secp256k1_rangeproof_info(
            secp256k1_zkp::ffi::secp256k1_context_no_precomp,
            &mut exp,
            &mut mantissa,
            &mut min_value,
            &mut max_value,
            proof_bytes.as_ptr(),
            proof_bytes.len(),
        )
    };
    if ret == 1 {
        Some((min_value, max_value))
    } else {
        None
    }
}

/// Verifica range proof dado commitment bytes (33 bytes).
pub fn verify(commitment_bytes: &[u8; 33], proof_bytes: &[u8]) -> Result<bool, DomError> {
    if proof_bytes.is_empty() {
        return Err(DomError::Malformed("range proof vazio".into()));
    }
    if proof_bytes.len() > LEGACY_BORROMEAN_MAX_PROOF_SIZE {
        return Err(DomError::Malformed(format!(
            "range proof muito grande: {} bytes",
            proof_bytes.len()
        )));
    }

    let generator = dom_generator();

    let zkp_bytes = sec1_to_zkp(commitment_bytes)?;
    let zkp_commit = ZkpCommit::from_slice(&zkp_bytes)
        .map_err(|e| DomError::Invalid(format!("commitment inválido: {e}")))?;

    let zkp_proof = ZkpRangeProof::from_slice(proof_bytes)
        .map_err(|e| DomError::Malformed(format!("proof malformado: {e}")))?;

    // R-07 (F-01 soundness + F-02 remote-crash DoS): bound-check the proof's
    // advertised range BEFORE calling the upstream verify(). The upstream path
    // computes `max_value + 1`, which overflows -> abort for a 64-bit proof
    // (max_value == u64::MAX). Reading the bounds here with the overflow-safe
    // rangeproof_info lets us reject any proof whose declared range escapes
    // [0, 2^52) before that overflow can be reached. An honest prover only ever
    // emits 52-bit proofs of values <= MAX_PROVABLE_VALUE (see prove()), so this
    // rejects nothing legitimate while (a) enforcing the upper bound the verifier
    // previously ignored (it only checked range.start == 0) and (b) closing the
    // DoS. A proof whose header cannot even be parsed is treated as invalid.
    let (_min_value, max_value) = match rangeproof_info_bounds(proof_bytes) {
        Some(bounds) => bounds,
        None => return Ok(false),
    };
    if max_value > MAX_PROVABLE_VALUE {
        return Ok(false);
    }

    match zkp_proof.verify(SECP256K1, zkp_commit, b"", generator) {
        // Defense in depth: re-assert the bound on the verified range. The `+ 1`
        // here cannot overflow because max_value <= MAX_PROVABLE_VALUE < u64::MAX
        // was enforced above.
        Ok(range) => Ok(range.start == 0 && range.end <= MAX_PROVABLE_VALUE + 1),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::BlindingFactor;

    #[test]
    fn h_dom_binding_verified() {
        use crate::h_generator::h_compressed;
        let h = h_compressed().expect("H deve estar finalizado");
        assert_eq!(
            h, H_DOM_COMPRESSED,
            "H_DOM diverge! Atualizar H_DOM_COMPRESSED: {:?}",
            h
        );
    }

    #[test]
    fn generator_is_deterministic() {
        let g1 = dom_generator();
        let g2 = dom_generator();
        assert_eq!(g1.serialize(), g2.serialize());
    }

    #[test]
    fn prove_verify_roundtrip_small() {
        let bf = BlindingFactor::random();
        let (proof, commit_bytes) = prove(100, &bf).unwrap();
        assert!(verify(&commit_bytes, &proof.bytes).unwrap());
    }

    #[test]
    fn prove_verify_zero() {
        let bf = BlindingFactor::random();
        let (proof, commit_bytes) = prove(0, &bf).unwrap();
        assert!(verify(&commit_bytes, &proof.bytes).unwrap());
    }

    #[test]
    fn prove_verify_max_supply() {
        // MAX_SUPPLY_DOM em noms — deve caber em 2^52
        let bf = BlindingFactor::random();
        let max_supply = dom_core::MAX_SUPPLY_NOMS;
        assert!(
            max_supply <= MAX_PROVABLE_VALUE,
            "MAX_SUPPLY_NOMS {max_supply} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        );
        let (proof, commit_bytes) = prove(max_supply, &bf).unwrap();
        assert!(verify(&commit_bytes, &proof.bytes).unwrap());
    }

    #[test]
    fn wrong_commitment_fails_verify() {
        let bf = BlindingFactor::random();
        let (proof, _) = prove(500, &bf).unwrap();
        let bf2 = BlindingFactor::random();
        let (_, wrong_bytes) = prove(501, &bf2).unwrap();
        let valid = verify(&wrong_bytes, &proof.bytes).unwrap_or(false);
        assert!(!valid);
    }

    #[test]
    fn empty_proof_rejected() {
        let commit_bytes = [0x02u8; 33];
        assert!(verify(&commit_bytes, &[]).is_err());
    }

    #[test]
    fn proof_size_within_limit() {
        let bf = BlindingFactor::random();
        let (proof, _) = prove(369, &bf).unwrap();
        assert!(
            proof.bytes.len() <= LEGACY_BORROMEAN_MAX_PROOF_SIZE,
            "proof {} bytes > LEGACY_BORROMEAN_MAX_PROOF_SIZE {}",
            proof.bytes.len(),
            LEGACY_BORROMEAN_MAX_PROOF_SIZE
        );
        println!("RangeProof size: {} bytes", proof.bytes.len());
    }

    #[test]
    fn value_above_max_rejected() {
        let bf = BlindingFactor::random();
        assert!(prove(MAX_PROVABLE_VALUE + 1, &bf).is_err());
    }

    // ── R-07 (F-01 soundness + F-02 remote-crash DoS) ─────────────────────────

    /// Build a range proof with an explicit `min_bits` width, bypassing prove()'s
    /// MAX_PROVABLE_VALUE cap. This lets tests exercise the verifier against proof
    /// widths an honest prover never emits. `min_bits = 64` makes libsecp256k1
    /// report `max_value = u64::MAX`, the exact input that overflows upstream
    /// `verify()`'s `max_value + 1` (R-07 phase 1).
    fn build_wide_proof(
        value: u64,
        blinding: &BlindingFactor,
        min_bits: u8,
    ) -> (Vec<u8>, [u8; 33]) {
        let generator = dom_generator();
        let commit = zkp_commit(value, blinding.as_bytes()).expect("commit");
        let commit_bytes = commit.serialize();
        let nonce_sk = SecretKey::new(&mut thread_rng());
        let tweak = Tweak::from_slice(blinding.as_bytes()).expect("tweak");
        let proof = ZkpRangeProof::new(
            SECP256K1,
            0,
            commit,
            value,
            tweak,
            b"DOM:bulletproof:v1",
            b"",
            nonce_sk,
            0,
            min_bits,
            generator,
        )
        .expect("wide proof");
        let sec1 = zkp_to_sec1(&commit_bytes).expect("zkp->sec1");
        (proof.serialize(), sec1)
    }

    /// Read the proof's implied `[min_value, max_value]` via the raw FFI
    /// `secp256k1_rangeproof_info` (no `+1`, so overflow-safe). Lets tests assert
    /// the F-02 precondition without aborting the process.
    #[allow(unsafe_code)] // raw FFI to inspect proof header; see rangeproof_info_bounds
    fn proof_info(proof_bytes: &[u8]) -> (u64, u64) {
        let mut exp: i32 = 0;
        let mut mantissa: i32 = 0;
        let mut min_value: u64 = 0;
        let mut max_value: u64 = 0;
        let ret = unsafe {
            secp256k1_zkp::ffi::secp256k1_rangeproof_info(
                secp256k1_zkp::ffi::secp256k1_context_no_precomp,
                &mut exp,
                &mut mantissa,
                &mut min_value,
                &mut max_value,
                proof_bytes.as_ptr(),
                proof_bytes.len(),
            )
        };
        assert_eq!(ret, 1, "rangeproof_info must parse the constructed proof");
        (min_value, max_value)
    }

    /// F-02 precondition: a 64-bit-wide proof's `max_value` is `u64::MAX`, so the
    /// upstream `verify()` doing `max_value + 1` overflows. Runs cleanly (no `+1`).
    #[test]
    fn f02_precondition_64bit_proof_max_value_is_u64_max() {
        let bf = BlindingFactor::random();
        let (proof_bytes, _sec1) = build_wide_proof(1_000, &bf, 64);
        let (min_value, max_value) = proof_info(&proof_bytes);
        assert_eq!(min_value, 0, "min_value should be 0");
        assert_eq!(
            max_value,
            u64::MAX,
            "64-bit proof must imply max_value = u64::MAX (the +1 overflow input)"
        );
    }

    /// F-02 fixed: the 64-bit proof that aborted bp_verify before R-07 (overflow
    /// at upstream `max_value + 1`) now returns `Ok(false)` — the guard rejects it
    /// before the overflowing path runs. If this test ever aborts, the guard
    /// regressed.
    #[test]
    fn robustness_verify_64bit_proof_does_not_abort() {
        let bf = BlindingFactor::random();
        let (proof_bytes, sec1) = build_wide_proof(1_000, &bf, 64);
        // Sanity: this proof really is the F-02 input (max_value == u64::MAX).
        assert_eq!(proof_info(&proof_bytes).1, u64::MAX);
        let r = verify(&sec1, &proof_bytes);
        assert_eq!(
            r,
            Ok(false),
            "64-bit proof must be rejected with Ok(false), not abort / not Ok(true)"
        );
    }

    /// F-01 fixed: a proof whose declared range exceeds [0, 2^52) is rejected even
    /// when its committed value and signature are internally valid. Here a 53-bit
    /// proof of a value above MAX_PROVABLE_VALUE -> Ok(false).
    #[test]
    fn robustness_verify_rejects_value_above_2pow52() {
        let bf = BlindingFactor::random();
        let value = (1u64 << 52) + 12_345; // > MAX_PROVABLE_VALUE, fits in 53 bits
        let (proof_bytes, sec1) = build_wide_proof(value, &bf, 53);
        // The proof's declared upper bound escapes [0, 2^52).
        assert!(
            proof_info(&proof_bytes).1 > MAX_PROVABLE_VALUE,
            "fixture must declare a range above MAX_PROVABLE_VALUE"
        );
        assert_eq!(
            verify(&sec1, &proof_bytes),
            Ok(false),
            "a >2^52 range proof must be rejected (F-01)"
        );
    }

    /// CRITICAL non-regression: every proof an honest prove() can emit must still
    /// verify Ok(true) after the guard — including the exact upper boundary
    /// MAX_PROVABLE_VALUE (2^52-1), zero, max supply, and random valid values.
    /// This proves the guard rejects nothing legitimate (it only tightens).
    #[test]
    fn nonregression_all_honest_proofs_still_verify() {
        use secp256k1_zkp::rand::Rng;

        let fixed = [
            0u64,
            1,
            2,
            1_000,
            1u64 << 20,
            1u64 << 40,
            1u64 << 51,
            dom_core::MAX_SUPPLY_NOMS,
            MAX_PROVABLE_VALUE - 1,
            MAX_PROVABLE_VALUE, // 2^52 - 1, the exact accepted upper boundary
        ];
        for &v in &fixed {
            let bf = BlindingFactor::random();
            let (proof, commit) = prove(v, &bf).expect("honest prove");
            assert_eq!(
                verify(&commit, &proof.bytes),
                Ok(true),
                "honest proof of value {v} must verify after the guard"
            );
        }

        let mut rng = thread_rng();
        for _ in 0..32 {
            let v = rng.gen_range(0..=MAX_PROVABLE_VALUE);
            let bf = BlindingFactor::random();
            let (proof, commit) = prove(v, &bf).expect("honest prove");
            assert_eq!(
                verify(&commit, &proof.bytes),
                Ok(true),
                "random honest proof of value {v} must verify after the guard"
            );
        }
    }
}

#[cfg(test)]
mod phase1_verification {
    use super::*;
    use crate::pedersen::{BlindingFactor, Commitment};

    /// The original test that found the bug. With dom_generator() now using
    /// Generator::from_slice(&[0x0a, H_X]) instead of Tag::from(H_X), the X
    /// coordinates of both commitments must match. The prefix byte still
    /// differs (SEC1 0x02/0x03 vs zkp 0x08/0x09) — that's Phase 2.
    #[test]
    fn pedersen_and_bulletproof_use_same_generator() {
        let r = BlindingFactor::random();
        let value: u64 = 1_000_000_000;

        let pedersen_sec1 = Commitment::commit(value, &r);
        let (_proof, bp_commit_sec1) = prove(value, &r).expect("bp_prove failed");

        let pedersen_bytes = pedersen_sec1.as_bytes();

        println!("Pedersen (SEC1): {}", hex::encode(pedersen_bytes));
        println!("Bulletproof    : {}", hex::encode(bp_commit_sec1));

        // After Phase 2, both should be in SEC1 format and match exactly
        assert_eq!(
            pedersen_bytes, &bp_commit_sec1,
            "Commitments must match exactly — both use H_DOM in SEC1 format"
        );
    }
}

#[cfg(test)]
mod bridge_edge_case_tests {
    // AUDIT-002: These tests sample the SEC1<->zkp bridge and the is_square oracle
    // equivalence (currently 1000+ random scalars plus edge-case values, with zero
    // mismatches) — strong evidence, but NOT a proof. Closing this fully requires a
    // complete mathematical proof of the is_square equivalence across the entire
    // domain, beyond sampling. That proof is pending (pre-mainnet); the equivalence
    // is currently evidenced, not proven.
    use super::*;
    use crate::pedersen::{BlindingFactor, Commitment};

    /// Blindings that are valid secp256k1 scalars (nonzero, < curve order n).
    /// `[0xff; 32]` and `[0u8; 32]` are intentionally NOT here — they are
    /// rejected by `BlindingFactor::from_bytes` (see `invalid_blindings_rejected`).
    fn edge_blindings() -> Vec<BlindingFactor> {
        let mut last_byte_one = [0u8; 32];
        last_byte_one[31] = 1;
        let mut v = vec![
            BlindingFactor::from_bytes(last_byte_one).expect("last-byte-1 is a valid scalar"),
            // 0xEE..EE < n (n starts 0xFFFFFFFF..), a valid high scalar standing
            // in for the audit's [0xff;32], which is out of range.
            BlindingFactor::from_bytes([0xee; 32]).expect("0xee..ee < n is a valid scalar"),
        ];
        for _ in 0..10 {
            v.push(BlindingFactor::random());
        }
        v
    }

    /// 1. Cross-validate the is_square bridge + prove/verify for edge-case values
    ///    and blindings that 200 random samples are unlikely to hit.
    #[test]
    fn edge_value_blinding_bridge_roundtrip_and_prove_verify() {
        let values = [
            0u64,
            1,
            MAX_PROVABLE_VALUE, // 2^52 - 1
            dom_core::MAX_SUPPLY_NOMS,
        ];
        for &value in &values {
            for r in edge_blindings() {
                // (a) Pedersen commitment -> SEC1 bytes.
                let sec1 = *Commitment::commit(value, &r).as_bytes();

                // (b,c) SEC1 -> zkp -> SEC1 must be byte-identical.
                let zkp = sec1_to_zkp(&sec1).expect("sec1->zkp");
                let back = zkp_to_sec1(&zkp).expect("zkp->sec1");
                assert_eq!(sec1, back, "bridge roundtrip drift at value={value}");

                // bulletproof prove() must yield the same SEC1 commitment as
                // Pedersen (single H, single generator).
                let (proof, bp_sec1) = prove(value, &r).expect("prove");
                assert_eq!(sec1, bp_sec1, "pedersen vs bulletproof commitment drift");

                // (d) prove + verify round-trips.
                assert!(
                    verify(&bp_sec1, &proof.bytes).expect("verify"),
                    "valid proof must verify at value={value}"
                );

                // (e) single-bit mutation of the commitment must NOT verify.
                let mut mutated = bp_sec1;
                mutated[17] ^= 0x01; // flip a bit inside the X coordinate
                assert!(
                    !matches!(verify(&mutated, &proof.bytes), Ok(true)),
                    "single-bit-mutated commitment must not verify (value={value})"
                );
            }
        }
    }

    /// Out-of-range / zero blindings are rejected, not silently accepted.
    #[test]
    fn invalid_blindings_rejected() {
        assert!(
            BlindingFactor::from_bytes([0xff; 32]).is_err(),
            "0xff..ff > curve order n must be rejected"
        );
        assert!(
            BlindingFactor::from_bytes([0u8; 32]).is_err(),
            "zero blinding must be rejected"
        );
    }

    /// 2. H generator unification: the bulletproof generator and the documented
    ///    H_DOM compressed point must be the SAME curve point — asserted by full
    ///    [u8;33] byte-equality of H in SEC1 plus X-coordinate equality of the
    ///    zkp generator, not merely an X match in a single representation.
    #[test]
    fn h_generator_unification_byte_equality() {
        // The zkp generator serializes as 0x0a/0x0b || X. Its X must be H_DOM_X.
        let gen_ser = dom_generator().serialize();
        let gen_x: [u8; 32] = gen_ser[1..].try_into().expect("33-byte generator");
        assert_eq!(gen_x, H_DOM_X, "bulletproof generator X must equal H_DOM_X");
        assert_eq!(
            &H_DOM_COMPRESSED[1..],
            &H_DOM_X[..],
            "H_DOM_COMPRESSED X must equal H_DOM_X"
        );
        // The Pedersen H, in SEC1, must equal the hard-coded H_DOM_COMPRESSED
        // byte-for-byte (full 33 bytes, prefix included).
        let h_sec1 = crate::h_generator::h_compressed().expect("H must be finalized");
        assert_eq!(
            h_sec1, H_DOM_COMPRESSED,
            "Pedersen H (SEC1) must equal hard-coded H_DOM_COMPRESSED byte-for-byte"
        );
    }

    /// 3. sec1<->zkp round-trip for >= 1000 random scalars (extends the existing
    ///    100-sample format_conversion_tests).
    #[test]
    fn bridge_roundtrip_1000_random_scalars() {
        for i in 0..1000u64 {
            let r = BlindingFactor::random();
            let sec1 = *Commitment::commit(i.wrapping_mul(1_000_003), &r).as_bytes();
            let zkp = sec1_to_zkp(&sec1).expect("sec1->zkp");
            let back = zkp_to_sec1(&zkp).expect("zkp->sec1");
            assert_eq!(sec1, back, "bridge roundtrip drift at sample {i}");
        }
    }
}

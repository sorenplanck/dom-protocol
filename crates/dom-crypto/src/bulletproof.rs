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

/// Cria PedersenCommitment zkp a partir de value + blinding.
use k256::FieldElement;
use secp256k1::PublicKey as Secp256k1PublicKey;

/// Convert SEC1 commitment (0x02/0x03 prefix) to zkp format (0x08/0x09).
///
/// SEC1 encodes y-parity (even/odd) in the prefix byte. zkp encodes is_square(y)
/// (whether y is a quadratic residue mod p). We use k256::FieldElement::sqrt as
/// the is_square oracle.
fn sec1_to_zkp(sec1_bytes: &[u8; 33]) -> Result<[u8; 33], DomError> {
    let pk = Secp256k1PublicKey::from_slice(sec1_bytes)
        .map_err(|e| DomError::Invalid(format!("invalid SEC1: {e}")))?;

    let uncompressed = pk.serialize_uncompressed();
    let y_bytes: [u8; 32] = uncompressed[33..65].try_into().unwrap();
    let y_field = FieldElement::from_bytes(&y_bytes.into())
        .expect("Y from valid point is valid field element");

    let is_square: bool = y_field.sqrt().is_some().into();
    let zkp_prefix = if is_square { 0x08 } else { 0x09 };

    let mut zkp_bytes = *sec1_bytes;
    zkp_bytes[0] = zkp_prefix;
    Ok(zkp_bytes)
}

/// Convert zkp commitment (0x08/0x09 prefix) to SEC1 format (0x02/0x03).
///
/// The zkp serialization encodes is_square(y) in the prefix byte but does not
/// directly expose Y's parity. To determine the correct SEC1 prefix (0x02 for
/// y-even, 0x03 for y-odd), we must reconstruct the point and validate which
/// prefix produces a Y coordinate matching the zkp's is_square encoding.
///
/// This loop is mathematically necessary (not trial-and-error): given X, there
/// are exactly 2 possible Y values (Y and -Y), encoded by SEC1's 0x02/0x03.
/// Exactly one of these will have is_square(Y) matching the zkp prefix.
fn zkp_to_sec1(zkp_bytes: &[u8; 33]) -> Result<[u8; 33], DomError> {
    // Validate zkp format first
    let x_bytes: [u8; 32] = zkp_bytes[1..].try_into().unwrap();
    let _ = secp256k1_zkp::PedersenCommitment::from_slice(zkp_bytes)
        .map_err(|e| DomError::Invalid(format!("invalid zkp: {e}")))?;

    // Try both SEC1 prefixes (0x02 and 0x03)
    for &prefix in &[0x02_u8, 0x03_u8] {
        let mut sec1_bytes = [0u8; 33];
        sec1_bytes[0] = prefix;
        sec1_bytes[1..].copy_from_slice(&x_bytes);

        if let Ok(pk) = Secp256k1PublicKey::from_slice(&sec1_bytes) {
            let uncompressed = pk.serialize_uncompressed();
            let y: [u8; 32] = uncompressed[33..65].try_into().unwrap();
            let y_field = FieldElement::from_bytes(&y.into()).expect("valid Y");
            let is_square: bool = y_field.sqrt().is_some().into();
            let expected_zkp = if is_square { 0x08 } else { 0x09 };

            if expected_zkp == zkp_bytes[0] {
                return Ok(sec1_bytes);
            }
        }
    }

    // Invariant: one of the two prefixes MUST succeed for valid zkp input
    Err(DomError::Internal("zkp→SEC1: no valid prefix found".into()))
}

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
        if bytes.len() > dom_core::MAX_PROOF_SIZE {
            return Err(DomError::Malformed(format!(
                "range proof {} bytes > MAX_PROOF_SIZE {}",
                bytes.len(),
                dom_core::MAX_PROOF_SIZE
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

/// Verifica range proof dado commitment bytes (33 bytes).
pub fn verify(commitment_bytes: &[u8; 33], proof_bytes: &[u8]) -> Result<bool, DomError> {
    if proof_bytes.is_empty() {
        return Err(DomError::Malformed("range proof vazio".into()));
    }
    if proof_bytes.len() > dom_core::MAX_PROOF_SIZE {
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

    match zkp_proof.verify(SECP256K1, zkp_commit, b"", generator) {
        Ok(range) => Ok(range.start == 0),
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
            proof.bytes.len() <= dom_core::MAX_PROOF_SIZE,
            "proof {} bytes > MAX_PROOF_SIZE {}",
            proof.bytes.len(),
            dom_core::MAX_PROOF_SIZE
        );
        println!("RangeProof size: {} bytes", proof.bytes.len());
    }

    #[test]
    fn value_above_max_rejected() {
        let bf = BlindingFactor::random();
        assert!(prove(MAX_PROVABLE_VALUE + 1, &bf).is_err());
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

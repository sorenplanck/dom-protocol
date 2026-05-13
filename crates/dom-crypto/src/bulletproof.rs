//! Bulletproofs range proofs via secp256k1-zkp.
//!
//! Prova que commitment C encoda v ∈ [0, 2^52) sem revelar v.
//! Range máximo: 2^52 noms ≈ 45M DOM > MAX_SUPPLY_DOM (~32M DOM).
//!
//! O Generator é derivado deterministicamente de H_DOM_X via Tag.
//! Commitment e RangeProof usam o mesmo Generator — binding garantido.

use dom_core::DomError;
use secp256k1_zkp::{
    global::SECP256K1,
    rand::thread_rng,
    Generator, PedersenCommitment as ZkpCommit,
    RangeProof as ZkpRangeProof,
    SecretKey, Tag, Tweak,
};

/// H_DOM compressed (RFC9380, DST="DOM:h2c:secp256k1:v6.1").
/// Verificado em h_generator::tests::h_final_matches_derivation.
const H_DOM_COMPRESSED: [u8; 33] = [
    0x02, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45,
    0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1, 0x7b,
    0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb,
    0x3e, 0xa6, 0x21, 0x7b, 0x07, 0x8f, 0x09, 0xd5, 0x50,
];

/// Coordenada x de H_DOM — usada como Tag para derivar o Generator.
const H_DOM_X: [u8; 32] = [
    0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f,
    0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1, 0x7b, 0x99,
    0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e,
    0xa6, 0x21, 0x7b, 0x07, 0x8f, 0x09, 0xd5, 0x50,
];

/// Valor máximo provável: 2^52 - 1 noms ≈ 45M DOM.
/// Valores acima deste limite estão fora do supply DOM e não precisam de prova.
pub const MAX_PROVABLE_VALUE: u64 = (1u64 << 52) - 1;

/// Generator DOM derivado deterministicamente de H_DOM_X.
fn dom_generator() -> Generator {
    Generator::new_unblinded(SECP256K1, Tag::from(H_DOM_X))
}

/// Cria PedersenCommitment zkp a partir de value + blinding.
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
                bytes.len(), dom_core::MAX_PROOF_SIZE
            )));
        }
        Ok(Self { bytes })
    }
}

/// Gera range proof para (value, blinding).
/// Retorna (proof, commitment_bytes[33]).
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

    Ok((RangeProof::from_bytes(proof.serialize())?, commit_bytes))
}

/// Verifica range proof dado commitment bytes (33 bytes).
pub fn verify(
    commitment_bytes: &[u8; 33],
    proof_bytes: &[u8],
) -> Result<bool, DomError> {
    if proof_bytes.is_empty() {
        return Err(DomError::Malformed("range proof vazio".into()));
    }
    if proof_bytes.len() > dom_core::MAX_PROOF_SIZE {
        return Err(DomError::Malformed(format!(
            "range proof muito grande: {} bytes", proof_bytes.len()
        )));
    }

    let generator = dom_generator();

    let zkp_commit = ZkpCommit::from_slice(commitment_bytes)
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
        assert_eq!(h, H_DOM_COMPRESSED,
            "H_DOM diverge! Atualizar H_DOM_COMPRESSED: {:?}", h);
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
        assert!(max_supply <= MAX_PROVABLE_VALUE,
            "MAX_SUPPLY_NOMS {max_supply} > MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}");
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
        assert!(proof.bytes.len() <= dom_core::MAX_PROOF_SIZE,
            "proof {} bytes > MAX_PROOF_SIZE {}", proof.bytes.len(), dom_core::MAX_PROOF_SIZE);
        println!("RangeProof size: {} bytes", proof.bytes.len());
    }

    #[test]
    fn value_above_max_rejected() {
        let bf = BlindingFactor::random();
        assert!(prove(MAX_PROVABLE_VALUE + 1, &bf).is_err());
    }
}

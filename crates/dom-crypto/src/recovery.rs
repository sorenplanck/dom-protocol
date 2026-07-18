//! Wallet V3 seed-only confidential-output recovery.
//!
//! The range proof remains non-rewindable. This module encrypts fixed-size,
//! authenticated recovery metadata under keys derived from the wallet seed and
//! chain identity. Successful authentication is the ownership test.

use crate::pedersen::{BlindingFactor, Commitment};
use crate::MAX_PROVABLE_VALUE;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use dom_core::DomError;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Recovery capsule format version.
pub const RECOVERY_VERSION: u16 = 1;
/// Recovery metadata format version.
pub const RECOVERY_METADATA_VERSION: u16 = 1;
/// Fixed metadata plaintext length.
pub const RECOVERY_PLAINTEXT_SIZE: usize = 64;
/// ChaCha20-Poly1305 nonce length.
pub const RECOVERY_NONCE_SIZE: usize = 12;
/// ChaCha20-Poly1305 authentication tag length.
pub const RECOVERY_TAG_SIZE: usize = 16;
/// Fixed ciphertext and tag length.
pub const RECOVERY_CIPHERTEXT_SIZE: usize = RECOVERY_PLAINTEXT_SIZE + RECOVERY_TAG_SIZE;
/// Fixed canonical capsule length.
pub const RECOVERY_CAPSULE_SIZE: usize = 2 + RECOVERY_NONCE_SIZE + 2 + RECOVERY_CIPHERTEXT_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryCapsuleFrontier {
    WrongLength,
    UnsupportedVersion,
    WrongCiphertextLength,
    Candidate,
}

pub(crate) const fn classify_recovery_capsule_frontier(
    length: usize,
    version: u16,
    ciphertext_length: usize,
) -> RecoveryCapsuleFrontier {
    if length != RECOVERY_CAPSULE_SIZE {
        RecoveryCapsuleFrontier::WrongLength
    } else if version != RECOVERY_VERSION {
        RecoveryCapsuleFrontier::UnsupportedVersion
    } else if ciphertext_length != RECOVERY_CIPHERTEXT_SIZE {
        RecoveryCapsuleFrontier::WrongCiphertextLength
    } else {
        RecoveryCapsuleFrontier::Candidate
    }
}

/// HKDF domain separation constants frozen by the recovery RFC.
pub const TAG_RECOVERY_ROOT: &[u8] = b"DOM:wallet-v3:recovery-root";
/// Recovery ownership-detection root domain.
pub const TAG_RECOVERY_DETECTION: &[u8] = b"DOM:wallet-v3:recovery-detection";
/// Recovery authenticated-encryption root domain.
pub const TAG_RECOVERY_AEAD: &[u8] = b"DOM:wallet-v3:recovery-aead";
/// Output blinding reconstruction domain.
pub const TAG_OUTPUT_BLINDING: &[u8] = b"DOM:wallet-v3:output-blinding";
/// Coinbase output metadata domain.
pub const TAG_COINBASE_OUTPUT: &[u8] = b"DOM:wallet-v3:coinbase-output";
/// Change output metadata domain.
pub const TAG_CHANGE_OUTPUT: &[u8] = b"DOM:wallet-v3:change-output";
/// Received output metadata domain.
pub const TAG_RECEIVED_OUTPUT: &[u8] = b"DOM:wallet-v3:received-output";
/// Self-transfer output metadata domain.
pub const TAG_SELF_TRANSFER_OUTPUT: &[u8] = b"DOM:wallet-v3:self-transfer-output";
/// Deterministic vector nonce domain; production uses CSPRNG nonces.
pub const TAG_RECOVERY_NONCE: &[u8] = b"DOM:wallet-v3:recovery-nonce:v1";
/// Associated-authenticated-data domain.
pub const TAG_RECOVERY_AAD: &[u8] = b"DOM:wallet-v3:recovery-aad:v1";

/// Public output context known from canonical block placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PublicOutputKind {
    /// A normal transaction output.
    Regular = 0,
    /// The block coinbase output.
    Coinbase = 1,
}

impl TryFrom<u8> for PublicOutputKind {
    type Error = DomError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Regular),
            1 => Ok(Self::Coinbase),
            other => Err(DomError::Malformed(format!(
                "unsupported public output kind {other}"
            ))),
        }
    }
}

/// Private wallet output role, visible only after authenticated recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputRecoveryDomain {
    /// Output created by the receiving wallet.
    Received = 0,
    /// Sender change output.
    Change = 1,
    /// Mining reward output.
    Coinbase = 2,
    /// Output created by an explicit self-transfer.
    SelfTransfer = 3,
}

impl OutputRecoveryDomain {
    /// Public output kind required for this private role.
    pub fn public_kind(self) -> PublicOutputKind {
        match self {
            Self::Coinbase => PublicOutputKind::Coinbase,
            Self::Received | Self::Change | Self::SelfTransfer => PublicOutputKind::Regular,
        }
    }

    fn derivation_tag(self) -> &'static [u8] {
        match self {
            Self::Received => TAG_RECEIVED_OUTPUT,
            Self::Change => TAG_CHANGE_OUTPUT,
            Self::Coinbase => TAG_COINBASE_OUTPUT,
            Self::SelfTransfer => TAG_SELF_TRANSFER_OUTPUT,
        }
    }
}

impl TryFrom<u8> for OutputRecoveryDomain {
    type Error = DomError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Received),
            1 => Ok(Self::Change),
            2 => Ok(Self::Coinbase),
            3 => Ok(Self::SelfTransfer),
            other => Err(DomError::Malformed(format!(
                "unsupported recovery output domain {other}"
            ))),
        }
    }
}

/// Network and chain identity bound into all recovery keys and ciphertexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryChainContext {
    /// Frozen network magic.
    pub network_magic: u32,
    /// Frozen chain identifier.
    pub chain_id: [u8; 32],
}

impl RecoveryChainContext {
    fn bytes(self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..4].copy_from_slice(&self.network_magic.to_le_bytes());
        out[4..].copy_from_slice(&self.chain_id);
        out
    }
}

/// Opaque seed-derived recovery root. Debug output never reveals key bytes.
pub struct RecoveryRoot(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RecoveryRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryRoot([REDACTED])")
    }
}

/// Authenticated metadata recovered from an owned output.
pub struct RecoveredOutput {
    /// Confidential value in noms.
    pub value: u64,
    /// Wallet account identifier.
    pub account: u32,
    /// Checked wallet derivation index.
    pub derivation_index: u64,
    /// Private wallet output role.
    pub domain: OutputRecoveryDomain,
    /// Output blinding that reconstructs the on-chain commitment.
    pub blinding: BlindingFactor,
}

impl std::fmt::Debug for RecoveredOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredOutput")
            .field("value", &"[REDACTED]")
            .field("account", &self.account)
            .field("derivation_index", &self.derivation_index)
            .field("domain", &self.domain)
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

/// Canonical fixed-size recovery capsule.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCapsule([u8; RECOVERY_CAPSULE_SIZE]);

impl std::fmt::Debug for RecoveryCapsule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCapsule")
            .field("version", &self.version())
            .field("length", &RECOVERY_CAPSULE_SIZE)
            .finish()
    }
}

impl RecoveryCapsule {
    /// Parse canonical public framing without allocating from encoded lengths.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        let version = if bytes.len() >= 2 {
            u16::from_le_bytes([bytes[0], bytes[1]])
        } else {
            0
        };
        let ciphertext_len = if bytes.len() >= 16 {
            u16::from_le_bytes([bytes[14], bytes[15]]) as usize
        } else {
            0
        };
        match classify_recovery_capsule_frontier(bytes.len(), version, ciphertext_len) {
            RecoveryCapsuleFrontier::WrongLength => {
                return Err(DomError::Malformed(format!(
                    "recovery capsule length {} != {RECOVERY_CAPSULE_SIZE}",
                    bytes.len()
                )));
            }
            RecoveryCapsuleFrontier::UnsupportedVersion => {
                return Err(DomError::Malformed(format!(
                    "unsupported recovery capsule version {version}"
                )));
            }
            RecoveryCapsuleFrontier::WrongCiphertextLength => {
                return Err(DomError::Malformed(format!(
                    "recovery ciphertext length {ciphertext_len} != {RECOVERY_CIPHERTEXT_SIZE}"
                )));
            }
            RecoveryCapsuleFrontier::Candidate => {}
        }
        let mut out = [0u8; RECOVERY_CAPSULE_SIZE];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// Borrow the canonical capsule bytes.
    pub fn as_bytes(&self) -> &[u8; RECOVERY_CAPSULE_SIZE] {
        &self.0
    }

    /// Return the parsed capsule version.
    pub fn version(&self) -> u16 {
        u16::from_le_bytes([self.0[0], self.0[1]])
    }
}

/// Derive the chain-bound Wallet V3 recovery root from seed bytes.
pub fn derive_recovery_root(
    seed: &[u8],
    chain: RecoveryChainContext,
) -> Result<RecoveryRoot, DomError> {
    if seed.is_empty() {
        return Err(DomError::Invalid("wallet seed must not be empty".into()));
    }
    let chain_bytes = chain.bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&chain_bytes), seed);
    let mut root = [0u8; 32];
    hkdf.expand(TAG_RECOVERY_ROOT, &mut root)
        .map_err(|_| DomError::Internal("recovery root HKDF expansion failed".into()))?;
    Ok(RecoveryRoot(Zeroizing::new(root)))
}

fn expand_root(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    tag: &[u8],
) -> Result<Zeroizing<[u8; 32]>, DomError> {
    let chain_bytes = chain.bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&chain_bytes), root.0.as_slice());
    let mut out = [0u8; 32];
    hkdf.expand(tag, &mut out)
        .map_err(|_| DomError::Internal("recovery subkey HKDF expansion failed".into()))?;
    Ok(Zeroizing::new(out))
}

fn output_aead_key(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    commitment: &[u8; 33],
) -> Result<Zeroizing<[u8; 32]>, DomError> {
    let detection = expand_root(root, chain, TAG_RECOVERY_DETECTION)?;
    let aead = expand_root(root, chain, TAG_RECOVERY_AEAD)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(detection.as_slice());
    ikm[32..].copy_from_slice(aead.as_slice());
    let hkdf = Hkdf::<Sha256>::new(Some(commitment), ikm.as_slice());
    let mut out = [0u8; 32];
    hkdf.expand(TAG_RECOVERY_AEAD, &mut out)
        .map_err(|_| DomError::Internal("per-output AEAD HKDF expansion failed".into()))?;
    Ok(Zeroizing::new(out))
}

fn output_blinding_mask(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    commitment: &[u8; 33],
    domain: OutputRecoveryDomain,
) -> Result<Zeroizing<[u8; 32]>, DomError> {
    let blinding_root = expand_root(root, chain, TAG_OUTPUT_BLINDING)?;
    let hkdf = Hkdf::<Sha256>::new(Some(commitment), blinding_root.as_slice());
    let mut info = Vec::with_capacity(TAG_OUTPUT_BLINDING.len() + domain.derivation_tag().len());
    info.extend_from_slice(TAG_OUTPUT_BLINDING);
    info.extend_from_slice(domain.derivation_tag());
    let mut out = [0u8; 32];
    hkdf.expand(&info, &mut out)
        .map_err(|_| DomError::Internal("output blinding HKDF expansion failed".into()))?;
    Ok(Zeroizing::new(out))
}

fn associated_data(
    chain: RecoveryChainContext,
    commitment: &[u8; 33],
    range_proof_version: u8,
    output_kind: PublicOutputKind,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_RECOVERY_AAD.len() + 2 + 4 + 32 + 33 + 1 + 1 + 2);
    out.extend_from_slice(TAG_RECOVERY_AAD);
    out.extend_from_slice(&RECOVERY_VERSION.to_le_bytes());
    out.extend_from_slice(&chain.network_magic.to_le_bytes());
    out.extend_from_slice(&chain.chain_id);
    out.extend_from_slice(commitment);
    out.push(range_proof_version);
    out.push(output_kind as u8);
    out.extend_from_slice(&(RECOVERY_CIPHERTEXT_SIZE as u16).to_le_bytes());
    out
}

#[allow(clippy::too_many_arguments)]
fn encode_metadata(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    commitment: &[u8; 33],
    value: u64,
    account: u32,
    derivation_index: u64,
    domain: OutputRecoveryDomain,
    blinding: &BlindingFactor,
) -> Result<Zeroizing<[u8; RECOVERY_PLAINTEXT_SIZE]>, DomError> {
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(format!(
            "recovery value {value} exceeds MAX_PROVABLE_VALUE {MAX_PROVABLE_VALUE}"
        )));
    }
    let mut out = Zeroizing::new([0u8; RECOVERY_PLAINTEXT_SIZE]);
    out[0..2].copy_from_slice(&RECOVERY_METADATA_VERSION.to_le_bytes());
    out[2..10].copy_from_slice(&value.to_le_bytes());
    out[10..14].copy_from_slice(&account.to_le_bytes());
    out[14..22].copy_from_slice(&derivation_index.to_le_bytes());
    out[22] = domain as u8;
    out[23] = u8::from(domain == OutputRecoveryDomain::Coinbase);
    let mask = output_blinding_mask(root, chain, commitment, domain)?;
    for (encoded, (secret, mask_byte)) in out[24..56]
        .iter_mut()
        .zip(blinding.as_bytes().iter().zip(mask.iter()))
    {
        *encoded = secret ^ mask_byte;
    }
    Ok(out)
}

/// Create a capsule with a fresh production nonce.
#[allow(clippy::too_many_arguments)]
pub fn create_recovery_capsule(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    commitment: &[u8; 33],
    range_proof_version: u8,
    value: u64,
    account: u32,
    derivation_index: u64,
    domain: OutputRecoveryDomain,
    blinding: &BlindingFactor,
) -> Result<RecoveryCapsule, DomError> {
    let mut nonce = [0u8; RECOVERY_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    create_recovery_capsule_with_nonce(
        root,
        chain,
        commitment,
        range_proof_version,
        value,
        account,
        derivation_index,
        domain,
        blinding,
        nonce,
    )
}

/// Deterministic constructor for frozen vectors and uniqueness tests.
#[allow(clippy::too_many_arguments)]
pub fn create_recovery_capsule_with_nonce(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    commitment: &[u8; 33],
    range_proof_version: u8,
    value: u64,
    account: u32,
    derivation_index: u64,
    domain: OutputRecoveryDomain,
    blinding: &BlindingFactor,
    nonce_bytes: [u8; RECOVERY_NONCE_SIZE],
) -> Result<RecoveryCapsule, DomError> {
    let key = output_aead_key(root, chain, commitment)?;
    let plaintext = encode_metadata(
        root,
        chain,
        commitment,
        value,
        account,
        derivation_index,
        domain,
        blinding,
    )?;
    let aad = associated_data(chain, commitment, range_proof_version, domain.public_kind());
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| DomError::Internal("invalid recovery AEAD key length".into()))?;
    #[allow(deprecated)]
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| DomError::Internal("recovery capsule encryption failed".into()))?;
    if ciphertext.len() != RECOVERY_CIPHERTEXT_SIZE {
        return Err(DomError::Internal(
            "recovery AEAD returned a noncanonical ciphertext length".into(),
        ));
    }
    let mut out = [0u8; RECOVERY_CAPSULE_SIZE];
    out[..2].copy_from_slice(&RECOVERY_VERSION.to_le_bytes());
    out[2..14].copy_from_slice(&nonce_bytes);
    out[14..16].copy_from_slice(&(RECOVERY_CIPHERTEXT_SIZE as u16).to_le_bytes());
    out[16..].copy_from_slice(&ciphertext);
    Ok(RecoveryCapsule(out))
}

/// Attempt authenticated recovery. AEAD failure means the output is not owned
/// or was tampered with and is returned without sensitive diagnostics.
pub fn recover_output_from_capsule(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    commitment: &[u8; 33],
    range_proof_version: u8,
    output_kind: PublicOutputKind,
    capsule: &RecoveryCapsule,
) -> Result<Option<RecoveredOutput>, DomError> {
    let key = output_aead_key(root, chain, commitment)?;
    let aad = associated_data(chain, commitment, range_proof_version, output_kind);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| DomError::Internal("invalid recovery AEAD key length".into()))?;
    let mut nonce_bytes = [0u8; RECOVERY_NONCE_SIZE];
    nonce_bytes.copy_from_slice(&capsule.0[2..14]);
    #[allow(deprecated)]
    let plaintext = match cipher.decrypt(
        Nonce::from_slice(&nonce_bytes),
        Payload {
            msg: &capsule.0[16..],
            aad: &aad,
        },
    ) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    parse_and_validate_metadata(root, chain, &plaintext, commitment, output_kind).map(Some)
}

fn parse_and_validate_metadata(
    root: &RecoveryRoot,
    chain: RecoveryChainContext,
    plaintext: &[u8],
    commitment: &[u8; 33],
    output_kind: PublicOutputKind,
) -> Result<RecoveredOutput, DomError> {
    if plaintext.len() != RECOVERY_PLAINTEXT_SIZE {
        return Err(DomError::Malformed(
            "noncanonical recovery plaintext length".into(),
        ));
    }
    let version = u16::from_le_bytes([plaintext[0], plaintext[1]]);
    if version != RECOVERY_METADATA_VERSION {
        return Err(DomError::Malformed(format!(
            "unsupported recovery metadata version {version}"
        )));
    }
    if plaintext[23] & !1 != 0 || plaintext[56..64] != [0u8; 8] {
        return Err(DomError::Malformed(
            "recovery metadata contains noncanonical flags or reserved bytes".into(),
        ));
    }
    let value = u64::from_le_bytes(plaintext[2..10].try_into().unwrap());
    if value > MAX_PROVABLE_VALUE {
        return Err(DomError::Invalid(
            "recovered value exceeds proof range".into(),
        ));
    }
    let account = u32::from_le_bytes(plaintext[10..14].try_into().unwrap());
    let derivation_index = u64::from_le_bytes(plaintext[14..22].try_into().unwrap());
    let domain = OutputRecoveryDomain::try_from(plaintext[22])?;
    let expected_coinbase = domain == OutputRecoveryDomain::Coinbase;
    if (plaintext[23] == 1) != expected_coinbase || domain.public_kind() != output_kind {
        return Err(DomError::Invalid(
            "recovered output domain does not match canonical output context".into(),
        ));
    }
    let mask = output_blinding_mask(root, chain, commitment, domain)?;
    let mut blinding_bytes = [0u8; 32];
    for (decoded, (encoded, mask_byte)) in blinding_bytes
        .iter_mut()
        .zip(plaintext[24..56].iter().zip(mask.iter()))
    {
        *decoded = encoded ^ mask_byte;
    }
    let blinding = BlindingFactor::from_bytes(blinding_bytes)?;
    blinding_bytes.zeroize();
    let recomputed = Commitment::commit(value, &blinding);
    if recomputed.as_bytes() != commitment {
        return Err(DomError::Invalid(
            "recovered value and blinding do not reconstruct commitment".into(),
        ));
    }
    Ok(RecoveredOutput {
        value,
        account,
        derivation_index,
        domain,
        blinding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    fn context() -> RecoveryChainContext {
        RecoveryChainContext {
            network_magic: 0x4452_4547,
            chain_id: [7u8; 32],
        }
    }

    fn fixture() -> (RecoveryRoot, BlindingFactor, Commitment, RecoveryCapsule) {
        let root = derive_recovery_root(&[9u8; 64], context()).unwrap();
        let blinding = BlindingFactor::from_bytes([3u8; 32]).unwrap();
        let commitment = Commitment::commit(42, &blinding);
        let capsule = create_recovery_capsule_with_nonce(
            &root,
            context(),
            commitment.as_bytes(),
            1,
            42,
            4,
            11,
            OutputRecoveryDomain::Received,
            &blinding,
            [5u8; 12],
        )
        .unwrap();
        (root, blinding, commitment, capsule)
    }

    #[test]
    fn deterministic_vector_and_roundtrip() {
        let (root, blinding, commitment, capsule) = fixture();
        assert_eq!(capsule.as_bytes().len(), 96);
        assert_eq!(
            hex::encode(&capsule.as_bytes()[..16]),
            "01000505050505050505050505055000"
        );
        let recovered = recover_output_from_capsule(
            &root,
            context(),
            commitment.as_bytes(),
            1,
            PublicOutputKind::Regular,
            &capsule,
        )
        .unwrap()
        .unwrap();
        assert_eq!(recovered.value, 42);
        assert_eq!(recovered.account, 4);
        assert_eq!(recovered.derivation_index, 11);
        assert_eq!(recovered.domain, OutputRecoveryDomain::Received);
        assert_eq!(recovered.blinding.as_bytes(), blinding.as_bytes());
    }

    #[test]
    fn wrong_seed_network_chain_and_kind_do_not_claim() {
        let (root, _, commitment, capsule) = fixture();
        let wrong_seed = derive_recovery_root(&[8u8; 64], context()).unwrap();
        assert!(recover_output_from_capsule(
            &wrong_seed,
            context(),
            commitment.as_bytes(),
            1,
            PublicOutputKind::Regular,
            &capsule
        )
        .unwrap()
        .is_none());
        let wrong_network = RecoveryChainContext {
            network_magic: 1,
            ..context()
        };
        assert!(recover_output_from_capsule(
            &root,
            wrong_network,
            commitment.as_bytes(),
            1,
            PublicOutputKind::Regular,
            &capsule
        )
        .unwrap()
        .is_none());
        let wrong_chain = RecoveryChainContext {
            chain_id: [6u8; 32],
            ..context()
        };
        assert!(recover_output_from_capsule(
            &root,
            wrong_chain,
            commitment.as_bytes(),
            1,
            PublicOutputKind::Regular,
            &capsule
        )
        .unwrap()
        .is_none());
        assert!(recover_output_from_capsule(
            &root,
            context(),
            commitment.as_bytes(),
            1,
            PublicOutputKind::Coinbase,
            &capsule
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn mutation_and_substitution_fail_closed() {
        let (root, _, commitment, capsule) = fixture();
        for index in 0..RECOVERY_CAPSULE_SIZE {
            let mut bytes = *capsule.as_bytes();
            bytes[index] ^= 1;
            let Ok(mutated) = RecoveryCapsule::from_bytes(&bytes) else {
                continue;
            };
            assert!(recover_output_from_capsule(
                &root,
                context(),
                commitment.as_bytes(),
                1,
                PublicOutputKind::Regular,
                &mutated
            )
            .unwrap()
            .is_none());
        }
        let other = Commitment::commit(42, &BlindingFactor::from_bytes([4u8; 32]).unwrap());
        assert!(recover_output_from_capsule(
            &root,
            context(),
            other.as_bytes(),
            1,
            PublicOutputKind::Regular,
            &capsule
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn parser_rejects_versions_and_lengths() {
        let (_, _, _, capsule) = fixture();
        assert!(RecoveryCapsule::from_bytes(&capsule.as_bytes()[..95]).is_err());
        let mut unsupported = *capsule.as_bytes();
        unsupported[0] = 2;
        assert!(RecoveryCapsule::from_bytes(&unsupported).is_err());
        let mut oversized_claim = *capsule.as_bytes();
        oversized_claim[14..16].copy_from_slice(&81u16.to_le_bytes());
        assert!(RecoveryCapsule::from_bytes(&oversized_claim).is_err());
    }

    #[test]
    fn secret_bearing_recovery_debug_paths_are_redacted() {
        let (root, _, commitment, capsule) = fixture();
        assert_eq!(format!("{root:?}"), "RecoveryRoot([REDACTED])");
        let recovered = recover_output_from_capsule(
            &root,
            context(),
            commitment.as_bytes(),
            1,
            PublicOutputKind::Regular,
            &capsule,
        )
        .expect("recovery succeeds")
        .expect("owned output");
        let dbg = format!("{recovered:?}");
        assert!(dbg.contains("value: \"[REDACTED]\""));
        assert!(dbg.contains("blinding: \"[REDACTED]\""));
        assert!(!dbg.contains(&hex::encode([3u8; 32])));
    }

    #[test]
    fn repeated_vectors_are_deterministic() {
        let (_, _, _, expected) = fixture();
        for _ in 0..100 {
            let (_, _, _, actual) = fixture();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn production_nonces_do_not_repeat_across_generated_domain() {
        let root = derive_recovery_root(&[0x61; 64], context()).unwrap();
        let blinding = BlindingFactor::from_bytes([7u8; 32]).unwrap();
        let commitment = Commitment::commit(99, &blinding);
        let mut nonces = HashSet::new();
        for index in 0..100u64 {
            let capsule = create_recovery_capsule(
                &root,
                context(),
                commitment.as_bytes(),
                1,
                99,
                0,
                index,
                OutputRecoveryDomain::Change,
                &blinding,
            )
            .unwrap();
            assert!(nonces.insert(capsule.as_bytes()[2..14].to_vec()));
        }
    }

    proptest! {
        #[test]
        fn generated_metadata_roundtrips_and_other_seeds_do_not_claim(
            value in 0u64..=MAX_PROVABLE_VALUE,
            account in any::<u32>(),
            index in any::<u64>(),
            blind_byte in 1u8..=100,
            seed_byte in 1u8..=100,
        ) {
            let seed = [seed_byte; 64];
            let root = derive_recovery_root(&seed, context()).unwrap();
            let blinding = BlindingFactor::from_bytes([blind_byte; 32]).unwrap();
            let commitment = Commitment::commit(value, &blinding);
            let capsule = create_recovery_capsule_with_nonce(
                &root,
                context(),
                commitment.as_bytes(),
                1,
                value,
                account,
                index,
                OutputRecoveryDomain::Received,
                &blinding,
                [0x33; 12],
            ).unwrap();
            let recovered = recover_output_from_capsule(
                &root,
                context(),
                commitment.as_bytes(),
                1,
                PublicOutputKind::Regular,
                &capsule,
            ).unwrap().unwrap();
            prop_assert_eq!(recovered.value, value);
            prop_assert_eq!(recovered.account, account);
            prop_assert_eq!(recovered.derivation_index, index);

            let other_seed = [seed_byte.saturating_add(101); 64];
            let other = derive_recovery_root(&other_seed, context()).unwrap();
            prop_assert!(recover_output_from_capsule(
                &other,
                context(),
                commitment.as_bytes(),
                1,
                PublicOutputKind::Regular,
                &capsule,
            ).unwrap().is_none());
        }
    }
}

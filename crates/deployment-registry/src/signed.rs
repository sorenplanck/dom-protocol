use std::collections::BTreeSet;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;

use crate::types::{
    RegistryManifestV1, RegistryValidationPolicyV1, ResolvedRegistryV1, MAX_MANIFEST_BYTES,
};
use crate::{RegistryError, Result, REGISTRY_VERSION};

/// Maximum offline verification keys accepted by one authority set.
pub const MAX_AUTHORITIES: usize = 16;
/// Maximum signatures carried by one signed registry envelope.
pub const MAX_SIGNATURES: usize = MAX_AUTHORITIES;
/// Maximum canonical size of one standalone authority-set artifact.
pub const MAX_AUTHORITY_SET_BYTES: usize = 16 + MAX_AUTHORITIES * 32;

const SIGNED_MAGIC: &[u8; 8] = b"DOMREGS1";
const AUTHORITY_SET_MAGIC: &[u8; 8] = b"DOMRAUS1";
const AUTHORITY_SET_VERSION: u16 = 1;
const AUTHORITY_SET_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/DEPLOYMENT-REGISTRY/AUTHORITY-SET/V1\0";
pub(crate) const MAX_SIGNED_BYTES: usize =
    MAX_MANIFEST_BYTES + 8 + 2 + 2 + 4 + 2 + MAX_SIGNATURES * 66;

/// Externally pinned threshold set of BIP340 registry authorities.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthoritySetV1 {
    threshold: u16,
    xonly_keys: Vec<[u8; 32]>,
}

/// One indexed BIP340 signature over the canonical manifest digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegistrySignatureV1 {
    /// Index into the externally pinned [`AuthoritySetV1`].
    pub signer_index: u16,
    /// BIP340 signature bytes.
    pub signature: [u8; 64],
}

/// Canonical manifest bytes plus a bounded ordered signature set.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRegistryV1 {
    manifest_bytes: Vec<u8>,
    signatures: Vec<RegistrySignatureV1>,
}

impl core::fmt::Debug for SignedRegistryV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedRegistryV1")
            .field(
                "manifest_bytes",
                &format_args!("{} bytes", self.manifest_bytes.len()),
            )
            .field("signature_count", &self.signatures.len())
            .finish()
    }
}

impl AuthoritySetV1 {
    /// Constructs a non-empty, unique and bounded threshold authority set.
    pub fn new(threshold: u16, xonly_keys: Vec<[u8; 32]>) -> Result<Self> {
        if xonly_keys.is_empty()
            || xonly_keys.len() > MAX_AUTHORITIES
            || threshold == 0
            || usize::from(threshold) > xonly_keys.len()
        {
            return Err(RegistryError::InvalidAuthoritySet);
        }
        let mut unique = BTreeSet::new();
        for key in &xonly_keys {
            if *key == [0u8; 32] || !unique.insert(*key) {
                return Err(RegistryError::InvalidAuthoritySet);
            }
        }
        Ok(Self {
            threshold,
            xonly_keys,
        })
    }

    /// Required number of independent valid signatures.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Ordered externally pinned BIP340 keys.
    pub fn xonly_keys(&self) -> &[[u8; 32]] {
        &self.xonly_keys
    }

    /// Validates every configured key with the pinned secp256k1 backend,
    /// including authorities that did not sign a particular envelope.
    pub fn validate_with_context(&self, secp: &SecpContext) -> Result<()> {
        for key in &self.xonly_keys {
            secp.validate_xonly_key(key)
                .map_err(|_| RegistryError::InvalidAuthoritySet)?;
        }
        Ok(())
    }

    /// Encodes this set in its standalone bounded canonical representation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        // Re-run the public constructor's structural checks so an authority
        // object can never acquire a second, less strict storage encoding.
        Self::new(self.threshold, self.xonly_keys.clone())?;
        let count =
            u16::try_from(self.xonly_keys.len()).map_err(|_| RegistryError::BoundExceeded)?;
        let mut bytes = Vec::with_capacity(16 + self.xonly_keys.len() * 32);
        bytes.extend_from_slice(AUTHORITY_SET_MAGIC);
        bytes.extend_from_slice(&AUTHORITY_SET_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.threshold.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for key in &self.xonly_keys {
            bytes.extend_from_slice(key);
        }
        if bytes.len() > MAX_AUTHORITY_SET_BYTES {
            return Err(RegistryError::BoundExceeded);
        }
        Ok(bytes)
    }

    /// Strictly decodes one standalone set and rejects trailing or alternate
    /// bytes. Curve membership remains checked by [`Self::validate_with_context`].
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_AUTHORITY_SET_BYTES || bytes.len() < 16 {
            return Err(RegistryError::BoundExceeded);
        }
        let mut reader = SignedReader::new(bytes);
        if reader.take::<8>()? != *AUTHORITY_SET_MAGIC {
            return Err(RegistryError::NonCanonicalEncoding);
        }
        if reader.u16()? != AUTHORITY_SET_VERSION {
            return Err(RegistryError::UnsupportedVersion);
        }
        if reader.u16()? != 0 {
            return Err(RegistryError::NonCanonicalEncoding);
        }
        let threshold = reader.u16()?;
        let count = usize::from(reader.u16()?);
        if count == 0 || count > MAX_AUTHORITIES {
            return Err(RegistryError::BoundExceeded);
        }
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(reader.take::<32>()?);
        }
        reader.finish()?;
        let value = Self::new(threshold, keys)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RegistryError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Domain-separated commitment used to pin the registry authority set in
    /// production bootstrap configuration.
    pub fn authority_set_digest(&self) -> Result<[u8; 32]> {
        let bytes = self.canonical_bytes()?;
        let mut hash = Blake2bVar::new(32).map_err(|_| RegistryError::CorruptState)?;
        hash.update(AUTHORITY_SET_DIGEST_DOMAIN);
        hash.update(&bytes);
        let mut output = [0; 32];
        hash.finalize_variable(&mut output)
            .map_err(|_| RegistryError::CorruptState)?;
        Ok(output)
    }
}

impl SignedRegistryV1 {
    /// Creates a signed envelope from a validated manifest and ordered signatures.
    pub fn new(
        manifest: &RegistryManifestV1,
        signatures: Vec<RegistrySignatureV1>,
    ) -> Result<Self> {
        Self::from_canonical_manifest(manifest.canonical_bytes()?, signatures)
    }

    fn from_canonical_manifest(
        manifest_bytes: Vec<u8>,
        signatures: Vec<RegistrySignatureV1>,
    ) -> Result<Self> {
        RegistryManifestV1::decode(&manifest_bytes)?;
        validate_signature_shape(&signatures)?;
        Ok(Self {
            manifest_bytes,
            signatures,
        })
    }

    /// Exact canonical manifest bytes covered by every signature.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Ordered signatures, strictly increasing by authority index.
    pub fn signatures(&self) -> &[RegistrySignatureV1] {
        &self.signatures
    }

    /// Canonical storage/transport representation of the signed envelope.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        RegistryManifestV1::decode(&self.manifest_bytes)?;
        validate_signature_shape(&self.signatures)?;
        let mut out = Vec::with_capacity(
            8 + 2 + 2 + 4 + self.manifest_bytes.len() + 2 + self.signatures.len() * 66,
        );
        out.extend_from_slice(SIGNED_MAGIC);
        out.extend_from_slice(&REGISTRY_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        let manifest_len =
            u32::try_from(self.manifest_bytes.len()).map_err(|_| RegistryError::BoundExceeded)?;
        out.extend_from_slice(&manifest_len.to_be_bytes());
        out.extend_from_slice(&self.manifest_bytes);
        let signature_count =
            u16::try_from(self.signatures.len()).map_err(|_| RegistryError::BoundExceeded)?;
        out.extend_from_slice(&signature_count.to_be_bytes());
        for signature in &self.signatures {
            out.extend_from_slice(&signature.signer_index.to_be_bytes());
            out.extend_from_slice(&signature.signature);
        }
        if out.len() > MAX_SIGNED_BYTES {
            return Err(RegistryError::BoundExceeded);
        }
        Ok(out)
    }

    /// Strictly decodes a signed registry, refusing trailing or alternate bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_BYTES {
            return Err(RegistryError::BoundExceeded);
        }
        let mut reader = SignedReader::new(bytes);
        if reader.take::<8>()? != *SIGNED_MAGIC {
            return Err(RegistryError::NonCanonicalEncoding);
        }
        if reader.u16()? != REGISTRY_VERSION {
            return Err(RegistryError::UnsupportedVersion);
        }
        if reader.u16()? != 0 {
            return Err(RegistryError::NonCanonicalEncoding);
        }
        let manifest_len =
            usize::try_from(reader.u32()?).map_err(|_| RegistryError::BoundExceeded)?;
        if manifest_len > MAX_MANIFEST_BYTES {
            return Err(RegistryError::BoundExceeded);
        }
        let manifest_bytes = reader.bytes(manifest_len)?.to_vec();
        let signature_count = usize::from(reader.u16()?);
        if signature_count == 0 || signature_count > MAX_SIGNATURES {
            return Err(RegistryError::BoundExceeded);
        }
        let mut signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            signatures.push(RegistrySignatureV1 {
                signer_index: reader.u16()?,
                signature: reader.take::<64>()?,
            });
        }
        reader.finish()?;
        let value = Self::from_canonical_manifest(manifest_bytes, signatures)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RegistryError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Verifies policy and every supplied signature, then issues a resolved value.
    pub fn verify(
        &self,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        policy: RegistryValidationPolicyV1,
    ) -> Result<ResolvedRegistryV1> {
        let resolved = self.verify_authenticity(authorities, secp, policy.expected_network_id)?;
        resolved.manifest().validate_policy(policy)?;
        Ok(resolved)
    }

    /// Verifies canonical material, network identity and threshold signatures
    /// without applying freshness/rollback policy. This is restricted to the
    /// durable store, which must authenticate retained state before trusting
    /// its denormalized epoch and digest even when that retained manifest has
    /// expired or is below the new external minimum.
    pub(crate) fn verify_authenticity(
        &self,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        expected_network_id: [u8; 32],
    ) -> Result<ResolvedRegistryV1> {
        authorities.validate_with_context(secp)?;
        validate_signature_shape(&self.signatures)?;
        let manifest = RegistryManifestV1::decode(&self.manifest_bytes)?;
        if manifest.network_id != expected_network_id {
            return Err(RegistryError::WrongNetwork);
        }
        let digest = manifest.manifest_digest()?;
        for signature in &self.signatures {
            let key = authorities
                .xonly_keys
                .get(usize::from(signature.signer_index))
                .ok_or(RegistryError::InvalidSignature)?;
            secp.verify_bip340(key, &digest, &signature.signature)
                .map_err(|_| RegistryError::InvalidSignature)?;
        }
        if self.signatures.len() < usize::from(authorities.threshold) {
            return Err(RegistryError::ThresholdNotMet);
        }
        Ok(ResolvedRegistryV1::new(manifest, digest))
    }
}

fn validate_signature_shape(signatures: &[RegistrySignatureV1]) -> Result<()> {
    if signatures.is_empty() || signatures.len() > MAX_SIGNATURES {
        return Err(RegistryError::BoundExceeded);
    }
    let mut previous = None;
    for signature in signatures {
        if signature.signature == [0u8; 64]
            || previous
                .map(|value| signature.signer_index <= value)
                .unwrap_or(false)
        {
            return Err(RegistryError::InvalidSignature);
        }
        previous = Some(signature.signer_index);
    }
    Ok(())
}

struct SignedReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SignedReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RegistryError::Overflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RegistryError::NonCanonicalEncoding)?;
        self.position = end;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| RegistryError::NonCanonicalEncoding)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(RegistryError::NonCanonicalEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_set_codec_is_canonical_bounded_and_committed() {
        let secp = SecpContext::new(&[0x31; 32]);
        let keys = [[0x11; 32], [0x12; 32], [0x13; 32]]
            .iter()
            .enumerate()
            .map(|(index, secret)| {
                secp.sign_bip340(secret, &[0x41; 32], &[0x51 + index as u8; 32])
                    .expect("valid test key")
                    .1
            })
            .collect();
        let authorities = AuthoritySetV1::new(2, keys).expect("valid authorities");
        authorities
            .validate_with_context(&secp)
            .expect("curve-valid keys");
        let bytes = authorities.canonical_bytes().expect("canonical bytes");
        assert_eq!(
            AuthoritySetV1::decode_canonical(&bytes).expect("round trip"),
            authorities
        );
        assert_ne!(
            authorities.authority_set_digest().expect("set digest"),
            [0; 32]
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(AuthoritySetV1::decode_canonical(&trailing).is_err());

        let mut alternate = bytes;
        alternate[10] = 1;
        assert!(matches!(
            AuthoritySetV1::decode_canonical(&alternate),
            Err(RegistryError::NonCanonicalEncoding)
        ));
    }
}

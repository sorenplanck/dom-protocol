//! Ratified encrypted nonce-secret plaintext boundary.

use crate::error::exact_array;
use crate::secret_nonce::SecretNoncePairV1;
use crate::{AdaptorError, Result, SessionContextV1, SigningShareV1, TrustedChainIdV1};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"DOMSNSEC";
const VERSION: u16 = 1;
const FIXED_PREFIX_LEN: usize = 78;
const SCALAR_BYTES_LEN: usize = 64;

/// Opaque, by-value transfer of one exact `NonceSecretRecordV1` plaintext.
///
/// This type deliberately implements no cloning, copying, debugging, display,
/// equality, ordering, or generic serialization. The contained plaintext is
/// compiler-visibly zeroized on every drop path.
pub struct NonceSecretTransferV1 {
    plaintext: Zeroizing<Vec<u8>>,
}

/// One-shot authority to transfer plaintext into the trusted DOM Contracts sealer.
///
/// Only the integrated signer can construct this non-cloneable capability.
pub struct VaultSecretSealCapabilityV1 {
    _private: (),
}

impl VaultSecretSealCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Consume the authority and opaque transfer into one zeroizing buffer.
    pub fn into_plaintext(self, secret: NonceSecretTransferV1) -> Zeroizing<Vec<u8>> {
        secret.plaintext
    }
}

/// One-shot authority to import plaintext opened by the DOM Contracts sealer.
///
/// Only the integrated signer can construct this non-cloneable capability.
pub struct VaultSecretImportCapabilityV1 {
    _private: (),
}

impl VaultSecretImportCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Consume DOM Contracts store-owned plaintext into an opaque validated transfer.
    pub fn import(self, mut plaintext: Zeroizing<Vec<u8>>) -> Result<NonceSecretTransferV1> {
        if let Err(error) = validate_structural_bytes(&plaintext) {
            plaintext.zeroize();
            return Err(error);
        }
        Ok(NonceSecretTransferV1 { plaintext })
    }
}

impl NonceSecretTransferV1 {
    /// Minimum exact record length (`n = 2`, no adaptor point).
    pub const MIN_ENCODED_LEN: usize = 387;
    /// Maximum exact record length (`n = 16`, adaptor point present).
    pub const MAX_ENCODED_LEN: usize = 882;

    pub(crate) fn from_nonce_pair(
        reservation_nonce_id: [u8; 32],
        participant_id: [u8; 32],
        context: &SessionContextV1,
        pair: SecretNoncePairV1,
    ) -> Result<Self> {
        if reservation_nonce_id == [0; 32] || participant_id == [0; 32] {
            return Err(AdaptorError::InvalidContext(
                "nonce secret record identifiers must be nonzero",
            ));
        }
        let context_bytes = context.to_bytes();
        validate_context_length(&context_bytes)?;
        let context_len = u32::try_from(context_bytes.len())
            .map_err(|_| AdaptorError::InvalidContext("context length does not fit u32"))?;
        let scalars = pair.into_record_scalars();
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            FIXED_PREFIX_LEN + context_bytes.len() + SCALAR_BYTES_LEN,
        ));
        plaintext.extend_from_slice(MAGIC);
        plaintext.extend_from_slice(&VERSION.to_le_bytes());
        plaintext.extend_from_slice(&reservation_nonce_id);
        plaintext.extend_from_slice(&participant_id);
        plaintext.extend_from_slice(&context_len.to_le_bytes());
        plaintext.extend_from_slice(&context_bytes);
        plaintext.extend_from_slice(scalars.as_ref());
        validate_structural_bytes(&plaintext)?;
        Ok(Self { plaintext })
    }

    pub(crate) fn into_validated_pair(
        self,
        expected_reservation_nonce_id: &[u8; 32],
        expected_participant_id: &[u8; 32],
        expected_context: &SessionContextV1,
        trusted_chain_id: &TrustedChainIdV1,
        signing_share: &SigningShareV1,
    ) -> Result<SecretNoncePairV1> {
        validate_structural_bytes(&self.plaintext)?;
        if &self.plaintext[10..42] != expected_reservation_nonce_id
            || &self.plaintext[42..74] != expected_participant_id
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let context_len = u32::from_le_bytes(exact_array::<4>(
            "NonceSecretRecordV1 context length",
            &self.plaintext[74..78],
        )?) as usize;
        let context_end = FIXED_PREFIX_LEN + context_len;
        let parsed_context = SessionContextV1::from_bytes(
            &self.plaintext[FIXED_PREFIX_LEN..context_end],
            trusted_chain_id,
            signing_share,
        )?;
        if parsed_context.to_bytes() != expected_context.to_bytes()
            && !parsed_context.is_same_nonce_reservation(expected_context)
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let first = exact_array::<32>(
            "NonceSecretRecordV1 first scalar",
            &self.plaintext[context_end..context_end + 32],
        )?;
        let second = exact_array::<32>(
            "NonceSecretRecordV1 second scalar",
            &self.plaintext[context_end + 32..context_end + 64],
        )?;
        SecretNoncePairV1::from_be_bytes(first, second)
    }
}

fn validate_structural_bytes(bytes: &[u8]) -> Result<()> {
    if !(NonceSecretTransferV1::MIN_ENCODED_LEN..=NonceSecretTransferV1::MAX_ENCODED_LEN)
        .contains(&bytes.len())
    {
        return Err(AdaptorError::InvalidLength {
            object: "NonceSecretRecordV1",
            expected: NonceSecretTransferV1::MIN_ENCODED_LEN,
            actual: bytes.len(),
        });
    }
    if &bytes[..8] != MAGIC {
        return Err(AdaptorError::InvalidContext(
            "invalid nonce secret record magic",
        ));
    }
    if u16::from_le_bytes([bytes[8], bytes[9]]) != VERSION {
        return Err(AdaptorError::InvalidContext(
            "invalid nonce secret record version",
        ));
    }
    if bytes[10..42] == [0; 32] || bytes[42..74] == [0; 32] {
        return Err(AdaptorError::InvalidContext(
            "nonce secret record identifiers must be nonzero",
        ));
    }
    let context_len = u32::from_le_bytes(exact_array::<4>(
        "NonceSecretRecordV1 context length",
        &bytes[74..78],
    )?) as usize;
    let expected_total = FIXED_PREFIX_LEN
        .checked_add(context_len)
        .and_then(|value| value.checked_add(SCALAR_BYTES_LEN))
        .ok_or(AdaptorError::InvalidContext(
            "nonce secret record length overflow",
        ))?;
    if expected_total != bytes.len() {
        return Err(AdaptorError::InvalidLength {
            object: "NonceSecretRecordV1",
            expected: expected_total,
            actual: bytes.len(),
        });
    }
    validate_context_length(&bytes[FIXED_PREFIX_LEN..FIXED_PREFIX_LEN + context_len])
}

fn validate_context_length(context: &[u8]) -> Result<()> {
    if context.len() < 179 {
        return Err(AdaptorError::InvalidLength {
            object: "SessionContextV1",
            expected: 179,
            actual: context.len(),
        });
    }
    let participant_count = usize::from(u16::from_le_bytes([context[174], context[175]]));
    if !(2..=16).contains(&participant_count) {
        return Err(AdaptorError::InvalidContext(
            "nonce secret record participant count is outside 2..=16",
        ));
    }
    let presence_offset = 176usize
        .checked_add(participant_count * 33)
        .and_then(|value| value.checked_add(2))
        .ok_or(AdaptorError::InvalidContext("context length overflow"))?;
    let adaptor_len = match context.get(presence_offset) {
        Some(0x00) => 0,
        Some(0x01) => 33,
        _ => {
            return Err(AdaptorError::InvalidContext(
                "nonce secret record adaptor presence is not canonical",
            ));
        }
    };
    let expected = presence_offset + 1 + adaptor_len;
    if context.len() != expected {
        return Err(AdaptorError::InvalidLength {
            object: "SessionContextV1",
            expected,
            actual: context.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirectionV1, PurposeV1, SessionContextInputsV1, SigningPhaseV1};
    use dom_crypto::PublicKey;

    fn scalar(value: u8) -> SigningShareV1 {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SigningShareV1::from_be_bytes(bytes).expect("canonical test scalar")
    }

    fn point(secret: &SigningShareV1) -> PublicKey {
        secret.public_key().clone()
    }

    fn context(participants: u8, purpose: PurposeV1) -> (SessionContextV1, SigningShareV1) {
        let share = scalar(1);
        let mut roster: Vec<PublicKey> = (1..=participants)
            .map(|value| point(&scalar(value)))
            .collect();
        roster.sort_by_key(PublicKey::to_compressed_bytes);
        let participant_index = roster
            .iter()
            .position(|candidate| candidate == &point(&share))
            .expect("local key in roster") as u16;
        let context = SessionContextV1::new(
            SessionContextInputsV1 {
                chain_id: [1; 32],
                session_id: [2; 32],
                purpose,
                direction: DirectionV1::Initiator,
                signing_phase: SigningPhaseV1::SigNonceCommit,
                template_hash: [3; 32],
                message_digest: [4; 32],
                transcript_hash: [5; 32],
                retry_counter: 0,
                participant_public_keys: roster,
                participant_index,
                adaptor_point: (purpose == PurposeV1::ClaimAdaptor).then(|| point(&scalar(31))),
            },
            &share,
        )
        .expect("valid test context");
        (context, share)
    }

    fn record_bytes(
        participants: u8,
        purpose: PurposeV1,
    ) -> (Zeroizing<Vec<u8>>, SessionContextV1, SigningShareV1) {
        let (context, share) = context(participants, purpose);
        let pair = SecretNoncePairV1::from_be_bytes(scalar_bytes(21), scalar_bytes(22))
            .expect("nonce pair");
        let transfer = NonceSecretTransferV1::from_nonce_pair([7; 32], [8; 32], &context, pair)
            .expect("record");
        let bytes = VaultSecretSealCapabilityV1::new().into_plaintext(transfer);
        (bytes, context, share)
    }

    fn scalar_bytes(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        bytes
    }

    #[test]
    fn exact_minimum_and_maximum_records_roundtrip() {
        for (participants, purpose, expected_len) in [
            (2, PurposeV1::Funding, 387),
            (16, PurposeV1::ClaimAdaptor, 882),
        ] {
            let (bytes, context, share) = record_bytes(participants, purpose);
            assert_eq!(bytes.len(), expected_len);
            let transfer = VaultSecretImportCapabilityV1::new()
                .import(bytes)
                .expect("strict structural record");
            let pair = transfer
                .into_validated_pair(
                    &[7; 32],
                    &[8; 32],
                    &context,
                    &TrustedChainIdV1::from_signed_fixture([1; 32]),
                    &share,
                )
                .expect("semantic record");
            let (first, second) = pair.public_keys().expect("public nonce pair");
            assert_eq!(first, point(&scalar(21)));
            assert_eq!(second, point(&scalar(22)));
        }
    }

    #[test]
    fn truncation_extension_and_closed_fields_fail() {
        let (bytes, _, _) = record_bytes(2, PurposeV1::Funding);
        for length in 0..bytes.len() {
            assert!(VaultSecretImportCapabilityV1::new()
                .import(Zeroizing::new(bytes[..length].to_vec()))
                .is_err());
        }
        let mut extension = bytes.clone();
        extension.push(0);
        assert!(VaultSecretImportCapabilityV1::new()
            .import(extension)
            .is_err());
        for (offset, replacement) in [(0, b'X'), (8, 2), (74, 0xff)] {
            let mut mutation = bytes.clone();
            mutation[offset] = replacement;
            assert!(VaultSecretImportCapabilityV1::new()
                .import(mutation)
                .is_err());
        }
        for range in [10..42, 42..74] {
            let mut mutation = bytes.clone();
            mutation[range].fill(0);
            assert!(VaultSecretImportCapabilityV1::new()
                .import(mutation)
                .is_err());
        }
    }

    #[test]
    fn semantic_binding_and_scalar_mutations_fail_closed() {
        let (bytes, context, share) = record_bytes(2, PurposeV1::Funding);
        let trusted = TrustedChainIdV1::from_signed_fixture([1; 32]);
        for (reservation, participant) in [([9; 32], [8; 32]), ([7; 32], [9; 32])] {
            let transfer = VaultSecretImportCapabilityV1::new()
                .import(bytes.clone())
                .expect("structural record");
            assert!(transfer
                .into_validated_pair(&reservation, &participant, &context, &trusted, &share)
                .is_err());
        }
        for scalar_start in [bytes.len() - 64, bytes.len() - 32] {
            let mut mutation = bytes.clone();
            mutation[scalar_start..scalar_start + 32].fill(0);
            let transfer = VaultSecretImportCapabilityV1::new()
                .import(mutation)
                .expect("structural record");
            assert!(transfer
                .into_validated_pair(&[7; 32], &[8; 32], &context, &trusted, &share)
                .is_err());
        }
    }
}

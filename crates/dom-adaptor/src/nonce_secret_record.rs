//! Ratified encrypted nonce-secret plaintext boundary.

use crate::{AdaptorError, Result, SessionContextV1, TrustedChainIdV1};
use dom_crypto::{ScriptlessSecretNoncePairV1, ScriptlessSecretScalar};
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

impl NonceSecretTransferV1 {
    /// Minimum exact record length (`n = 2`, no adaptor point).
    pub const MIN_ENCODED_LEN: usize = 387;
    /// Maximum exact record length (`n = 16`, adaptor point present).
    pub const MAX_ENCODED_LEN: usize = 882;

    pub(crate) fn from_nonce_pair(
        reservation_nonce_id: [u8; 32],
        participant_id: [u8; 32],
        context: &SessionContextV1,
        pair: ScriptlessSecretNoncePairV1,
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

    /// Accept an owned decrypted buffer from the approved Wallet sealer.
    ///
    /// Structural validation happens before ownership is accepted. Semantic
    /// context and scalar validation happens when the signer consumes this
    /// transfer for its one partial attempt.
    pub fn from_decrypted_plaintext(mut plaintext: Zeroizing<Vec<u8>>) -> Result<Self> {
        if let Err(error) = validate_structural_bytes(&plaintext) {
            plaintext.zeroize();
            return Err(error);
        }
        Ok(Self { plaintext })
    }

    /// Transfer the plaintext by value into the trusted Wallet sealer call.
    ///
    /// The callback receives a temporary borrow only for the duration of the
    /// approved sealing operation. The buffer is zeroized before this method
    /// returns, including when the callback returns an error or unwinds.
    pub fn seal_with<T, E>(
        self,
        sealer: impl FnOnce(&[u8]) -> core::result::Result<T, E>,
    ) -> core::result::Result<T, E> {
        sealer(&self.plaintext)
    }

    pub(crate) fn into_validated_pair(
        self,
        expected_reservation_nonce_id: &[u8; 32],
        expected_participant_id: &[u8; 32],
        expected_context: &SessionContextV1,
        trusted_chain_id: &TrustedChainIdV1,
        signing_share: &ScriptlessSecretScalar,
    ) -> Result<ScriptlessSecretNoncePairV1> {
        validate_structural_bytes(&self.plaintext)?;
        if &self.plaintext[10..42] != expected_reservation_nonce_id
            || &self.plaintext[42..74] != expected_participant_id
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let context_len = u32::from_le_bytes(
            self.plaintext[74..78]
                .try_into()
                .expect("validated fixed context-length field"),
        ) as usize;
        let context_end = FIXED_PREFIX_LEN + context_len;
        let parsed_context = SessionContextV1::from_bytes(
            &self.plaintext[FIXED_PREFIX_LEN..context_end],
            trusted_chain_id,
            signing_share,
        )?;
        if parsed_context.to_bytes() != expected_context.to_bytes() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let first: [u8; 32] = self.plaintext[context_end..context_end + 32]
            .try_into()
            .expect("validated first scalar width");
        let second: [u8; 32] = self.plaintext[context_end + 32..context_end + 64]
            .try_into()
            .expect("validated second scalar width");
        ScriptlessSecretNoncePairV1::from_be_bytes(first, second).map_err(Into::into)
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
    let context_len = u32::from_le_bytes(
        bytes[74..78]
            .try_into()
            .expect("fixed context-length field"),
    ) as usize;
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

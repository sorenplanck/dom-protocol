//! Ratified encrypted nonce-secret plaintext boundary.

use crate::error::exact_array;
use crate::secret_nonce::SecretNoncePairV1;
use crate::{
    AdaptorError, DirectionV1, PurposeV1, Result, SessionContextV1, SigningPhaseV1, SigningShareV1,
    TrustedChainIdV1,
};
use dom_crypto::{blake2b_256_tagged, PublicKey};
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

/// Audit one decrypted `NonceSecretRecordV1` plaintext for canonical structure.
///
/// This is a consuming, no-export Store boundary. It deliberately returns only
/// structural success or failure: it cannot create an import capability,
/// transfer, nonce pair, or signing authorization. The supplied plaintext is
/// compiler-visibly zeroized before this function returns on every path.
/// Passing this audit does not validate scalar canonicity or semantic binding;
/// the capability-gated import path must still perform those checks before use.
pub fn audit_nonce_secret_plaintext_v1(mut plaintext: Zeroizing<Vec<u8>>) -> Result<()> {
    validate_and_zeroize_plaintext(&mut plaintext)
}

/// Public facts expected from one retained nonce-secret record.
///
/// This is an audit request, not an import capability. It contains no scalar,
/// has no codec or Debug implementation, and grants no access to the record.
pub struct NonceSecretPlaintextAuditBindingV1 {
    reservation_nonce_id: [u8; 32],
    participant_id: [u8; 32],
    key_id: [u8; 32],
    session_id: [u8; 32],
    purpose: PurposeV1,
    template_hash: [u8; 32],
    retry_counter: u64,
}

impl NonceSecretPlaintextAuditBindingV1 {
    /// Construct the exact public facts recoverable from a retained reservation.
    pub fn new(
        reservation_nonce_id: [u8; 32],
        participant_id: [u8; 32],
        key_id: [u8; 32],
        session_id: [u8; 32],
        purpose: PurposeV1,
        template_hash: [u8; 32],
        retry_counter: u64,
    ) -> Result<Self> {
        if [
            reservation_nonce_id,
            participant_id,
            key_id,
            session_id,
            template_hash,
        ]
        .contains(&[0; 32])
            || !purpose.is_strict_v1_authorized()
        {
            return Err(AdaptorError::InvalidContext(
                "invalid nonce-secret audit binding",
            ));
        }
        Ok(Self {
            reservation_nonce_id,
            participant_id,
            key_id,
            session_id,
            purpose,
            template_hash,
            retry_counter,
        })
    }
}

/// Consume and audit a sealed plaintext against every retained comparable fact.
///
/// The plaintext is structurally parsed inside its canonical owner, including
/// canonical roster keys, stage, adaptor-point policy and secret scalars. It
/// is compiler-visibly zeroized on every success and error path and never
/// yields a transfer, scalar, context or getter.
pub fn audit_bound_nonce_secret_plaintext_v1(
    mut plaintext: Zeroizing<Vec<u8>>,
    expected: &NonceSecretPlaintextAuditBindingV1,
) -> Result<()> {
    let result = audit_bound_plaintext(&plaintext, expected);
    plaintext.zeroize();
    result
}

fn audit_bound_plaintext(
    plaintext: &[u8],
    expected: &NonceSecretPlaintextAuditBindingV1,
) -> Result<()> {
    validate_structural_bytes(plaintext)?;
    if plaintext[10..42] != expected.reservation_nonce_id
        || plaintext[42..74] != expected.participant_id
    {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let context_len = u32::from_le_bytes(exact_array::<4>(
        "NonceSecretRecordV1 context length",
        &plaintext[74..78],
    )?) as usize;
    let context_end = FIXED_PREFIX_LEN
        .checked_add(context_len)
        .ok_or(AdaptorError::InvalidContext("context length overflow"))?;
    let context = &plaintext[FIXED_PREFIX_LEN..context_end];
    audit_bound_context(context, expected)?;
    let first = exact_array::<32>(
        "NonceSecretRecordV1 first scalar",
        &plaintext[context_end..context_end + 32],
    )?;
    let second = exact_array::<32>(
        "NonceSecretRecordV1 second scalar",
        &plaintext[context_end + 32..context_end + 64],
    )?;
    drop(SecretNoncePairV1::from_be_bytes(first, second)?);
    Ok(())
}

fn audit_bound_context(
    context: &[u8],
    expected: &NonceSecretPlaintextAuditBindingV1,
) -> Result<()> {
    if u16::from_le_bytes([context[0], context[1]]) != SessionContextV1::VERSION
        || context[2..34] == [0; 32]
        || context[34..66] != expected.session_id
        || PurposeV1::try_from(context[66])? != expected.purpose
        || DirectionV1::try_from(context[67]).is_err()
        || SigningPhaseV1::try_from(u16::from_le_bytes([context[68], context[69]]))?
            != SigningPhaseV1::SigNonceCommit
        || context[70..102] != expected.template_hash
        || context[102..134] == [0; 32]
        || context[134..166] == [0; 32]
        || u64::from_le_bytes(exact_array::<8>(
            "SessionContextV1 retry counter",
            &context[166..174],
        )?) != expected.retry_counter
    {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let count = usize::from(u16::from_le_bytes([context[174], context[175]]));
    let roster_end = 176usize
        .checked_add(
            count
                .checked_mul(33)
                .ok_or(AdaptorError::InvalidContext("participant byte overflow"))?,
        )
        .ok_or(AdaptorError::InvalidContext("context length overflow"))?;
    let mut prior: Option<[u8; 33]> = None;
    for encoded in context[176..roster_end].chunks_exact(33) {
        let parsed = PublicKey::from_compressed_bytes(encoded)?;
        let canonical = parsed.to_compressed_bytes();
        if canonical.as_slice() != encoded || prior.is_some_and(|value| value >= canonical) {
            return Err(AdaptorError::InvalidContext(
                "nonce-secret roster is not canonical and unique",
            ));
        }
        prior = Some(canonical);
    }
    let participant_index = usize::from(u16::from_le_bytes(exact_array::<2>(
        "SessionContextV1 participant index",
        &context[roster_end..roster_end + 2],
    )?));
    if participant_index >= count {
        return Err(AdaptorError::InvalidContext(
            "nonce-secret participant index is outside the roster",
        ));
    }
    let local_key_offset = 176usize
        .checked_add(
            participant_index
                .checked_mul(33)
                .ok_or(AdaptorError::InvalidContext("local key offset overflow"))?,
        )
        .ok_or(AdaptorError::InvalidContext("local key offset overflow"))?;
    let mut budget_key_preimage = [0_u8; 65];
    budget_key_preimage[..32].copy_from_slice(&context[2..34]);
    budget_key_preimage[32..].copy_from_slice(&context[local_key_offset..local_key_offset + 33]);
    let derived_key_id = *blake2b_256_tagged(
        crate::DomainTag::VaultBudgetKey.as_str(),
        &budget_key_preimage,
    )
    .as_bytes();
    if derived_key_id != expected.key_id {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let presence_offset = roster_end + 2;
    let adaptor_present = context[presence_offset] == 1;
    match (expected.purpose, adaptor_present) {
        (PurposeV1::ClaimAdaptor, true) => {
            let encoded = &context[presence_offset + 1..];
            if PublicKey::from_compressed_bytes(encoded)?
                .to_compressed_bytes()
                .as_slice()
                != encoded
            {
                return Err(AdaptorError::InvalidContext(
                    "nonce-secret adaptor point is not canonical",
                ));
            }
        }
        (PurposeV1::Refund | PurposeV1::Funding, false) => {}
        _ => return Err(AdaptorError::AuthorizationMismatch),
    }
    Ok(())
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

fn validate_and_zeroize_plaintext(plaintext: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    let result = validate_structural_bytes(plaintext);
    plaintext.zeroize();
    result
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

    fn audit_binding(
        context: &SessionContextV1,
        share: &SigningShareV1,
    ) -> NonceSecretPlaintextAuditBindingV1 {
        let mut key_preimage = [0_u8; 65];
        key_preimage[..32].copy_from_slice(context.chain_id());
        key_preimage[32..].copy_from_slice(&share.public_key().to_compressed_bytes());
        let key_id = *blake2b_256_tagged(crate::DomainTag::VaultBudgetKey.as_str(), &key_preimage)
            .as_bytes();
        NonceSecretPlaintextAuditBindingV1::new(
            [7; 32],
            [8; 32],
            key_id,
            [2; 32],
            PurposeV1::Funding,
            [3; 32],
            0,
        )
        .expect("valid retained audit binding")
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

    #[test]
    fn store_audit_accepts_canonical_plaintext_without_importing_it() {
        let (bytes, _, _) = record_bytes(2, PurposeV1::Funding);
        assert!(audit_nonce_secret_plaintext_v1(bytes).is_ok());
    }

    #[test]
    fn bound_store_audit_requires_every_comparable_retained_fact() {
        let (bytes, context, share) = record_bytes(2, PurposeV1::Funding);
        let binding = audit_binding(&context, &share);
        assert!(audit_bound_nonce_secret_plaintext_v1(bytes.clone(), &binding).is_ok());

        let key_id = binding.key_id;
        for rejected in [
            NonceSecretPlaintextAuditBindingV1::new(
                [9; 32],
                [8; 32],
                key_id,
                [2; 32],
                PurposeV1::Funding,
                [3; 32],
                0,
            ),
            NonceSecretPlaintextAuditBindingV1::new(
                [7; 32],
                [9; 32],
                key_id,
                [2; 32],
                PurposeV1::Funding,
                [3; 32],
                0,
            ),
            NonceSecretPlaintextAuditBindingV1::new(
                [7; 32],
                [8; 32],
                [9; 32],
                [2; 32],
                PurposeV1::Funding,
                [3; 32],
                0,
            ),
            NonceSecretPlaintextAuditBindingV1::new(
                [7; 32],
                [8; 32],
                key_id,
                [9; 32],
                PurposeV1::Funding,
                [3; 32],
                0,
            ),
            NonceSecretPlaintextAuditBindingV1::new(
                [7; 32],
                [8; 32],
                key_id,
                [2; 32],
                PurposeV1::Refund,
                [3; 32],
                0,
            ),
            NonceSecretPlaintextAuditBindingV1::new(
                [7; 32],
                [8; 32],
                key_id,
                [2; 32],
                PurposeV1::Funding,
                [9; 32],
                0,
            ),
            NonceSecretPlaintextAuditBindingV1::new(
                [7; 32],
                [8; 32],
                key_id,
                [2; 32],
                PurposeV1::Funding,
                [3; 32],
                1,
            ),
        ] {
            let rejected = rejected.expect("nonzero alternate binding");
            assert!(audit_bound_nonce_secret_plaintext_v1(bytes.clone(), &rejected).is_err());
        }
    }

    #[test]
    fn bound_store_audit_rejects_cross_reservation_and_cross_chain_transplants() {
        let (bytes, context, share) = record_bytes(2, PurposeV1::Funding);
        let binding = audit_binding(&context, &share);

        let cross_reservation = NonceSecretPlaintextAuditBindingV1::new(
            [9; 32],
            [8; 32],
            binding.key_id,
            [2; 32],
            PurposeV1::Funding,
            [3; 32],
            0,
        )
        .expect("alternate reservation binding");
        assert!(audit_bound_nonce_secret_plaintext_v1(bytes.clone(), &cross_reservation).is_err());

        let mut cross_chain = bytes;
        // Fixed record prefix is 78 bytes; the canonical context chain ID is
        // its bytes 2..34.  This remains structurally valid, so only the
        // retained key-owner derivation can reject the transplant.
        cross_chain[80..112].fill(9);
        assert!(audit_bound_nonce_secret_plaintext_v1(cross_chain, &binding).is_err());
    }

    #[test]
    fn store_audit_rejects_structural_mutations() {
        let (bytes, _, _) = record_bytes(2, PurposeV1::Funding);
        for (offset, replacement) in [(0, b'X'), (8, 2), (74, 0xff)] {
            let mut mutation = bytes.clone();
            mutation[offset] = replacement;
            assert!(audit_nonce_secret_plaintext_v1(mutation).is_err());
        }

        let mut truncated = bytes.clone();
        truncated.pop();
        assert!(audit_nonce_secret_plaintext_v1(truncated).is_err());

        let mut extended = bytes;
        extended.push(0);
        assert!(audit_nonce_secret_plaintext_v1(extended).is_err());
    }

    #[test]
    fn store_audit_zeroizes_success_and_error_inputs() {
        let (mut valid, _, _) = record_bytes(2, PurposeV1::Funding);
        assert!(validate_and_zeroize_plaintext(&mut valid).is_ok());
        assert!(valid.iter().all(|byte| *byte == 0));

        let (mut invalid, _, _) = record_bytes(2, PurposeV1::Funding);
        invalid[0] ^= 1;
        assert!(validate_and_zeroize_plaintext(&mut invalid).is_err());
        assert!(invalid.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn structural_store_audit_does_not_authorize_invalid_scalar_payloads() {
        let (bytes, context, share) = record_bytes(2, PurposeV1::Funding);
        let trusted = TrustedChainIdV1::from_signed_fixture([1; 32]);
        let scalar_start = bytes.len() - SCALAR_BYTES_LEN;

        for replacement in [[0u8; 32], [0xffu8; 32]] {
            let mut mutation = bytes.clone();
            mutation[scalar_start..scalar_start + 32].copy_from_slice(&replacement);

            assert!(audit_nonce_secret_plaintext_v1(mutation.clone()).is_ok());
            let transfer = VaultSecretImportCapabilityV1::new()
                .import(mutation)
                .expect("structurally valid record");
            assert!(transfer
                .into_validated_pair(&[7; 32], &[8; 32], &context, &trusted, &share)
                .is_err());
        }
    }
}

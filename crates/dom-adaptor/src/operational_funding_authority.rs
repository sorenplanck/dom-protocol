//! Durable operational authorization boundary for first funding finalization.

use crate::{AdaptorError, BpStatementV1, Result};
use core::fmt;
use dom_consensus::Transaction;
use std::error::Error;

/// Domain of the canonical M.8 V2 funding-authorization binding.
pub const OPERATIONAL_M8_FUNDING_AUTHORIZATION_BINDING_V2_DOMAIN: &str =
    "DOM:contracts-operational-m8-funding-authorization-binding:v2";
/// Magic reserved for the durable M.8 V2 issuance record owned by Contracts.
pub const OPERATIONAL_M8_FUNDING_ISSUANCE_MAGIC_V2: [u8; 8] = *b"DOMSM8I2";
/// Domain reserved for the durable M.8 V2 issuance record owned by Contracts.
pub const OPERATIONAL_M8_FUNDING_ISSUANCE_V2_DOMAIN: &str =
    "DOM:contracts-operational-m8-funding-issuance:v2";
/// Magic reserved for the durable M.8 V2 funding commit owned by Contracts.
pub const OPERATIONAL_M8_FUNDING_COMMIT_MAGIC_V2: [u8; 8] = *b"DOMSM8C2";
/// Domain reserved for the durable M.8 V2 funding commit owned by Contracts.
pub const OPERATIONAL_M8_FUNDING_COMMIT_V2_DOMAIN: &str =
    "DOM:contracts-operational-m8-funding-commit:v2";

/// Exact public evidence bound by a durable one-shot funding issuance record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalFundingAuthorizationBindingV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    terms_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    bp_statement_hash: [u8; 32],
    funding_template_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    refund_tx_hash: [u8; 32],
    claim_presignature_hash: [u8; 32],
    backup_receipt_hash: [u8; 32],
}

/// Exact public evidence for the M.8 two-phase funding profile.
///
/// Unlike [`OperationalFundingAuthorizationBindingV1`], this profile does not
/// contain a claim adaptor pre-signature hash. M.8 requires real funding
/// anchors to exist before claim signing nonces may be allocated. The binding
/// instead freezes the exact unsigned claim template, its adaptor point, and
/// the complete pre-funding timing/finality policy. Post-confirmation anchor
/// evidence is deliberately outside this pre-funding capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalM8FundingAuthorizationBindingV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    terms_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    bp_statement_hash: [u8; 32],
    funding_template_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    claim_adaptor_point: [u8; 33],
    m8_policy_digest: [u8; 32],
    refund_tx_hash: [u8; 32],
    backup_receipt_hash: [u8; 32],
}

/// Exact M.8 V2 funding authority including bilateral readiness and explicit
/// final-claim roles.
///
/// The first 400 bytes preserve the economic field positions of the frozen
/// M.8 V1 profile, but use a distinct magic and version. The final two fields
/// bind the complete role object and the deterministic bilateral 0x11 vote
/// payload. V1 bytes are never accepted or guessed by length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalM8FundingAuthorizationBindingV2 {
    economic_binding: OperationalM8FundingAuthorizationBindingV1,
    final_claim_role_binding_digest: [u8; 32],
    ready_binding_digest: [u8; 32],
}

/// Complete already-durable evidence from which an operational funding token
/// may be imported.
///
/// The Store constructs this value only after it has persisted and fsynced the
/// exact binding plus a one-shot issuance record. Keeping the proof separate
/// from the import capability makes it impossible for an implementation to
/// omit the immutable record digest or revision accidentally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableOperationalFundingIssuanceV1 {
    binding: OperationalFundingAuthorizationBindingV1,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

/// Complete durable issuance proof for the M.8 two-phase funding profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableOperationalM8FundingIssuanceV1 {
    binding: OperationalM8FundingAuthorizationBindingV1,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

/// Complete durable issuance proof for the M.8 V2 funding profile.
///
/// This proof cannot be imported by the V1 capability. The durable Contracts
/// record must use [`OPERATIONAL_M8_FUNDING_ISSUANCE_MAGIC_V2`] and
/// [`OPERATIONAL_M8_FUNDING_ISSUANCE_V2_DOMAIN`] and copy both V2 digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableOperationalM8FundingIssuanceV2 {
    binding: OperationalM8FundingAuthorizationBindingV2,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

/// Borrowed exact unsigned funding template presented to the Store before
/// operational authorization.
///
/// Construction is lifecycle-private. The Store receives both the canonical
/// signature-omitting bytes and the structured canonical DOM transaction so it
/// can re-run validation and persist exact public evidence rather than trust a
/// caller-supplied digest.
pub struct OperationalFundingUnsignedTemplateV1<'a> {
    transaction: &'a Transaction,
    bp_statement: &'a BpStatementV1,
    canonical_template_bytes: &'a [u8],
    template_hash: &'a [u8; 32],
}

impl OperationalFundingAuthorizationBindingV1 {
    /// Bind the complete ready-to-fund evidence used by the operational store.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        transcript_hash: [u8; 32],
        terms_hash: [u8; 32],
        shared_output_commitment: [u8; 33],
        bp_statement_hash: [u8; 32],
        funding_template_hash: [u8; 32],
        claim_template_hash: [u8; 32],
        refund_tx_hash: [u8; 32],
        claim_presignature_hash: [u8; 32],
        backup_receipt_hash: [u8; 32],
    ) -> Result<Self> {
        if [
            chain_id,
            session_id,
            transcript_hash,
            terms_hash,
            bp_statement_hash,
            funding_template_hash,
            claim_template_hash,
            refund_tx_hash,
            claim_presignature_hash,
            backup_receipt_hash,
        ]
        .contains(&[0; 32])
            || shared_output_commitment == [0; 33]
        {
            return Err(AdaptorError::InvalidContext(
                "operational funding authorization binding fields must be nonzero",
            ));
        }
        dom_crypto::pedersen::Commitment::from_compressed_bytes(&shared_output_commitment)?;
        Ok(Self {
            chain_id,
            session_id,
            transcript_hash,
            terms_hash,
            shared_output_commitment,
            bp_statement_hash,
            funding_template_hash,
            claim_template_hash,
            refund_tx_hash,
            claim_presignature_hash,
            backup_receipt_hash,
        })
    }

    /// DOM chain identity authenticated by the real node adapter.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Session whose durable state reached `FundingAuthorized`.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Ready-to-fund transcript hash.
    pub const fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// Hash of the exact accepted economic terms.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    /// Exact confidential output `C` created once by funding and spent by both
    /// mutually exclusive terminal templates.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        &self.shared_output_commitment
    }

    /// Hash of the complete canonical collaborative-Bulletproof statement.
    pub const fn bp_statement_hash(&self) -> &[u8; 32] {
        &self.bp_statement_hash
    }

    /// Signature-omitting canonical funding template hash.
    pub const fn funding_template_hash(&self) -> &[u8; 32] {
        &self.funding_template_hash
    }

    /// Signature-omitting canonical claim template hash.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Exact fully signed refund transaction hash.
    pub const fn refund_tx_hash(&self) -> &[u8; 32] {
        &self.refund_tx_hash
    }

    /// Hash of the verified claim adaptor pre-signature evidence.
    pub const fn claim_presignature_hash(&self) -> &[u8; 32] {
        &self.claim_presignature_hash
    }

    /// Hash of the complete durable bilateral-backup receipt.
    pub const fn backup_receipt_hash(&self) -> &[u8; 32] {
        &self.backup_receipt_hash
    }

    /// Canonical versioned bytes that the Store issuance record must bind.
    pub fn to_bytes(&self) -> [u8; 363] {
        let mut bytes = [0u8; 363];
        bytes[..8].copy_from_slice(b"DOMF7OPA");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..42].copy_from_slice(&self.chain_id);
        bytes[42..74].copy_from_slice(&self.session_id);
        bytes[74..106].copy_from_slice(&self.transcript_hash);
        bytes[106..138].copy_from_slice(&self.terms_hash);
        bytes[138..171].copy_from_slice(&self.shared_output_commitment);
        bytes[171..203].copy_from_slice(&self.bp_statement_hash);
        bytes[203..235].copy_from_slice(&self.funding_template_hash);
        bytes[235..267].copy_from_slice(&self.claim_template_hash);
        bytes[267..299].copy_from_slice(&self.refund_tx_hash);
        bytes[299..331].copy_from_slice(&self.claim_presignature_hash);
        bytes[331..363].copy_from_slice(&self.backup_receipt_hash);
        bytes
    }
}

impl OperationalM8FundingAuthorizationBindingV1 {
    /// Canonical magic for the DOM-owned M.8 two-phase operational profile.
    pub const MAGIC: [u8; 8] = *b"DOMF7M8A";
    /// Canonical binding version.
    pub const VERSION: u16 = 1;
    /// Explicit profile tag preventing confusion with pre-signed-claim flows.
    pub const PROFILE_TAG: [u8; 4] = *b"M8T2";
    /// Exact canonical encoded length.
    pub const ENCODED_LEN: usize = 400;

    /// Bind all public evidence that must exist before M.8 funding signing.
    ///
    /// `m8_policy_digest` is the digest of the complete immutable M.8 timing
    /// policy, including both legs' anchor/finality rules. A funding-anchor
    /// evidence digest is intentionally not accepted here because such
    /// evidence cannot exist until after this funding transaction confirms.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        transcript_hash: [u8; 32],
        terms_hash: [u8; 32],
        shared_output_commitment: [u8; 33],
        bp_statement_hash: [u8; 32],
        funding_template_hash: [u8; 32],
        claim_template_hash: [u8; 32],
        claim_adaptor_point: [u8; 33],
        m8_policy_digest: [u8; 32],
        refund_tx_hash: [u8; 32],
        backup_receipt_hash: [u8; 32],
    ) -> Result<Self> {
        if [
            chain_id,
            session_id,
            transcript_hash,
            terms_hash,
            bp_statement_hash,
            funding_template_hash,
            claim_template_hash,
            m8_policy_digest,
            refund_tx_hash,
            backup_receipt_hash,
        ]
        .contains(&[0; 32])
            || shared_output_commitment == [0; 33]
            || claim_adaptor_point == [0; 33]
        {
            return Err(AdaptorError::InvalidContext(
                "M.8 operational funding authorization binding fields must be nonzero",
            ));
        }
        dom_crypto::pedersen::Commitment::from_compressed_bytes(&shared_output_commitment)?;
        dom_crypto::PublicKey::from_compressed_bytes(&claim_adaptor_point)?;
        Ok(Self {
            chain_id,
            session_id,
            transcript_hash,
            terms_hash,
            shared_output_commitment,
            bp_statement_hash,
            funding_template_hash,
            claim_template_hash,
            claim_adaptor_point,
            m8_policy_digest,
            refund_tx_hash,
            backup_receipt_hash,
        })
    }

    /// DOM chain identity authenticated by the real node adapter.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Session whose durable state reached M.8 funding authorization.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Ready-to-fund transcript hash.
    pub const fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// Hash of the exact accepted economic terms.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    /// Exact confidential output created by funding and spent by claim/refund.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        &self.shared_output_commitment
    }

    /// Hash of the complete canonical collaborative-Bulletproof statement.
    pub const fn bp_statement_hash(&self) -> &[u8; 32] {
        &self.bp_statement_hash
    }

    /// Signature-omitting canonical funding template hash.
    pub const fn funding_template_hash(&self) -> &[u8; 32] {
        &self.funding_template_hash
    }

    /// Signature-omitting canonical claim template hash.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Exact canonical compressed adaptor point `T=tG` for the later claim.
    pub const fn claim_adaptor_point(&self) -> &[u8; 33] {
        &self.claim_adaptor_point
    }

    /// Digest of the immutable M.8 timing and anchor/finality policy.
    pub const fn m8_policy_digest(&self) -> &[u8; 32] {
        &self.m8_policy_digest
    }

    /// Exact fully signed refund transaction hash.
    pub const fn refund_tx_hash(&self) -> &[u8; 32] {
        &self.refund_tx_hash
    }

    /// Hash of the complete durable bilateral-backup receipt.
    pub const fn backup_receipt_hash(&self) -> &[u8; 32] {
        &self.backup_receipt_hash
    }

    /// Canonical profile-tagged bytes that the Store issuance record binds.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..8].copy_from_slice(&Self::MAGIC);
        bytes[8..10].copy_from_slice(&Self::VERSION.to_le_bytes());
        bytes[10..14].copy_from_slice(&Self::PROFILE_TAG);
        bytes[14..46].copy_from_slice(&self.chain_id);
        bytes[46..78].copy_from_slice(&self.session_id);
        bytes[78..110].copy_from_slice(&self.transcript_hash);
        bytes[110..142].copy_from_slice(&self.terms_hash);
        bytes[142..175].copy_from_slice(&self.shared_output_commitment);
        bytes[175..207].copy_from_slice(&self.bp_statement_hash);
        bytes[207..239].copy_from_slice(&self.funding_template_hash);
        bytes[239..271].copy_from_slice(&self.claim_template_hash);
        bytes[271..304].copy_from_slice(&self.claim_adaptor_point);
        bytes[304..336].copy_from_slice(&self.m8_policy_digest);
        bytes[336..368].copy_from_slice(&self.refund_tx_hash);
        bytes[368..400].copy_from_slice(&self.backup_receipt_hash);
        bytes
    }
}

impl OperationalM8FundingAuthorizationBindingV2 {
    /// Canonical magic for the role-bound M.8 V2 operational profile.
    pub const MAGIC: [u8; 8] = *b"DOMF7M82";
    /// Canonical binding version.
    pub const VERSION: u16 = 2;
    /// Explicit two-phase M.8 profile tag. Its meaning is version-scoped by
    /// [`Self::MAGIC`] and [`Self::VERSION`].
    pub const PROFILE_TAG: [u8; 4] = *b"M8T2";
    /// Exact canonical encoded length.
    pub const ENCODED_LEN: usize = 464;

    /// Extend an already validated M.8 economic binding with the exact
    /// final-claim role and bilateral-ready commitments.
    ///
    /// Keeping the frozen economic object intact avoids a second
    /// caller-shaped list of the same fields at the V2 boundary. The Store
    /// must still reauthenticate the complete role and ready objects before it
    /// imports an issuance capability.
    pub fn new(
        economic_binding: OperationalM8FundingAuthorizationBindingV1,
        final_claim_role_binding_digest: [u8; 32],
        ready_binding_digest: [u8; 32],
    ) -> Result<Self> {
        if final_claim_role_binding_digest == [0; 32] || ready_binding_digest == [0; 32] {
            return Err(AdaptorError::InvalidContext(
                "M.8 V2 role and ready binding digests must be nonzero",
            ));
        }
        Ok(Self {
            economic_binding,
            final_claim_role_binding_digest,
            ready_binding_digest,
        })
    }

    /// Strictly decode the exact V2 representation.
    ///
    /// V1 magic/version, truncation, extension, invalid points and zero fields
    /// all fail closed. The value is reconstructed through [`Self::new`] and
    /// compared byte-for-byte so no non-canonical representation is accepted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(AdaptorError::InvalidLength {
                object: "OperationalM8FundingAuthorizationBindingV2",
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        if bytes.get(..8) != Some(Self::MAGIC.as_slice())
            || bytes.get(8..10) != Some(Self::VERSION.to_le_bytes().as_slice())
            || bytes.get(10..14) != Some(Self::PROFILE_TAG.as_slice())
        {
            return Err(AdaptorError::InvalidContext(
                "invalid M.8 V2 funding authorization header",
            ));
        }
        let economic_binding = OperationalM8FundingAuthorizationBindingV1::new(
            binding_array(bytes, 14)?,
            binding_array(bytes, 46)?,
            binding_array(bytes, 78)?,
            binding_array(bytes, 110)?,
            binding_array(bytes, 142)?,
            binding_array(bytes, 175)?,
            binding_array(bytes, 207)?,
            binding_array(bytes, 239)?,
            binding_array(bytes, 271)?,
            binding_array(bytes, 304)?,
            binding_array(bytes, 336)?,
            binding_array(bytes, 368)?,
        )?;
        let binding = Self::new(
            economic_binding,
            binding_array(bytes, 400)?,
            binding_array(bytes, 432)?,
        )?;
        if binding.to_bytes().as_slice() != bytes {
            return Err(AdaptorError::InvalidContext(
                "non-canonical M.8 V2 funding authorization binding",
            ));
        }
        Ok(binding)
    }

    /// Canonical profile-tagged V2 bytes bound by issuance and commit records.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..OperationalM8FundingAuthorizationBindingV1::ENCODED_LEN]
            .copy_from_slice(&self.economic_binding.to_bytes());
        bytes[..8].copy_from_slice(&Self::MAGIC);
        bytes[8..10].copy_from_slice(&Self::VERSION.to_le_bytes());
        bytes[10..14].copy_from_slice(&Self::PROFILE_TAG);
        bytes[400..432].copy_from_slice(&self.final_claim_role_binding_digest);
        bytes[432..464].copy_from_slice(&self.ready_binding_digest);
        bytes
    }

    /// Domain-separated digest of the exact V2 canonical bytes.
    pub fn digest(&self) -> [u8; 32] {
        *dom_crypto::blake2b_256_tagged(
            OPERATIONAL_M8_FUNDING_AUTHORIZATION_BINDING_V2_DOMAIN,
            &self.to_bytes(),
        )
        .as_bytes()
    }

    /// DOM chain identity authenticated by the real node adapter.
    pub const fn chain_id(&self) -> &[u8; 32] {
        self.economic_binding.chain_id()
    }

    /// Session whose durable state reached M.8 V2 funding authorization.
    pub const fn session_id(&self) -> &[u8; 32] {
        self.economic_binding.session_id()
    }

    /// Ready-to-fund transcript hash.
    pub const fn transcript_hash(&self) -> &[u8; 32] {
        self.economic_binding.transcript_hash()
    }

    /// Hash of the exact accepted economic terms.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        self.economic_binding.terms_hash()
    }

    /// Exact confidential output created by funding.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        self.economic_binding.shared_output_commitment()
    }

    /// Hash of the canonical collaborative-Bulletproof statement.
    pub const fn bp_statement_hash(&self) -> &[u8; 32] {
        self.economic_binding.bp_statement_hash()
    }

    /// Signature-omitting funding template hash.
    pub const fn funding_template_hash(&self) -> &[u8; 32] {
        self.economic_binding.funding_template_hash()
    }

    /// Signature-omitting claim template hash.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        self.economic_binding.claim_template_hash()
    }

    /// Exact canonical compressed adaptor point `T=tG`.
    pub const fn claim_adaptor_point(&self) -> &[u8; 33] {
        self.economic_binding.claim_adaptor_point()
    }

    /// Digest of the immutable M.8 timing and anchor/finality policy.
    pub const fn m8_policy_digest(&self) -> &[u8; 32] {
        self.economic_binding.m8_policy_digest()
    }

    /// Exact fully signed refund transaction hash.
    pub const fn refund_tx_hash(&self) -> &[u8; 32] {
        self.economic_binding.refund_tx_hash()
    }

    /// Hash of the complete durable bilateral-backup receipt.
    pub const fn backup_receipt_hash(&self) -> &[u8; 32] {
        self.economic_binding.backup_receipt_hash()
    }

    /// Digest of the exact self-contained final-claim role binding.
    pub const fn final_claim_role_binding_digest(&self) -> &[u8; 32] {
        &self.final_claim_role_binding_digest
    }

    /// Digest signed identically by both bilateral ReadyToFund voters.
    pub const fn ready_binding_digest(&self) -> &[u8; 32] {
        &self.ready_binding_digest
    }

    /// Frozen M.8 economic evidence extended by this V2 binding.
    pub const fn economic_binding(&self) -> &OperationalM8FundingAuthorizationBindingV1 {
        &self.economic_binding
    }
}

impl DurableOperationalFundingIssuanceV1 {
    /// Construct proof of an exact nonzero durable issuance record.
    pub fn new(
        binding: OperationalFundingAuthorizationBindingV1,
        issuance_record_digest: [u8; 32],
        authorized_revision: u64,
    ) -> Result<Self> {
        if issuance_record_digest == [0; 32] || authorized_revision == 0 {
            return Err(AdaptorError::InvalidContext(
                "operational funding issuance proof must be nonzero",
            ));
        }
        Ok(Self {
            binding,
            issuance_record_digest,
            authorized_revision,
        })
    }

    /// Exact ready-to-fund evidence stored in the issuance record.
    pub const fn binding(&self) -> &OperationalFundingAuthorizationBindingV1 {
        &self.binding
    }

    /// Digest of the immutable authenticated issuance record.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable session revision that owns the issuance record.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

impl DurableOperationalM8FundingIssuanceV1 {
    /// Construct proof of an exact nonzero durable M.8 issuance record.
    pub fn new(
        binding: OperationalM8FundingAuthorizationBindingV1,
        issuance_record_digest: [u8; 32],
        authorized_revision: u64,
    ) -> Result<Self> {
        if issuance_record_digest == [0; 32] || authorized_revision == 0 {
            return Err(AdaptorError::InvalidContext(
                "M.8 operational funding issuance proof must be nonzero",
            ));
        }
        Ok(Self {
            binding,
            issuance_record_digest,
            authorized_revision,
        })
    }

    /// Exact M.8 ready-to-fund evidence stored in the issuance record.
    pub const fn binding(&self) -> &OperationalM8FundingAuthorizationBindingV1 {
        &self.binding
    }

    /// Digest of the immutable authenticated issuance record.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable session revision that owns the issuance record.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

impl DurableOperationalM8FundingIssuanceV2 {
    /// Construct proof of an exact nonzero durable M.8 V2 issuance record.
    pub fn new(
        binding: OperationalM8FundingAuthorizationBindingV2,
        issuance_record_digest: [u8; 32],
        authorized_revision: u64,
    ) -> Result<Self> {
        if issuance_record_digest == [0; 32] || authorized_revision == 0 {
            return Err(AdaptorError::InvalidContext(
                "M.8 V2 operational funding issuance proof must be nonzero",
            ));
        }
        Ok(Self {
            binding,
            issuance_record_digest,
            authorized_revision,
        })
    }

    /// Exact role- and ready-bound evidence stored in the V2 issuance record.
    pub const fn binding(&self) -> &OperationalM8FundingAuthorizationBindingV2 {
        &self.binding
    }

    /// Digest of the immutable authenticated V2 issuance record.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable session revision that owns the V2 issuance record.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

impl<'a> OperationalFundingUnsignedTemplateV1<'a> {
    pub(crate) const fn new(
        transaction: &'a Transaction,
        bp_statement: &'a BpStatementV1,
        canonical_template_bytes: &'a [u8],
        template_hash: &'a [u8; 32],
    ) -> Self {
        Self {
            transaction,
            bp_statement,
            canonical_template_bytes,
            template_hash,
        }
    }

    /// Structured canonical DOM transaction with its kernel signature omitted.
    pub const fn transaction(&self) -> &Transaction {
        self.transaction
    }

    /// Complete canonical BP statement whose aggregate commitment must equal
    /// the exact shared output in all lifecycle templates.
    pub const fn bp_statement(&self) -> &BpStatementV1 {
        self.bp_statement
    }

    /// Exact NAR-002 signature-omitting canonical template bytes.
    pub const fn canonical_template_bytes(&self) -> &[u8] {
        self.canonical_template_bytes
    }

    /// Canonical template hash that must equal the authorization binding.
    pub const fn template_hash(&self) -> &[u8; 32] {
        self.template_hash
    }
}

/// One-shot, process-local authorization to finalize the exact funding
/// template. It has no public constructor, codec, Clone, Copy, or Debug.
pub struct OperationalFundingAuthorizationV1 {
    binding: OperationalFundingAuthorizationBindingV1,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

/// One-shot process-local authority for the exact M.8 funding profile.
///
/// It is a distinct type so a legacy pre-signed-claim issuance cannot be
/// replayed or substituted at the two-phase M.8 finalizer (or vice versa).
pub struct OperationalM8FundingAuthorizationV1 {
    binding: OperationalM8FundingAuthorizationBindingV1,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

/// One-shot process-local authority for the exact role-bound M.8 V2 profile.
///
/// It has no public constructor, codec, `Clone`, `Copy`, or `Debug` and cannot
/// be substituted at either V1 finalization path.
pub struct OperationalM8FundingAuthorizationV2 {
    binding: OperationalM8FundingAuthorizationBindingV2,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

impl OperationalFundingAuthorizationV1 {
    pub(crate) const fn binding(&self) -> &OperationalFundingAuthorizationBindingV1 {
        &self.binding
    }

    /// Store issuance-record digest retained for exact sink cross-checking.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable session revision that issued this authority.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

impl OperationalM8FundingAuthorizationV1 {
    pub(crate) const fn binding(&self) -> &OperationalM8FundingAuthorizationBindingV1 {
        &self.binding
    }

    /// Store issuance-record digest retained for exact sink cross-checking.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable session revision that issued this authority.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

impl OperationalM8FundingAuthorizationV2 {
    pub(crate) const fn binding(&self) -> &OperationalM8FundingAuthorizationBindingV2 {
        &self.binding
    }

    /// Store issuance-record digest retained for exact V2 sink cross-checking.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable session revision that issued this V2 authority.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

/// One-shot authority available only to the lifecycle builder when asking the
/// statically selected Contracts Store to import a durable issuance record.
pub struct OperationalFundingAuthorizationImportCapabilityV1 {
    _private: (),
}

/// One-shot lifecycle authority to import an exact durable M.8 issuance.
pub struct OperationalM8FundingAuthorizationImportCapabilityV1 {
    _private: (),
}

/// One-shot lifecycle authority to import an exact durable M.8 V2 issuance.
pub struct OperationalM8FundingAuthorizationImportCapabilityV2 {
    _private: (),
}

impl OperationalFundingAuthorizationImportCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Import an already persisted, authenticated and one-shot issuance record.
    ///
    /// The Store supplies its immutable record digest and authorized revision;
    /// zero values are rejected. The capability is consumed, so the same call
    /// cannot mint a second operational token.
    pub fn import(
        self,
        expected_binding: &OperationalFundingAuthorizationBindingV1,
        issuance: DurableOperationalFundingIssuanceV1,
    ) -> Result<OperationalFundingAuthorizationV1> {
        if issuance.binding() != expected_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(OperationalFundingAuthorizationV1 {
            binding: issuance.binding,
            issuance_record_digest: issuance.issuance_record_digest,
            authorized_revision: issuance.authorized_revision,
        })
    }
}

impl OperationalM8FundingAuthorizationImportCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Import one already-persisted M.8 issuance after an exact binding check.
    pub fn import(
        self,
        expected_binding: &OperationalM8FundingAuthorizationBindingV1,
        issuance: DurableOperationalM8FundingIssuanceV1,
    ) -> Result<OperationalM8FundingAuthorizationV1> {
        if issuance.binding() != expected_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(OperationalM8FundingAuthorizationV1 {
            binding: issuance.binding,
            issuance_record_digest: issuance.issuance_record_digest,
            authorized_revision: issuance.authorized_revision,
        })
    }
}

impl OperationalM8FundingAuthorizationImportCapabilityV2 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Import one already-persisted V2 issuance after an exact binding check.
    pub fn import(
        self,
        expected_binding: &OperationalM8FundingAuthorizationBindingV2,
        issuance: DurableOperationalM8FundingIssuanceV2,
    ) -> Result<OperationalM8FundingAuthorizationV2> {
        if issuance.binding() != expected_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(OperationalM8FundingAuthorizationV2 {
            binding: issuance.binding,
            issuance_record_digest: issuance.issuance_record_digest,
            authorized_revision: issuance.authorized_revision,
        })
    }
}

/// Static DOM Contracts Store composition for durable funding authorization.
///
/// The implementation must reverify the complete binding against the current
/// `ClaimPrepared` record and exact persisted refund, claim pre-signature and
/// backup evidence, persist+fsync `FundingAuthorized`, durably burn its
/// issuance slot, and only then call `capability.import`. A restart may import
/// a fresh process-local token from that same immutable issuance, but must
/// never create a second issuance/revision and must reject resume after the
/// signed successor consumes it.
pub trait OperationalFundingAuthorizationStoreV1: Sized {
    /// Store-specific redacted error.
    type Error: Error + Send + Sync + 'static;

    /// Durably issue one process-local authority for the exact binding.
    fn issue_operational_funding_authorization(
        &mut self,
        binding: &OperationalFundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalFundingAuthorizationImportCapabilityV1,
    ) -> core::result::Result<OperationalFundingAuthorizationV1, Self::Error>;

    /// Rehydrate process-local authority from the exact already-durable
    /// issuance after a crash, without creating a new record or revision.
    ///
    /// The implementation must authenticate the immutable issuance record,
    /// prove it matches `binding` and `unsigned_template`, reject a terminally
    /// consumed funding successor, and call `capability.import` with the same
    /// issuance digest and authorized revision. It MUST NOT allocate another
    /// issuance slot, advance the revision, or accept caller-supplied success.
    fn resume_operational_funding_authorization(
        &mut self,
        binding: &OperationalFundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalFundingAuthorizationImportCapabilityV1,
    ) -> core::result::Result<OperationalFundingAuthorizationV1, Self::Error>;
}

/// Static Contracts Store composition for M.8 two-phase funding authority.
///
/// The Store must authenticate the policy digest, claim template and adaptor
/// point against its immutable pre-funding record; validate the refund,
/// collaborative proof and backup; persist and fsync a profile-tagged one-shot
/// issuance; then call `capability.import`. It must reject any claim
/// pre-signature evidence at this phase and must not substitute a legacy
/// issuance record. Real funding-anchor evidence is checked later, before the
/// separate claim-signing capability is issued.
pub trait OperationalM8FundingAuthorizationStoreV1: Sized {
    /// Store-specific redacted error.
    type Error: Error + Send + Sync + 'static;

    /// Durably issue one process-local authority for the exact M.8 binding.
    fn issue_operational_m8_funding_authorization(
        &mut self,
        binding: &OperationalM8FundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalM8FundingAuthorizationImportCapabilityV1,
    ) -> core::result::Result<OperationalM8FundingAuthorizationV1, Self::Error>;

    /// Rehydrate the exact already-issued authority without allocating a new
    /// issuance slot or revision.
    fn resume_operational_m8_funding_authorization(
        &mut self,
        binding: &OperationalM8FundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalM8FundingAuthorizationImportCapabilityV1,
    ) -> core::result::Result<OperationalM8FundingAuthorizationV1, Self::Error>;
}

/// Static Contracts Store composition for role-bound M.8 V2 funding.
///
/// Implementations must authenticate the complete final-claim role binding,
/// deterministic ready binding and their exact digests before issuing. The
/// retained issuance must use the V2 magic/domain constants, copy both
/// digests, be persisted and fsynced, and remain disjoint from every V1 record
/// and filename. Resume may re-import only that exact immutable V2 issuance.
pub trait OperationalM8FundingAuthorizationStoreV2: Sized {
    /// Store-specific redacted error.
    type Error: Error + Send + Sync + 'static;

    /// Durably issue one process-local authority for the exact M.8 V2 binding.
    fn issue_operational_m8_funding_authorization_v2(
        &mut self,
        binding: &OperationalM8FundingAuthorizationBindingV2,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalM8FundingAuthorizationImportCapabilityV2,
    ) -> core::result::Result<OperationalM8FundingAuthorizationV2, Self::Error>;

    /// Rehydrate only the exact already-issued V2 authority after a crash.
    fn resume_operational_m8_funding_authorization_v2(
        &mut self,
        binding: &OperationalM8FundingAuthorizationBindingV2,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        capability: OperationalM8FundingAuthorizationImportCapabilityV2,
    ) -> core::result::Result<OperationalM8FundingAuthorizationV2, Self::Error>;
}

fn binding_array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N]> {
    let end = start.checked_add(N).ok_or(AdaptorError::InvalidLength {
        object: "OperationalM8FundingAuthorizationBindingV2 field",
        expected: N,
        actual: 0,
    })?;
    let field = bytes.get(start..end).ok_or(AdaptorError::InvalidLength {
        object: "OperationalM8FundingAuthorizationBindingV2 field",
        expected: N,
        actual: bytes.len().saturating_sub(start),
    })?;
    field.try_into().map_err(|_| AdaptorError::InvalidLength {
        object: "OperationalM8FundingAuthorizationBindingV2 field",
        expected: N,
        actual: field.len(),
    })
}

/// Failure at the lifecycle/store operational authorization boundary.
#[derive(Debug)]
pub enum OperationalFundingAuthorizationError<E> {
    /// Canonical DOM input validation failed.
    Protocol(AdaptorError),
    /// The selected operational store failed closed.
    Store(E),
}

impl<E: fmt::Display> fmt::Display for OperationalFundingAuthorizationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(formatter, "operational funding protocol error: {error}")
            }
            Self::Store(_) => formatter.write_str("operational funding store rejected issuance"),
        }
    }
}

impl<E: Error + Send + Sync + 'static> Error for OperationalFundingAuthorizationError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Store(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(OperationalM8FundingAuthorizationV2: Clone, Copy, fmt::Debug);
    assert_not_impl_any!(OperationalM8FundingAuthorizationImportCapabilityV2: Clone, Copy, fmt::Debug);

    const GENERATOR_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn v1_binding() -> OperationalM8FundingAuthorizationBindingV1 {
        OperationalM8FundingAuthorizationBindingV1::new(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            GENERATOR_COMPRESSED,
            [5; 32],
            [6; 32],
            [7; 32],
            GENERATOR_COMPRESSED,
            [8; 32],
            [9; 32],
            [10; 32],
        )
        .expect("valid V1 recovery binding")
    }

    fn v2_binding() -> OperationalM8FundingAuthorizationBindingV2 {
        OperationalM8FundingAuthorizationBindingV2::new(v1_binding(), [11; 32], [12; 32])
            .expect("valid V2 binding")
    }

    #[test]
    fn v2_codec_preserves_v1_economic_offsets_but_never_the_header() {
        let legacy = v1_binding().to_bytes();
        let binding = v2_binding();
        let bytes = binding.to_bytes();

        assert_eq!(bytes.len(), 464);
        assert_eq!(
            &bytes[..8],
            &OperationalM8FundingAuthorizationBindingV2::MAGIC
        );
        assert_eq!(&bytes[8..10], &2_u16.to_le_bytes());
        assert_ne!(&bytes[..10], &legacy[..10]);
        assert_eq!(&bytes[10..400], &legacy[10..400]);
        assert_eq!(&bytes[400..432], &[11; 32]);
        assert_eq!(&bytes[432..464], &[12; 32]);
        assert_eq!(
            OperationalM8FundingAuthorizationBindingV2::from_bytes(&bytes).expect("roundtrip"),
            binding
        );
    }

    #[test]
    fn v2_codec_fails_closed_on_v1_tamper_or_extension() {
        let binding = v2_binding();
        let bytes = binding.to_bytes();
        assert!(
            OperationalM8FundingAuthorizationBindingV2::from_bytes(&v1_binding().to_bytes())
                .is_err()
        );

        let mut tampered = bytes;
        tampered[0] ^= 1;
        assert!(OperationalM8FundingAuthorizationBindingV2::from_bytes(&tampered).is_err());
        let mut tampered = bytes;
        tampered[400..432].fill(0);
        assert!(OperationalM8FundingAuthorizationBindingV2::from_bytes(&tampered).is_err());
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(OperationalM8FundingAuthorizationBindingV2::from_bytes(&extended).is_err());
    }

    #[test]
    fn role_and_ready_digests_are_distinct_issuance_evidence() {
        let binding = v2_binding();
        let issuance = DurableOperationalM8FundingIssuanceV2::new(binding.clone(), [13; 32], 14)
            .expect("issuance");
        let authority = OperationalM8FundingAuthorizationImportCapabilityV2::new()
            .import(&binding, issuance)
            .expect("exact import");
        assert_eq!(
            authority.binding().final_claim_role_binding_digest(),
            &[11; 32]
        );
        assert_eq!(authority.binding().ready_binding_digest(), &[12; 32]);
        assert_eq!(authority.issuance_record_digest(), &[13; 32]);
        assert_eq!(authority.authorized_revision(), 14);
    }
}

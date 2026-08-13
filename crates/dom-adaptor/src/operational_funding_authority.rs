//! Durable operational authorization boundary for first funding finalization.

use crate::{AdaptorError, BpStatementV1, Result};
use core::fmt;
use dom_consensus::Transaction;
use std::error::Error;

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

/// One-shot authority available only to the lifecycle builder when asking the
/// statically selected Contracts Store to import a durable issuance record.
pub struct OperationalFundingAuthorizationImportCapabilityV1 {
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

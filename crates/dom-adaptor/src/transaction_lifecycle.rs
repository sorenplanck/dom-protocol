//! Real DOM transaction assembly for the Scriptless funding lifecycle.
//!
//! This module is an off-chain builder over the existing canonical DOM
//! [`Transaction`] type. It neither adds a consensus feature nor implements a
//! cryptographic primitive. Collaborative range proofs, DOM Schnorr signatures
//! and adaptor signatures are accepted only through the pinned `dom-crypto`
//! and `dom-adaptor` types and every completed transaction passes the complete
//! DOM consensus transaction validator before its bytes are released.

use crate::{
    canonical_template_v1, AdaptorError, AdaptorPreSignatureV1, AdaptorSecret, BpStatementV1,
    ContractTxRoleV1, OperationalFundingAuthorizationBindingV1,
    OperationalFundingAuthorizationError, OperationalFundingAuthorizationImportCapabilityV1,
    OperationalFundingAuthorizationStoreV1, OperationalFundingAuthorizationV1,
    OperationalFundingUnsignedTemplateV1, OperationalM8FundingAuthorizationBindingV1,
    OperationalM8FundingAuthorizationImportCapabilityV1, OperationalM8FundingAuthorizationStoreV1,
    OperationalM8FundingAuthorizationV1, RangeProof739, Result, SharedCommitmentV1,
};
use dom_consensus::{Transaction, TransactionInput, TransactionKernel, TransactionOutput, ValidationContext, validate_balance_equation, validate_range_proofs, validate_transaction, validate_transaction_structure};
use dom_scriptless_consensus::{scriptless_kernel_message_digest_v1};
use dom_core::{BlockHeight, Timestamp, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{
    blake2b_256, pedersen::Commitment, range_proof_verify, range_proof_verify_with_extra_commit,
    recovery::RecoveryCapsule, PublicKey, SchnorrSignature,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use std::error::Error;

/// A shared output whose exact collaborative proof has passed the unchanged
/// DOM range-proof verifier.
///
/// Proof provenance is intentionally not encoded on chain: a collaborative
/// proof must be indistinguishable from a normal proof. This type therefore
/// proves the enforceable boundary — the agreed shared commitment and exact
/// proof envelope pass the canonical verifier — while the authenticated
/// session proves that the caller obtained the proof collaboratively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSharedOutputV1 {
    output: TransactionOutput,
}

impl VerifiedSharedOutputV1 {
    /// Validate and freeze a collaborative output without a recovery capsule.
    pub fn from_collaborative_proof(
        shared: &SharedCommitmentV1,
        proof: RangeProof739,
    ) -> Result<Self> {
        Self::from_collaborative_proof_and_capsule(shared, proof, None)
    }

    /// Validate and freeze a collaborative output carrying a canonical Wallet
    /// V3 recovery capsule. The exact capsule bytes are the proof's immutable
    /// `extra_commit` transcript input.
    pub fn from_collaborative_proof_and_capsule(
        shared: &SharedCommitmentV1,
        proof: RangeProof739,
        capsule: Option<&RecoveryCapsule>,
    ) -> Result<Self> {
        let commitment = Commitment::from_compressed_bytes(shared.commitment_bytes())?;
        let accepted = match capsule {
            Some(capsule) => range_proof_verify_with_extra_commit(
                shared.commitment_bytes(),
                proof.as_bytes(),
                capsule.as_bytes(),
            )?,
            None => range_proof_verify(shared.commitment_bytes(), proof.as_bytes())?,
        };
        if !accepted {
            return Err(AdaptorError::VerificationFailed(
                "collaborative range proof under the DOM verifier",
            ));
        }
        let output = match capsule {
            Some(capsule) => TransactionOutput::with_recovery_capsule(
                commitment,
                proof.as_bytes().to_vec(),
                capsule,
            )?,
            None => TransactionOutput {
                commitment,
                proof: proof.as_bytes().to_vec(),
            },
        };
        Ok(Self { output })
    }

    /// Exact shared-output commitment.
    pub fn commitment(&self) -> &[u8; 33] {
        self.output.commitment.as_bytes()
    }

    /// Frozen canonical output, including the exact proof envelope.
    pub const fn output(&self) -> &TransactionOutput {
        &self.output
    }
}

/// Frozen Scriptless transaction template with one unsigned DOM kernel.
///
/// The kernel signature bytes are zero only inside this non-serializable
/// builder state. No public method exposes transaction bytes until a role-
/// appropriate finalization path installs a signature and the full consensus
/// validator accepts it.
#[derive(Debug)]
pub struct ScriptlessTransactionTemplateV1 {
    role: ContractTxRoleV1,
    transaction: Transaction,
    canonical_template_bytes: Vec<u8>,
    template_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    refund_lock_height: Option<u64>,
}

impl ScriptlessTransactionTemplateV1 {
    /// Build the exact funding template and insert the verified shared output
    /// at `shared_output_position` without reordering caller-provided change
    /// outputs.
    pub fn funding(
        shared_output: &VerifiedSharedOutputV1,
        inputs: Vec<TransactionInput>,
        mut other_outputs: Vec<TransactionOutput>,
        shared_output_position: usize,
        unsigned_kernel: TransactionKernel,
        offset: [u8; 32],
    ) -> Result<Self> {
        if inputs.is_empty() {
            return Err(AdaptorError::InvalidContext(
                "funding requires at least one canonical input",
            ));
        }
        if inputs
            .iter()
            .any(|input| input.commitment.as_bytes() == shared_output.commitment())
        {
            return Err(AdaptorError::InvalidContext(
                "funding must create, not spend, the shared output",
            ));
        }
        if other_outputs
            .iter()
            .any(|output| output.commitment.as_bytes() == shared_output.commitment())
        {
            return Err(AdaptorError::InvalidContext(
                "funding contains a duplicate shared output",
            ));
        }
        if shared_output_position > other_outputs.len() {
            return Err(AdaptorError::InvalidContext(
                "shared output position exceeds funding output count",
            ));
        }
        other_outputs.insert(shared_output_position, shared_output.output.clone());
        Self::new(
            ContractTxRoleV1::Funding,
            *shared_output.commitment(),
            inputs,
            other_outputs,
            unsigned_kernel,
            offset,
            None,
        )
    }

    /// Build the cooperative adaptor-claim template. V1 spends only the shared
    /// output, has one ordinary PLAIN kernel and carries no on-chain marker.
    pub fn claim(
        shared_output: &VerifiedSharedOutputV1,
        outputs: Vec<TransactionOutput>,
        unsigned_kernel: TransactionKernel,
        offset: [u8; 32],
    ) -> Result<Self> {
        Self::spend(
            ContractTxRoleV1::Claim,
            shared_output,
            outputs,
            unsigned_kernel,
            offset,
            None,
        )
    }

    /// Build the pre-signed absolute-height refund template. The existing
    /// ordinary `HEIGHT_LOCKED` feature is mandatory and the unlock height must
    /// be strictly later than the funding tip used to negotiate the contract.
    pub fn refund(
        shared_output: &VerifiedSharedOutputV1,
        outputs: Vec<TransactionOutput>,
        unsigned_kernel: TransactionKernel,
        offset: [u8; 32],
        funding_tip_height: u64,
    ) -> Result<Self> {
        if unsigned_kernel.features != KERNEL_FEAT_HEIGHT_LOCKED || unsigned_kernel.lock_height == 0
        {
            return Err(AdaptorError::InvalidContext(
                "refund requires the existing nonzero HEIGHT_LOCKED kernel",
            ));
        }
        if unsigned_kernel.lock_height <= funding_tip_height {
            return Err(AdaptorError::InvalidContext(
                "refund lock height must be later than the funding tip",
            ));
        }
        let refund_lock_height = unsigned_kernel.lock_height;
        Self::spend(
            ContractTxRoleV1::Refund,
            shared_output,
            outputs,
            unsigned_kernel,
            offset,
            Some(refund_lock_height),
        )
    }

    fn spend(
        role: ContractTxRoleV1,
        shared_output: &VerifiedSharedOutputV1,
        outputs: Vec<TransactionOutput>,
        unsigned_kernel: TransactionKernel,
        offset: [u8; 32],
        refund_lock_height: Option<u64>,
    ) -> Result<Self> {
        if outputs.is_empty() {
            return Err(AdaptorError::InvalidContext(
                "shared-output spend requires at least one payout output",
            ));
        }
        if outputs
            .iter()
            .any(|output| output.commitment.as_bytes() == shared_output.commitment())
        {
            return Err(AdaptorError::InvalidContext(
                "shared-output spend must not recreate the contract output",
            ));
        }
        Self::new(
            role,
            *shared_output.commitment(),
            vec![TransactionInput {
                commitment: shared_output.output.commitment.clone(),
            }],
            outputs,
            unsigned_kernel,
            offset,
            refund_lock_height,
        )
    }

    fn new(
        role: ContractTxRoleV1,
        shared_output_commitment: [u8; 33],
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        unsigned_kernel: TransactionKernel,
        offset: [u8; 32],
        refund_lock_height: Option<u64>,
    ) -> Result<Self> {
        if unsigned_kernel.excess_signature != [0u8; 65] {
            return Err(AdaptorError::InvalidContext(
                "template kernel signature must be the all-zero placeholder",
            ));
        }
        match role {
            ContractTxRoleV1::Funding | ContractTxRoleV1::Claim => {
                if unsigned_kernel.features != KERNEL_FEAT_PLAIN || unsigned_kernel.lock_height != 0
                {
                    return Err(AdaptorError::InvalidContext(
                        "funding and claim require an ordinary PLAIN kernel",
                    ));
                }
            }
            ContractTxRoleV1::Refund => {
                if unsigned_kernel.features != KERNEL_FEAT_HEIGHT_LOCKED
                    || refund_lock_height != Some(unsigned_kernel.lock_height)
                {
                    return Err(AdaptorError::InvalidContext(
                        "refund feature and frozen lock height disagree",
                    ));
                }
            }
        }
        let transaction = Transaction {
            inputs,
            outputs,
            kernels: vec![unsigned_kernel],
            offset,
        };
        // Signature-independent consensus checks freeze a real, balanced DOM
        // transaction before any nonce or adaptor pre-signature is produced.
        validate_transaction_structure(&transaction)?;
        validate_range_proofs(&transaction)?;
        validate_balance_equation(&transaction)?;
        let (canonical_template_bytes, template_hash) = canonical_template_v1(&transaction)?;
        Ok(Self {
            role,
            transaction,
            canonical_template_bytes,
            template_hash,
            shared_output_commitment,
            refund_lock_height,
        })
    }

    /// Lifecycle role of this template.
    pub const fn role(&self) -> ContractTxRoleV1 {
        self.role
    }

    /// Canonical NAR-002 signature-omitting template hash.
    pub const fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }

    /// Exact shared-output commitment created or spent by this template.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        &self.shared_output_commitment
    }

    /// Signature-independent canonical transaction template.
    pub const fn transaction_template(&self) -> &Transaction {
        &self.transaction
    }

    /// Ask the statically selected Contracts Store to issue a durable,
    /// process-local authorization bound to this exact unsigned funding
    /// template and ready-to-fund evidence.
    // The flat arguments are intentional at this authority boundary: every
    // independently authenticated prerequisite remains visible at the call
    // site and is cross-checked before the Store receives an issuance token.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_funding_v1<Store: OperationalFundingAuthorizationStoreV1>(
        &self,
        chain_id: &[u8; 32],
        session_id: [u8; 32],
        expected_transcript_hash: [u8; 32],
        terms_hash: [u8; 32],
        bp_statement: &BpStatementV1,
        claim_template_hash: [u8; 32],
        refund_tx_hash: [u8; 32],
        claim_presignature_hash: [u8; 32],
        backup_receipt_hash: [u8; 32],
        store: &mut Store,
    ) -> core::result::Result<
        OperationalFundingAuthorizationV1,
        OperationalFundingAuthorizationError<Store::Error>,
    > {
        if self.role != ContractTxRoleV1::Funding {
            return Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::InvalidContext(
                    "operational funding authorization received another transaction role",
                ),
            ));
        }
        if chain_id == &[0; 32] {
            return Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::InvalidContext(
                    "operational funding authorization chain identity is empty",
                ),
            ));
        }
        if bp_statement.chain_id() != *chain_id
            || bp_statement.session_id() != session_id
            || bp_statement.aggregate_commitment().to_compressed_bytes()
                != self.shared_output_commitment
            || self
                .transaction
                .outputs
                .iter()
                .filter(|output| output.commitment.as_bytes() == &self.shared_output_commitment)
                .count()
                != 1
        {
            return Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::AuthorizationMismatch,
            ));
        }
        let binding = OperationalFundingAuthorizationBindingV1::new(
            *chain_id,
            session_id,
            expected_transcript_hash,
            terms_hash,
            self.shared_output_commitment,
            bp_statement.statement_hash(),
            self.template_hash,
            claim_template_hash,
            refund_tx_hash,
            claim_presignature_hash,
            backup_receipt_hash,
        )
        .map_err(OperationalFundingAuthorizationError::Protocol)?;
        store
            .issue_operational_funding_authorization(
                &binding,
                &OperationalFundingUnsignedTemplateV1::new(
                    &self.transaction,
                    bp_statement,
                    &self.canonical_template_bytes,
                    &self.template_hash,
                ),
                OperationalFundingAuthorizationImportCapabilityV1::new(),
            )
            .map_err(OperationalFundingAuthorizationError::Store)
    }

    /// Resume the exact already-issued operational funding authority after a
    /// process crash, without issuing another durable record or revision.
    ///
    /// This repeats all public template/BP/session cross-checks performed by
    /// [`Self::authorize_funding_v1`], then asks the selected Store to
    /// authenticate and import the immutable prior issuance. A Store must
    /// reject the request once the signed funding successor was consumed.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_funding_authorization_v1<Store: OperationalFundingAuthorizationStoreV1>(
        &self,
        chain_id: &[u8; 32],
        session_id: [u8; 32],
        expected_transcript_hash: [u8; 32],
        terms_hash: [u8; 32],
        bp_statement: &BpStatementV1,
        claim_template_hash: [u8; 32],
        refund_tx_hash: [u8; 32],
        claim_presignature_hash: [u8; 32],
        backup_receipt_hash: [u8; 32],
        store: &mut Store,
    ) -> core::result::Result<
        OperationalFundingAuthorizationV1,
        OperationalFundingAuthorizationError<Store::Error>,
    > {
        if self.role != ContractTxRoleV1::Funding {
            return Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::InvalidContext(
                    "operational funding resume received another transaction role",
                ),
            ));
        }
        if chain_id == &[0; 32]
            || bp_statement.chain_id() != *chain_id
            || bp_statement.session_id() != session_id
            || bp_statement.aggregate_commitment().to_compressed_bytes()
                != self.shared_output_commitment
            || self
                .transaction
                .outputs
                .iter()
                .filter(|output| output.commitment.as_bytes() == &self.shared_output_commitment)
                .count()
                != 1
        {
            return Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::AuthorizationMismatch,
            ));
        }
        let binding = OperationalFundingAuthorizationBindingV1::new(
            *chain_id,
            session_id,
            expected_transcript_hash,
            terms_hash,
            self.shared_output_commitment,
            bp_statement.statement_hash(),
            self.template_hash,
            claim_template_hash,
            refund_tx_hash,
            claim_presignature_hash,
            backup_receipt_hash,
        )
        .map_err(OperationalFundingAuthorizationError::Protocol)?;
        store
            .resume_operational_funding_authorization(
                &binding,
                &OperationalFundingUnsignedTemplateV1::new(
                    &self.transaction,
                    bp_statement,
                    &self.canonical_template_bytes,
                    &self.template_hash,
                ),
                OperationalFundingAuthorizationImportCapabilityV1::new(),
            )
            .map_err(OperationalFundingAuthorizationError::Store)
    }

    /// Issue the M.8 two-phase funding authority without allocating claim
    /// signing nonces or requiring a claim adaptor pre-signature.
    ///
    /// The exact claim template and adaptor point are frozen now, together
    /// with the immutable M.8 timing/finality policy. Real funding-anchor
    /// evidence is necessarily produced after funding confirms and therefore
    /// belongs to the later claim-signing gate, not this capability.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_funding_m8_v1<Store: OperationalM8FundingAuthorizationStoreV1>(
        &self,
        chain_id: &[u8; 32],
        session_id: [u8; 32],
        expected_transcript_hash: [u8; 32],
        terms_hash: [u8; 32],
        bp_statement: &BpStatementV1,
        claim_template_hash: [u8; 32],
        expected_adaptor_point: [u8; 33],
        refund_tx_hash: [u8; 32],
        backup_receipt_hash: [u8; 32],
        m8_policy_digest: [u8; 32],
        store: &mut Store,
    ) -> core::result::Result<
        OperationalM8FundingAuthorizationV1,
        OperationalFundingAuthorizationError<Store::Error>,
    > {
        self.validate_operational_funding_inputs(chain_id, session_id, bp_statement, false)?;
        let binding = OperationalM8FundingAuthorizationBindingV1::new(
            *chain_id,
            session_id,
            expected_transcript_hash,
            terms_hash,
            self.shared_output_commitment,
            bp_statement.statement_hash(),
            self.template_hash,
            claim_template_hash,
            expected_adaptor_point,
            m8_policy_digest,
            refund_tx_hash,
            backup_receipt_hash,
        )
        .map_err(OperationalFundingAuthorizationError::Protocol)?;
        store
            .issue_operational_m8_funding_authorization(
                &binding,
                &OperationalFundingUnsignedTemplateV1::new(
                    &self.transaction,
                    bp_statement,
                    &self.canonical_template_bytes,
                    &self.template_hash,
                ),
                OperationalM8FundingAuthorizationImportCapabilityV1::new(),
            )
            .map_err(OperationalFundingAuthorizationError::Store)
    }

    /// Resume the exact already-durable M.8 funding issuance after a crash.
    ///
    /// All public fields and the canonical unsigned template are reconstructed
    /// and rechecked. The Store must import the same issuance digest and
    /// revision and must reject a consumed successor or profile substitution.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_funding_m8_authorization_v1<Store: OperationalM8FundingAuthorizationStoreV1>(
        &self,
        chain_id: &[u8; 32],
        session_id: [u8; 32],
        expected_transcript_hash: [u8; 32],
        terms_hash: [u8; 32],
        bp_statement: &BpStatementV1,
        claim_template_hash: [u8; 32],
        expected_adaptor_point: [u8; 33],
        refund_tx_hash: [u8; 32],
        backup_receipt_hash: [u8; 32],
        m8_policy_digest: [u8; 32],
        store: &mut Store,
    ) -> core::result::Result<
        OperationalM8FundingAuthorizationV1,
        OperationalFundingAuthorizationError<Store::Error>,
    > {
        self.validate_operational_funding_inputs(chain_id, session_id, bp_statement, true)?;
        let binding = OperationalM8FundingAuthorizationBindingV1::new(
            *chain_id,
            session_id,
            expected_transcript_hash,
            terms_hash,
            self.shared_output_commitment,
            bp_statement.statement_hash(),
            self.template_hash,
            claim_template_hash,
            expected_adaptor_point,
            m8_policy_digest,
            refund_tx_hash,
            backup_receipt_hash,
        )
        .map_err(OperationalFundingAuthorizationError::Protocol)?;
        store
            .resume_operational_m8_funding_authorization(
                &binding,
                &OperationalFundingUnsignedTemplateV1::new(
                    &self.transaction,
                    bp_statement,
                    &self.canonical_template_bytes,
                    &self.template_hash,
                ),
                OperationalM8FundingAuthorizationImportCapabilityV1::new(),
            )
            .map_err(OperationalFundingAuthorizationError::Store)
    }

    fn validate_operational_funding_inputs<E>(
        &self,
        chain_id: &[u8; 32],
        session_id: [u8; 32],
        bp_statement: &BpStatementV1,
        resume: bool,
    ) -> core::result::Result<(), OperationalFundingAuthorizationError<E>> {
        if self.role != ContractTxRoleV1::Funding {
            return Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::InvalidContext(if resume {
                    "M.8 operational funding resume received another transaction role"
                } else {
                    "M.8 operational funding authorization received another transaction role"
                }),
            ));
        }
        if chain_id == &[0; 32]
            || bp_statement.chain_id() != *chain_id
            || bp_statement.session_id() != session_id
            || bp_statement.aggregate_commitment().to_compressed_bytes()
                != self.shared_output_commitment
            || self
                .transaction
                .outputs
                .iter()
                .filter(|output| output.commitment.as_bytes() == &self.shared_output_commitment)
                .count()
                != 1
        {
            return Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::AuthorizationMismatch,
            ));
        }
        Ok(())
    }

    /// Finalize funding only after consuming the Contracts Store's durable,
    /// template-bound one-shot operational authorization.
    pub fn finalize_funding(
        self,
        authorization: OperationalFundingAuthorizationV1,
        final_signature: SchnorrSignature,
        chain_id: &[u8; 32],
        current_height: u64,
    ) -> Result<VerifiedFundingTransactionV1> {
        if self.role != ContractTxRoleV1::Funding {
            return Err(AdaptorError::InvalidContext(
                "funding finalizer received another transaction role",
            ));
        }
        if authorization.binding().funding_template_hash() != &self.template_hash
            || authorization.binding().shared_output_commitment() != &self.shared_output_commitment
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        if authorization.binding().chain_id() != chain_id {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let authorization_binding = authorization.binding().clone();
        let issuance_record_digest = *authorization.issuance_record_digest();
        let authorized_revision = authorization.authorized_revision();
        let transaction =
            self.finalize_with_signature(final_signature, chain_id, current_height)?;
        Ok(VerifiedFundingTransactionV1 {
            transaction,
            authorization: VerifiedFundingAuthorizationV1 {
                binding: authorization_binding,
                issuance_record_digest,
                authorized_revision,
            },
        })
    }

    /// Finalize M.8 funding after consuming its distinct profile-bound,
    /// durable one-shot authorization.
    ///
    /// A legacy pre-signed-claim token cannot inhabit the M.8 authorization
    /// type, so profile confusion is rejected statically as well as by the
    /// Store's canonical binding bytes.
    pub fn finalize_funding_m8(
        self,
        authorization: OperationalM8FundingAuthorizationV1,
        final_signature: SchnorrSignature,
        chain_id: &[u8; 32],
        current_height: u64,
    ) -> Result<VerifiedM8FundingTransactionV1> {
        if self.role != ContractTxRoleV1::Funding {
            return Err(AdaptorError::InvalidContext(
                "M.8 funding finalizer received another transaction role",
            ));
        }
        if authorization.binding().funding_template_hash() != &self.template_hash
            || authorization.binding().shared_output_commitment() != &self.shared_output_commitment
            || authorization.binding().chain_id() != chain_id
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let authorization_binding = authorization.binding().clone();
        let issuance_record_digest = *authorization.issuance_record_digest();
        let authorized_revision = authorization.authorized_revision();
        let transaction =
            self.finalize_with_signature(final_signature, chain_id, current_height)?;
        Ok(VerifiedM8FundingTransactionV1 {
            transaction,
            authorization: VerifiedM8FundingAuthorizationV1 {
                binding: authorization_binding,
                issuance_record_digest,
                authorized_revision,
            },
        })
    }

    /// Adapt and finalize a claim with the canonical session-bound adaptor
    /// pre-signature. There is no plain-signature claim escape hatch.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_claim(
        self,
        pre_signature: &AdaptorPreSignatureV1,
        adaptor_secret: &AdaptorSecret,
        expected_transcript_hash: &[u8; 32],
        chain_id: &[u8; 32],
        current_height: u64,
    ) -> Result<VerifiedScriptlessTransactionV1> {
        if self.role != ContractTxRoleV1::Claim {
            return Err(AdaptorError::InvalidContext(
                "claim finalizer received another transaction role",
            ));
        }
        let kernel = self
            .transaction
            .kernels
            .first()
            .ok_or(AdaptorError::InvalidContext("claim kernel is missing"))?;
        let signing_key = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())?;
        let message = scriptless_kernel_message_digest_v1(kernel);
        let signature = pre_signature.adapt(
            adaptor_secret,
            &self.template_hash,
            expected_transcript_hash,
            &signing_key,
            chain_id,
            message.as_bytes(),
        )?;
        self.finalize_with_signature(signature, chain_id, current_height)
    }

    /// Finalize the already co-signed refund and prove that consensus accepts
    /// it at the exact absolute unlock height. The returned bytes remain valid
    /// thereafter, subject only to the shared output still being unspent.
    pub fn finalize_refund(
        self,
        final_signature: SchnorrSignature,
        chain_id: &[u8; 32],
    ) -> Result<VerifiedScriptlessTransactionV1> {
        if self.role != ContractTxRoleV1::Refund {
            return Err(AdaptorError::InvalidContext(
                "refund finalizer received another transaction role",
            ));
        }
        let unlock = self.refund_lock_height.ok_or(AdaptorError::InvalidContext(
            "refund template has no frozen unlock height",
        ))?;
        self.finalize_with_signature(final_signature, chain_id, unlock)
    }

    fn finalize_with_signature(
        mut self,
        final_signature: SchnorrSignature,
        chain_id: &[u8; 32],
        validation_height: u64,
    ) -> Result<VerifiedScriptlessTransactionV1> {
        self.transaction.kernels[0].excess_signature = final_signature.to_bytes();
        validate_transaction(
            &self.transaction,
            &ValidationContext {
                current_height: BlockHeight(validation_height),
                chain_id: *chain_id,
                now: Timestamp(0),
            },
        )?;
        let canonical_bytes = self.transaction.to_bytes()?;
        let roundtrip = Transaction::from_bytes(&canonical_bytes)?;
        if roundtrip != self.transaction {
            return Err(AdaptorError::VerificationFailed(
                "canonical DOM transaction roundtrip",
            ));
        }
        let tx_hash = *blake2b_256(&canonical_bytes).as_bytes();
        Ok(VerifiedScriptlessTransactionV1 {
            role: self.role,
            transaction: self.transaction,
            canonical_bytes,
            tx_hash,
            template_hash: self.template_hash,
            shared_output_commitment: self.shared_output_commitment,
        })
    }
}

/// Fully signed canonical DOM transaction accepted by the real verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedScriptlessTransactionV1 {
    role: ContractTxRoleV1,
    transaction: Transaction,
    canonical_bytes: Vec<u8>,
    tx_hash: [u8; 32],
    template_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
}

/// Public evidence carried by a verified funding transaction for the Store's
/// post-sign persistence/consumption sink. It contains no authorization token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFundingAuthorizationV1 {
    binding: OperationalFundingAuthorizationBindingV1,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

/// Public M.8 issuance evidence carried to the post-sign persistence sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedM8FundingAuthorizationV1 {
    binding: OperationalM8FundingAuthorizationBindingV1,
    issuance_record_digest: [u8; 32],
    authorized_revision: u64,
}

impl VerifiedScriptlessTransactionV1 {
    /// Lifecycle role.
    pub const fn role(&self) -> ContractTxRoleV1 {
        self.role
    }

    /// Fully signed canonical transaction.
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Exact bytes for `/tx/submit` and byte-identical restart retransmission.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// DOM transaction id (`BLAKE2b-256(canonical_bytes)`).
    pub const fn tx_hash(&self) -> &[u8; 32] {
        &self.tx_hash
    }

    /// Signature-omitting NAR-002 template hash.
    pub const fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }

    /// Shared output created by funding or spent by claim/refund.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        &self.shared_output_commitment
    }

    /// Re-run the full real DOM verifier at a caller-supplied canonical height.
    pub fn verify(&self, chain_id: &[u8; 32], current_height: u64) -> Result<()> {
        validate_transaction(
            &self.transaction,
            &ValidationContext {
                current_height: BlockHeight(current_height),
                chain_id: *chain_id,
                now: Timestamp(0),
            },
        )?;
        Ok(())
    }
}

/// Fully verified funding transaction that cannot expose broadcast bytes
/// before the statically selected Store persistence sink consumes it.
///
/// This type deliberately implements no `Clone`, `Copy`, `Debug`, generic
/// serialization, or direct `Transaction`/byte accessor. Public inspection is
/// limited to non-broadcast identifiers and verification. Exact bytes cross
/// the boundary only inside [`OperationalFundingTransactionSinkV1`].
pub struct VerifiedFundingTransactionV1 {
    transaction: VerifiedScriptlessTransactionV1,
    authorization: VerifiedFundingAuthorizationV1,
}

/// Fully verified M.8 funding transaction with no direct byte accessor.
///
/// This type deliberately implements no `Clone`, `Copy`, `Debug`, codec, or
/// direct canonical-byte accessor. Exact bytes are exposed only during the
/// explicit, consuming handoff to an implementation of the profile-specific
/// persistence sink. The public sink trait is a composition boundary, not an
/// attestation that a caller selected a particular trusted implementation.
pub struct VerifiedM8FundingTransactionV1 {
    transaction: VerifiedScriptlessTransactionV1,
    authorization: VerifiedM8FundingAuthorizationV1,
}

impl VerifiedFundingTransactionV1 {
    /// DOM transaction id of the fully verified funding transaction.
    pub const fn tx_hash(&self) -> &[u8; 32] {
        self.transaction.tx_hash()
    }

    /// Signature-omitting template hash bound by the issuance record.
    pub const fn template_hash(&self) -> &[u8; 32] {
        self.transaction.template_hash()
    }

    /// Store-verifiable evidence copied from the consumed authorization.
    pub const fn authorization(&self) -> &VerifiedFundingAuthorizationV1 {
        &self.authorization
    }

    /// Re-run the full real DOM verifier without releasing transaction bytes.
    pub fn verify(&self, chain_id: &[u8; 32], current_height: u64) -> Result<()> {
        self.transaction.verify(chain_id, current_height)
    }

    /// Consume this value into the statically selected Store sink.
    ///
    /// The sink must reverify the complete binding and exact canonical bytes,
    /// persist+fsync them with consumption of the matching one-shot issuance
    /// record, and only then return its own persisted broadcast authority.
    pub fn persist_with_sink_v1<Sink: OperationalFundingTransactionSinkV1>(
        self,
        sink: &mut Sink,
    ) -> core::result::Result<Sink::PersistedFunding, Sink::Error> {
        sink.persist_verified_funding(OperationalFundingPersistenceCapabilityV1 { funding: self })
    }
}

impl VerifiedM8FundingTransactionV1 {
    /// DOM transaction id of the fully verified M.8 funding transaction.
    pub const fn tx_hash(&self) -> &[u8; 32] {
        self.transaction.tx_hash()
    }

    /// Signature-omitting template hash bound by the M.8 issuance record.
    pub const fn template_hash(&self) -> &[u8; 32] {
        self.transaction.template_hash()
    }

    /// Store-verifiable M.8 evidence copied from the consumed authorization.
    pub const fn authorization(&self) -> &VerifiedM8FundingAuthorizationV1 {
        &self.authorization
    }

    /// Re-run the real DOM verifier without releasing transaction bytes.
    pub fn verify(&self, chain_id: &[u8; 32], current_height: u64) -> Result<()> {
        self.transaction.verify(chain_id, current_height)
    }

    /// Consume this value into the caller-selected M.8 Store sink.
    ///
    /// Production callers must select their trusted persistence Store here;
    /// the type system enforces a consuming capability handoff but does not
    /// authenticate a particular downstream trait implementation.
    pub fn persist_with_m8_sink_v1<Sink: OperationalM8FundingTransactionSinkV1>(
        self,
        sink: &mut Sink,
    ) -> core::result::Result<Sink::PersistedFunding, Sink::Error> {
        sink.persist_verified_m8_funding(OperationalM8FundingPersistenceCapabilityV1 {
            funding: self,
        })
    }
}

/// One-shot post-sign capability delivered only to the selected Store sink.
///
/// It owns the verified funding transaction and its issuance evidence. The
/// Store may inspect exact canonical content while durably consuming the
/// issuance record; ordinary lifecycle callers never receive this capability.
pub struct OperationalFundingPersistenceCapabilityV1 {
    funding: VerifiedFundingTransactionV1,
}

/// One-shot post-sign capability for the exact M.8 funding profile.
///
/// This capability can only be created by the consuming handoff above, but a
/// downstream crate can implement the public sink trait and inspect it. Trust
/// in durable persistence and issuance consumption therefore remains an
/// operational property of the selected Store implementation.
pub struct OperationalM8FundingPersistenceCapabilityV1 {
    funding: VerifiedM8FundingTransactionV1,
}

impl OperationalFundingPersistenceCapabilityV1 {
    /// Fully signed canonical transaction for Store-side revalidation.
    pub const fn transaction(&self) -> &Transaction {
        self.funding.transaction.transaction()
    }

    /// Exact canonical bytes that must be fsynced before broadcast.
    pub fn canonical_bytes(&self) -> &[u8] {
        self.funding.transaction.canonical_bytes()
    }

    /// DOM transaction id of the exact canonical bytes.
    pub const fn tx_hash(&self) -> &[u8; 32] {
        self.funding.transaction.tx_hash()
    }

    /// Signature-omitting funding template hash.
    pub const fn template_hash(&self) -> &[u8; 32] {
        self.funding.transaction.template_hash()
    }

    /// Shared output created by this funding transaction.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        self.funding.transaction.shared_output_commitment()
    }

    /// Exact operational issuance evidence to consume atomically.
    pub const fn authorization(&self) -> &VerifiedFundingAuthorizationV1 {
        self.funding.authorization()
    }

    /// Re-run the complete DOM verifier before committing the broadcast row.
    pub fn verify(&self, chain_id: &[u8; 32], current_height: u64) -> Result<()> {
        self.funding.verify(chain_id, current_height)
    }
}

impl OperationalM8FundingPersistenceCapabilityV1 {
    /// Fully signed canonical transaction for Store-side revalidation.
    pub const fn transaction(&self) -> &Transaction {
        self.funding.transaction.transaction()
    }

    /// Exact canonical bytes that must be fsynced before broadcast.
    pub fn canonical_bytes(&self) -> &[u8] {
        self.funding.transaction.canonical_bytes()
    }

    /// DOM transaction id of the exact canonical bytes.
    pub const fn tx_hash(&self) -> &[u8; 32] {
        self.funding.transaction.tx_hash()
    }

    /// Signature-omitting funding template hash.
    pub const fn template_hash(&self) -> &[u8; 32] {
        self.funding.transaction.template_hash()
    }

    /// Shared output created by this funding transaction.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        self.funding.transaction.shared_output_commitment()
    }

    /// Exact M.8 issuance evidence to consume atomically.
    pub const fn authorization(&self) -> &VerifiedM8FundingAuthorizationV1 {
        self.funding.authorization()
    }

    /// Re-run the complete DOM verifier before committing broadcast bytes.
    pub fn verify(&self, chain_id: &[u8; 32], current_height: u64) -> Result<()> {
        self.funding.verify(chain_id, current_height)
    }
}

/// Static post-sign Store composition for a verified funding transaction.
///
/// Implementations must reject any mismatch among the issuance record,
/// session/transcript, unsigned template hash, signed canonical transaction,
/// txid, refund, claim pre-signature and backup evidence. On success they must
/// atomically persist the byte-identical transaction and durably consume the
/// one-shot issuance record before returning a broadcast-capable value.
pub trait OperationalFundingTransactionSinkV1: Sized {
    /// Store-specific redacted error.
    type Error: Error + Send + Sync + 'static;

    /// Store-owned artifact proving exact funding bytes are durable and the
    /// matching issuance record has been consumed.
    type PersistedFunding;

    /// Consume the only capability that reveals exact signed funding bytes.
    fn persist_verified_funding(
        &mut self,
        capability: OperationalFundingPersistenceCapabilityV1,
    ) -> core::result::Result<Self::PersistedFunding, Self::Error>;
}

/// Static post-sign Store composition for M.8 funding.
///
/// Implementations must authenticate the exact M.8 profile binding and its
/// issuance record, atomically persist the byte-identical signed transaction,
/// and consume the issuance before returning a broadcast-capable artifact.
pub trait OperationalM8FundingTransactionSinkV1: Sized {
    /// Store-specific redacted error.
    type Error: Error + Send + Sync + 'static;

    /// Store-owned artifact proving durable bytes and issuance consumption.
    type PersistedFunding;

    /// Consume the M.8 capability that reveals signed funding bytes.
    fn persist_verified_m8_funding(
        &mut self,
        capability: OperationalM8FundingPersistenceCapabilityV1,
    ) -> core::result::Result<Self::PersistedFunding, Self::Error>;
}

impl VerifiedFundingAuthorizationV1 {
    /// Complete ready-to-fund evidence binding consumed before signing.
    pub const fn binding(&self) -> &OperationalFundingAuthorizationBindingV1 {
        &self.binding
    }

    /// Exact immutable Store issuance-record digest.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable `FundingAuthorized` session revision.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

impl VerifiedM8FundingAuthorizationV1 {
    /// Complete profile-tagged pre-funding evidence binding.
    pub const fn binding(&self) -> &OperationalM8FundingAuthorizationBindingV1 {
        &self.binding
    }

    /// Exact immutable Store issuance-record digest.
    pub const fn issuance_record_digest(&self) -> &[u8; 32] {
        &self.issuance_record_digest
    }

    /// Durable M.8 funding-authorized session revision.
    pub const fn authorized_revision(&self) -> u64 {
        self.authorized_revision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregate_public_nonces_v1, aggregate_shared_commitment_v1, combine_decoy_capsule_v1,
        contribute_blinding_share_v1, AggregateBpRound1, AggregateBpRound2, BpStatementV1,
        CollaborativeRangeProof, DecoyContributionV1, DirectionV1, DomCollaborativeRangeProofV1,
        DurableOperationalFundingIssuanceV1, DurableOperationalM8FundingIssuanceV1,
        PendingCommonNonce, SessionId, SigningShareV1, TrustedChainIdV1,
    };
    use dom_core::{Amount, Hash256};
    use dom_crypto::{
        pedersen::BlindingFactor, range_proof_prove_bytes, schnorr_challenge, schnorr_sign,
        PartialSig, SecretKey,
    };
    use k256::elliptic_curve::PrimeField;

    fn scalar(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        bytes
    }

    fn blinding(value: u8) -> BlindingFactor {
        BlindingFactor::from_bytes(scalar(value)).expect("canonical blinding")
    }

    fn signing_share(value: u8) -> SigningShareV1 {
        SigningShareV1::from_be_bytes(scalar(value)).expect("canonical share")
    }

    fn output(value: u64, blind: &BlindingFactor) -> TransactionOutput {
        let commitment = Commitment::commit(value, blind);
        let (proof, proved_commitment) =
            range_proof_prove_bytes(value, blind).expect("range proof");
        assert_eq!(proved_commitment, *commitment.as_bytes());
        TransactionOutput { commitment, proof }
    }

    fn unsigned_kernel(
        fee: u64,
        lock_height: u64,
        excess_blinding: &BlindingFactor,
    ) -> TransactionKernel {
        TransactionKernel {
            features: if lock_height == 0 {
                KERNEL_FEAT_PLAIN
            } else {
                KERNEL_FEAT_HEIGHT_LOCKED
            },
            fee: Amount::from_noms(fee).expect("fee"),
            lock_height,
            excess: Commitment::commit(0, excess_blinding),
            excess_signature: [0u8; 65],
        }
    }

    fn sign_kernel(
        kernel: &TransactionKernel,
        excess_blinding: &BlindingFactor,
        chain_id: &[u8; 32],
    ) -> SchnorrSignature {
        let secret = SecretKey::from_bytes(excess_blinding.as_bytes()).expect("kernel secret");
        let message = scriptless_kernel_message_digest_v1(kernel);
        schnorr_sign(&secret, message.as_bytes(), chain_id).expect("DOM kernel signature")
    }

    struct SharedFixture {
        output: VerifiedSharedOutputV1,
        aggregate_blinding: BlindingFactor,
        chain: TrustedChainIdV1,
        statement: BpStatementV1,
    }

    fn shared_fixture(value: u64) -> SharedFixture {
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            dom_core::NETWORK_MAGIC_REGTEST,
            &Hash256::from_bytes([0x11; 32]),
        );
        let session_id = [0x22; 32];
        let participant_ids = vec![[0x31; 32], [0x42; 32]];
        let shares = [signing_share(3), signing_share(5)];
        let roles = [DirectionV1::Initiator, DirectionV1::Responder];
        let terms_hash = [0x55; 32];
        let capsule_hash = [0x66; 32];
        let contributions = (0..2)
            .map(|index| {
                contribute_blinding_share_v1(
                    &chain,
                    session_id,
                    &participant_ids,
                    roles[index],
                    index as u16,
                    &shares[index],
                    terms_hash,
                    capsule_hash,
                )
                .expect("share contribution")
            })
            .collect::<Vec<_>>();
        let shared = aggregate_shared_commitment_v1(
            &chain,
            session_id,
            &participant_ids,
            value,
            terms_hash,
            capsule_hash,
            &contributions,
        )
        .expect("shared commitment");
        let commitment_shares = shares
            .iter()
            .map(|share| share.public_key().clone())
            .collect::<Vec<_>>();
        let aggregate_commitment =
            PublicKey::from_compressed_bytes(shared.commitment_bytes()).expect("shared point");
        let decoy_session = SessionId::from_bytes(session_id).expect("decoy session");
        let local_decoy = DecoyContributionV1::derive(&shares[0], &decoy_session);
        let remote_decoy = DecoyContributionV1::derive(&shares[1], &decoy_session);
        let remote_decoy_commitment = remote_decoy.commitment();
        let capsule = combine_decoy_capsule_v1(
            &local_decoy.into_reveal(),
            &remote_decoy.into_reveal(),
            &remote_decoy_commitment,
        )
        .expect("canonical collaborative recovery capsule");
        let statement = BpStatementV1::new(
            &chain,
            session_id,
            participant_ids,
            value,
            commitment_shares,
            aggregate_commitment,
            Some(*blake2b_256(capsule.as_bytes()).as_bytes()),
        )
        .expect("BP statement");
        let driver_a = DomCollaborativeRangeProofV1::new(&statement, capsule.as_bytes().to_vec())
            .expect("driver A");
        let driver_b = DomCollaborativeRangeProofV1::new(&statement, capsule.as_bytes().to_vec())
            .expect("driver B");
        let (pending_a, commitment_a) =
            PendingCommonNonce::new(&statement, 0, &shares[0]).expect("pending A");
        let (pending_b, commitment_b) =
            PendingCommonNonce::new(&statement, 1, &shares[1]).expect("pending B");
        let accepted_common = [commitment_a, commitment_b];
        let reveal_a = pending_a.reveal_bytes();
        let reveal_b = pending_b.reveal_bytes();
        let local_a = pending_a
            .finish(
                &statement,
                &accepted_common,
                vec![reveal_a.clone(), reveal_b.clone()],
            )
            .expect("common A");
        let local_b = pending_b
            .finish(&statement, &accepted_common, vec![reveal_a, reveal_b])
            .expect("common B");
        let round1_a = driver_a.round1(&statement, &local_a).expect("round1 A");
        let round1_b = driver_b.round1(&statement, &local_b).expect("round1 B");
        let accepted_round1 = [round1_a.reveal_commitment(), round1_b.reveal_commitment()];
        let aggregate_round1 =
            AggregateBpRound1::new(&statement, &accepted_round1, &[round1_a, round1_b])
                .expect("aggregate round1");
        let round2_a = driver_a
            .round2(&statement, &local_a, &aggregate_round1)
            .expect("round2 A");
        let round2_b = driver_b
            .round2(&statement, &local_b, &aggregate_round1)
            .expect("round2 B");
        let aggregate_round2 =
            AggregateBpRound2::new(&statement, vec![round2_a, round2_b]).expect("aggregate round2");
        let proof = driver_a
            .finalize(&statement, &aggregate_round1, &aggregate_round2)
            .expect("collaborative proof");
        let output = VerifiedSharedOutputV1::from_collaborative_proof_and_capsule(
            &shared,
            proof,
            Some(&capsule),
        )
        .expect("verified");
        let aggregate_blinding = blinding(8);
        assert_eq!(
            output.commitment(),
            Commitment::commit(value, &aggregate_blinding).as_bytes()
        );
        SharedFixture {
            output,
            aggregate_blinding,
            chain,
            statement,
        }
    }

    #[derive(Default)]
    struct TestAuthorizationStore {
        issuance: Option<DurableOperationalFundingIssuanceV1>,
        issue_count: usize,
        resume_count: usize,
        consumed: bool,
    }

    fn validate_unsigned_authorization_view(
        binding: &OperationalFundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
    ) -> core::result::Result<(), std::io::Error> {
        let (canonical_bytes, template_hash) =
            canonical_template_v1(unsigned_template.transaction())
                .map_err(std::io::Error::other)?;
        if canonical_bytes != unsigned_template.canonical_template_bytes()
            || &template_hash != unsigned_template.template_hash()
            || binding.funding_template_hash() != unsigned_template.template_hash()
            || binding.bp_statement_hash() != &unsigned_template.bp_statement().statement_hash()
            || binding.shared_output_commitment()
                != &unsigned_template
                    .bp_statement()
                    .aggregate_commitment()
                    .to_compressed_bytes()
        {
            return Err(std::io::Error::other("unsigned funding template mismatch"));
        }
        Ok(())
    }

    impl OperationalFundingAuthorizationStoreV1 for TestAuthorizationStore {
        type Error = std::io::Error;

        fn issue_operational_funding_authorization(
            &mut self,
            binding: &OperationalFundingAuthorizationBindingV1,
            unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
            capability: OperationalFundingAuthorizationImportCapabilityV1,
        ) -> core::result::Result<OperationalFundingAuthorizationV1, Self::Error> {
            validate_unsigned_authorization_view(binding, unsigned_template)?;
            if self.issuance.is_some() || self.consumed {
                return Err(std::io::Error::other("funding issuance already exists"));
            }
            let issuance = DurableOperationalFundingIssuanceV1::new(binding.clone(), [0x75; 32], 7)
                .map_err(std::io::Error::other)?;
            self.issuance = Some(issuance.clone());
            self.issue_count += 1;
            capability
                .import(binding, issuance)
                .map_err(std::io::Error::other)
        }

        fn resume_operational_funding_authorization(
            &mut self,
            binding: &OperationalFundingAuthorizationBindingV1,
            unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
            capability: OperationalFundingAuthorizationImportCapabilityV1,
        ) -> core::result::Result<OperationalFundingAuthorizationV1, Self::Error> {
            validate_unsigned_authorization_view(binding, unsigned_template)?;
            if self.consumed {
                return Err(std::io::Error::other("funding issuance was consumed"));
            }
            let issuance = self
                .issuance
                .clone()
                .ok_or_else(|| std::io::Error::other("funding issuance does not exist"))?;
            if issuance.binding() != binding {
                return Err(std::io::Error::other("funding issuance binding mismatch"));
            }
            self.resume_count += 1;
            capability
                .import(binding, issuance)
                .map_err(std::io::Error::other)
        }
    }

    #[derive(Default)]
    struct TestM8AuthorizationStore {
        issuance: Option<DurableOperationalM8FundingIssuanceV1>,
        issue_count: usize,
        resume_count: usize,
        consumed: bool,
    }

    fn validate_unsigned_m8_authorization_view(
        binding: &OperationalM8FundingAuthorizationBindingV1,
        unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
    ) -> core::result::Result<(), std::io::Error> {
        let (canonical_bytes, template_hash) =
            canonical_template_v1(unsigned_template.transaction())
                .map_err(std::io::Error::other)?;
        if canonical_bytes != unsigned_template.canonical_template_bytes()
            || &template_hash != unsigned_template.template_hash()
            || binding.funding_template_hash() != unsigned_template.template_hash()
            || binding.bp_statement_hash() != &unsigned_template.bp_statement().statement_hash()
            || binding.shared_output_commitment()
                != &unsigned_template
                    .bp_statement()
                    .aggregate_commitment()
                    .to_compressed_bytes()
        {
            return Err(std::io::Error::other(
                "unsigned M.8 funding template mismatch",
            ));
        }
        Ok(())
    }

    impl OperationalM8FundingAuthorizationStoreV1 for TestM8AuthorizationStore {
        type Error = std::io::Error;

        fn issue_operational_m8_funding_authorization(
            &mut self,
            binding: &OperationalM8FundingAuthorizationBindingV1,
            unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
            capability: OperationalM8FundingAuthorizationImportCapabilityV1,
        ) -> core::result::Result<OperationalM8FundingAuthorizationV1, Self::Error> {
            validate_unsigned_m8_authorization_view(binding, unsigned_template)?;
            if self.issuance.is_some() || self.consumed {
                return Err(std::io::Error::other("M.8 funding issuance already exists"));
            }
            let issuance =
                DurableOperationalM8FundingIssuanceV1::new(binding.clone(), [0x85; 32], 8)
                    .map_err(std::io::Error::other)?;
            self.issuance = Some(issuance.clone());
            self.issue_count += 1;
            capability
                .import(binding, issuance)
                .map_err(std::io::Error::other)
        }

        fn resume_operational_m8_funding_authorization(
            &mut self,
            binding: &OperationalM8FundingAuthorizationBindingV1,
            unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
            capability: OperationalM8FundingAuthorizationImportCapabilityV1,
        ) -> core::result::Result<OperationalM8FundingAuthorizationV1, Self::Error> {
            validate_unsigned_m8_authorization_view(binding, unsigned_template)?;
            if self.consumed {
                return Err(std::io::Error::other("M.8 funding issuance was consumed"));
            }
            let issuance = self
                .issuance
                .clone()
                .ok_or_else(|| std::io::Error::other("M.8 funding issuance does not exist"))?;
            if issuance.binding() != binding {
                return Err(std::io::Error::other(
                    "M.8 funding issuance binding mismatch",
                ));
            }
            self.resume_count += 1;
            capability
                .import(binding, issuance)
                .map_err(std::io::Error::other)
        }
    }

    struct TestFundingSink {
        chain_id: [u8; 32],
        height: u64,
        stored_bytes: Option<Vec<u8>>,
    }

    impl OperationalFundingTransactionSinkV1 for TestFundingSink {
        type Error = std::io::Error;
        type PersistedFunding = [u8; 32];

        fn persist_verified_funding(
            &mut self,
            capability: OperationalFundingPersistenceCapabilityV1,
        ) -> core::result::Result<Self::PersistedFunding, Self::Error> {
            capability
                .verify(&self.chain_id, self.height)
                .map_err(std::io::Error::other)?;
            if capability.authorization().binding().funding_template_hash()
                != capability.template_hash()
                || capability.authorization().issuance_record_digest() != &[0x75; 32]
                || capability.authorization().authorized_revision() != 7
            {
                return Err(std::io::Error::other(
                    "funding persistence evidence mismatch",
                ));
            }
            let tx_hash = *capability.tx_hash();
            self.stored_bytes = Some(capability.canonical_bytes().to_vec());
            Ok(tx_hash)
        }
    }

    struct TestM8FundingSink {
        chain_id: [u8; 32],
        height: u64,
        stored_bytes: Option<Vec<u8>>,
    }

    impl OperationalM8FundingTransactionSinkV1 for TestM8FundingSink {
        type Error = std::io::Error;
        type PersistedFunding = [u8; 32];

        fn persist_verified_m8_funding(
            &mut self,
            capability: OperationalM8FundingPersistenceCapabilityV1,
        ) -> core::result::Result<Self::PersistedFunding, Self::Error> {
            capability
                .verify(&self.chain_id, self.height)
                .map_err(std::io::Error::other)?;
            if capability.authorization().binding().funding_template_hash()
                != capability.template_hash()
                || capability.authorization().issuance_record_digest() != &[0x85; 32]
                || capability.authorization().authorized_revision() != 8
            {
                return Err(std::io::Error::other(
                    "M.8 funding persistence evidence mismatch",
                ));
            }
            let tx_hash = *capability.tx_hash();
            self.stored_bytes = Some(capability.canonical_bytes().to_vec());
            Ok(tx_hash)
        }
    }

    #[test]
    fn legacy_profile_still_requires_nonzero_claim_presignature_hash() {
        let shared = shared_fixture(90);
        let chain_id = *shared.chain.as_bytes();
        let input_blinding = blinding(11);
        let excess_blinding = shared
            .aggregate_blinding
            .sub(&input_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero excess");
        let template = ScriptlessTransactionTemplateV1::funding(
            &shared.output,
            vec![TransactionInput {
                commitment: Commitment::commit(100, &input_blinding),
            }],
            Vec::new(),
            0,
            unsigned_kernel(10, 0, &excess_blinding),
            [0u8; 32],
        )
        .expect("funding template");
        let mut store = TestAuthorizationStore::default();
        let result = template.authorize_funding_v1(
            &chain_id,
            shared.statement.session_id(),
            [0x71; 32],
            [0x55; 32],
            &shared.statement,
            [0x76; 32],
            [0x72; 32],
            [0; 32],
            [0x74; 32],
            &mut store,
        );
        assert!(matches!(
            result,
            Err(OperationalFundingAuthorizationError::Protocol(
                AdaptorError::InvalidContext(_)
            ))
        ));
        assert_eq!(store.issue_count, 0);
        assert!(store.issuance.is_none());
    }

    #[test]
    fn m8_two_phase_funding_authorizes_without_claim_nonce_or_presignature() {
        let shared = shared_fixture(90);
        let chain_id = *shared.chain.as_bytes();
        let input_blinding = blinding(11);
        let excess_blinding = shared
            .aggregate_blinding
            .sub(&input_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero excess");
        let kernel = unsigned_kernel(10, 0, &excess_blinding);
        let signature = sign_kernel(&kernel, &excess_blinding, &chain_id);
        let template = ScriptlessTransactionTemplateV1::funding(
            &shared.output,
            vec![TransactionInput {
                commitment: Commitment::commit(100, &input_blinding),
            }],
            Vec::new(),
            0,
            kernel,
            [0u8; 32],
        )
        .expect("funding template");
        let template_hash = *template.template_hash();
        let adaptor_point = SecretKey::from_bytes(&scalar(13))
            .expect("adaptor secret fixture")
            .public_key()
            .to_compressed_bytes();
        let policy_digest = [0x79; 32];
        let mut store = TestM8AuthorizationStore::default();
        let authorization = template
            .authorize_funding_m8_v1(
                &chain_id,
                shared.statement.session_id(),
                [0x71; 32],
                [0x55; 32],
                &shared.statement,
                [0x76; 32],
                adaptor_point,
                [0x72; 32],
                [0x74; 32],
                policy_digest,
                &mut store,
            )
            .expect("M.8 pre-funding authority without claim signing");
        let funding = template
            .finalize_funding_m8(authorization, signature, &chain_id, 5)
            .expect("verified M.8 funding");
        assert_eq!(funding.template_hash(), &template_hash);
        let binding = funding.authorization().binding();
        assert_eq!(binding.claim_template_hash(), &[0x76; 32]);
        assert_eq!(binding.claim_adaptor_point(), &adaptor_point);
        assert_eq!(binding.m8_policy_digest(), &policy_digest);
        assert_eq!(binding.refund_tx_hash(), &[0x72; 32]);
        assert_eq!(binding.backup_receipt_hash(), &[0x74; 32]);
        let encoded = binding.to_bytes();
        assert_eq!(
            &encoded[..8],
            &OperationalM8FundingAuthorizationBindingV1::MAGIC
        );
        assert_eq!(&encoded[8..10], &1u16.to_le_bytes());
        assert_eq!(&encoded[10..14], b"M8T2");
        assert_eq!(encoded.len(), 400);

        let expected_tx_hash = *funding.tx_hash();
        let mut sink = TestM8FundingSink {
            chain_id,
            height: 5,
            stored_bytes: None,
        };
        let persisted = funding
            .persist_with_m8_sink_v1(&mut sink)
            .expect("persist exact M.8 funding bytes");
        assert_eq!(persisted, expected_tx_hash);
        assert_eq!(
            blake2b_256(&sink.stored_bytes.expect("stored bytes")).as_bytes(),
            &expected_tx_hash
        );
    }

    #[test]
    fn m8_restart_resumes_same_profile_issuance_and_rejects_substitution() {
        let shared = shared_fixture(90);
        let chain_id = *shared.chain.as_bytes();
        let input_blinding = blinding(11);
        let excess_blinding = shared
            .aggregate_blinding
            .sub(&input_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero excess");
        let template = ScriptlessTransactionTemplateV1::funding(
            &shared.output,
            vec![TransactionInput {
                commitment: Commitment::commit(100, &input_blinding),
            }],
            Vec::new(),
            0,
            unsigned_kernel(10, 0, &excess_blinding),
            [0u8; 32],
        )
        .expect("funding template");
        let adaptor_point = SecretKey::from_bytes(&scalar(13))
            .expect("adaptor secret fixture")
            .public_key()
            .to_compressed_bytes();
        let mut store = TestM8AuthorizationStore::default();

        {
            let first = template
                .authorize_funding_m8_v1(
                    &chain_id,
                    shared.statement.session_id(),
                    [0x71; 32],
                    [0x55; 32],
                    &shared.statement,
                    [0x76; 32],
                    adaptor_point,
                    [0x72; 32],
                    [0x74; 32],
                    [0x79; 32],
                    &mut store,
                )
                .expect("initial durable M.8 issuance");
            assert_eq!(first.issuance_record_digest(), &[0x85; 32]);
            assert_eq!(first.authorized_revision(), 8);
        }
        assert_eq!(store.issue_count, 1);

        {
            let resumed = template
                .resume_funding_m8_authorization_v1(
                    &chain_id,
                    shared.statement.session_id(),
                    [0x71; 32],
                    [0x55; 32],
                    &shared.statement,
                    [0x76; 32],
                    adaptor_point,
                    [0x72; 32],
                    [0x74; 32],
                    [0x79; 32],
                    &mut store,
                )
                .expect("same M.8 issuance after process crash");
            assert_eq!(resumed.issuance_record_digest(), &[0x85; 32]);
            assert_eq!(resumed.authorized_revision(), 8);
        }
        assert_eq!(store.issue_count, 1, "resume must not reissue");
        assert_eq!(store.resume_count, 1);

        assert!(template
            .resume_funding_m8_authorization_v1(
                &chain_id,
                shared.statement.session_id(),
                [0x71; 32],
                [0x55; 32],
                &shared.statement,
                [0x76; 32],
                adaptor_point,
                [0x72; 32],
                [0x74; 32],
                [0x99; 32],
                &mut store,
            )
            .is_err());
        assert_eq!(store.resume_count, 1, "substitution must not import");
        store.consumed = true;
        assert!(template
            .resume_funding_m8_authorization_v1(
                &chain_id,
                shared.statement.session_id(),
                [0x71; 32],
                [0x55; 32],
                &shared.statement,
                [0x76; 32],
                adaptor_point,
                [0x72; 32],
                [0x74; 32],
                [0x79; 32],
                &mut store,
            )
            .is_err());
    }

    #[test]
    fn m8_binding_rejects_zero_noncanonical_and_policy_substitution() {
        let shared = shared_fixture(90);
        let adaptor_point = SecretKey::from_bytes(&scalar(13))
            .expect("adaptor secret fixture")
            .public_key()
            .to_compressed_bytes();
        let make = |point, policy| {
            OperationalM8FundingAuthorizationBindingV1::new(
                *shared.chain.as_bytes(),
                shared.statement.session_id(),
                [0x71; 32],
                [0x55; 32],
                *shared.output.commitment(),
                shared.statement.statement_hash(),
                [0x70; 32],
                [0x76; 32],
                point,
                policy,
                [0x72; 32],
                [0x74; 32],
            )
        };
        let binding = make(adaptor_point, [0x79; 32]).expect("valid binding");
        let substituted = make(adaptor_point, [0x7a; 32]).expect("other policy");
        assert_ne!(binding, substituted);
        assert_ne!(binding.to_bytes(), substituted.to_bytes());
        assert!(make(adaptor_point, [0; 32]).is_err());
        assert!(make([0; 33], [0x79; 32]).is_err());
        let mut malformed = adaptor_point;
        malformed[0] = 0x04;
        assert!(make(malformed, [0x79; 32]).is_err());
    }

    #[test]
    fn funding_includes_exact_verified_shared_output_and_consumes_authorization() {
        let shared = shared_fixture(90);
        let chain_id = *shared.chain.as_bytes();
        let input_blinding = blinding(11);
        let excess_blinding = shared
            .aggregate_blinding
            .sub(&input_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero excess");
        let kernel = unsigned_kernel(10, 0, &excess_blinding);
        let signature = sign_kernel(&kernel, &excess_blinding, &chain_id);
        let template = ScriptlessTransactionTemplateV1::funding(
            &shared.output,
            vec![TransactionInput {
                commitment: Commitment::commit(100, &input_blinding),
            }],
            Vec::new(),
            0,
            kernel,
            [0u8; 32],
        )
        .expect("funding template");
        let template_hash = *template.template_hash();
        let session_id = shared.statement.session_id();
        let transcript = [0x71; 32];
        let mut wrong_binding_store = TestAuthorizationStore::default();
        assert!(template
            .authorize_funding_v1(
                &chain_id,
                [0x99; 32],
                transcript,
                [0x55; 32],
                &shared.statement,
                [0x76; 32],
                [0x72; 32],
                [0x73; 32],
                [0x74; 32],
                &mut wrong_binding_store,
            )
            .is_err());
        let mut authorization_store = TestAuthorizationStore::default();
        let authorization = template
            .authorize_funding_v1(
                &chain_id,
                session_id,
                transcript,
                [0x55; 32],
                &shared.statement,
                [0x76; 32],
                [0x72; 32],
                [0x73; 32],
                [0x74; 32],
                &mut authorization_store,
            )
            .expect("durable operational authorization");
        let funding = template
            .finalize_funding(authorization, signature, &chain_id, 5)
            .expect("verified funding");

        assert_eq!(funding.template_hash(), &template_hash);
        let binding = funding.authorization().binding();
        assert_eq!(binding.session_id(), &session_id);
        assert_eq!(binding.terms_hash(), &[0x55; 32]);
        assert_eq!(
            binding.shared_output_commitment(),
            shared.output.commitment()
        );
        assert_eq!(
            binding.bp_statement_hash(),
            &shared.statement.statement_hash()
        );
        assert_eq!(binding.claim_template_hash(), &[0x76; 32]);
        funding.verify(&chain_id, 5).expect("full verifier");
        let expected_tx_hash = *funding.tx_hash();

        let mut sink = TestFundingSink {
            chain_id,
            height: 5,
            stored_bytes: None,
        };
        let persisted_tx_hash = funding
            .persist_with_sink_v1(&mut sink)
            .expect("durable post-sign persistence");
        let stored_bytes = sink.stored_bytes.expect("stored exact bytes");
        let stored_transaction = Transaction::from_bytes(&stored_bytes).expect("canonical funding");
        assert_eq!(stored_transaction.outputs.len(), 1);
        assert_eq!(
            stored_transaction.outputs[0],
            shared.output.output().clone()
        );
        assert_eq!(persisted_tx_hash, expected_tx_hash);
        assert_eq!(blake2b_256(&stored_bytes).as_bytes(), &expected_tx_hash);
    }

    #[test]
    fn funding_authorization_restart_resumes_same_issuance_without_reissue() {
        let shared = shared_fixture(90);
        let chain_id = *shared.chain.as_bytes();
        let input_blinding = blinding(11);
        let excess_blinding = shared
            .aggregate_blinding
            .sub(&input_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero excess");
        let kernel = unsigned_kernel(10, 0, &excess_blinding);
        let template = ScriptlessTransactionTemplateV1::funding(
            &shared.output,
            vec![TransactionInput {
                commitment: Commitment::commit(100, &input_blinding),
            }],
            Vec::new(),
            0,
            kernel,
            [0u8; 32],
        )
        .expect("funding template");
        let session_id = shared.statement.session_id();
        let transcript = [0x71; 32];
        let mut store = TestAuthorizationStore::default();

        {
            let first = template
                .authorize_funding_v1(
                    &chain_id,
                    session_id,
                    transcript,
                    [0x55; 32],
                    &shared.statement,
                    [0x76; 32],
                    [0x72; 32],
                    [0x73; 32],
                    [0x74; 32],
                    &mut store,
                )
                .expect("initial durable issuance");
            assert_eq!(first.issuance_record_digest(), &[0x75; 32]);
            assert_eq!(first.authorized_revision(), 7);
        } // process crash before signing discards the process-local authority
        assert_eq!(store.issue_count, 1);

        {
            let resumed = template
                .resume_funding_authorization_v1(
                    &chain_id,
                    session_id,
                    transcript,
                    [0x55; 32],
                    &shared.statement,
                    [0x76; 32],
                    [0x72; 32],
                    [0x73; 32],
                    [0x74; 32],
                    &mut store,
                )
                .expect("same-issuance resume");
            assert_eq!(resumed.issuance_record_digest(), &[0x75; 32]);
            assert_eq!(resumed.authorized_revision(), 7);
        }
        assert_eq!(store.issue_count, 1, "resume must not issue again");
        assert_eq!(store.resume_count, 1);

        assert!(template
            .resume_funding_authorization_v1(
                &chain_id,
                [0x99; 32],
                transcript,
                [0x55; 32],
                &shared.statement,
                [0x76; 32],
                [0x72; 32],
                [0x73; 32],
                [0x74; 32],
                &mut store,
            )
            .is_err());
        store.consumed = true;
        assert!(template
            .resume_funding_authorization_v1(
                &chain_id,
                session_id,
                transcript,
                [0x55; 32],
                &shared.statement,
                [0x76; 32],
                [0x72; 32],
                [0x73; 32],
                [0x74; 32],
                &mut store,
            )
            .is_err());
    }

    #[test]
    fn refund_is_presigned_for_the_exact_shared_input_and_absolute_height() {
        let shared = shared_fixture(90);
        let chain_id = *shared.chain.as_bytes();
        let payout_blinding = blinding(7);
        let excess_blinding = payout_blinding
            .sub(&shared.aggregate_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero excess");
        let kernel = unsigned_kernel(11, 100, &excess_blinding);
        let signature = sign_kernel(&kernel, &excess_blinding, &chain_id);
        let refund = ScriptlessTransactionTemplateV1::refund(
            &shared.output,
            vec![output(79, &payout_blinding)],
            kernel,
            [0u8; 32],
            10,
        )
        .expect("refund template")
        .finalize_refund(signature, &chain_id)
        .expect("verified refund");

        assert_eq!(refund.role(), ContractTxRoleV1::Refund);
        assert_eq!(refund.transaction().inputs.len(), 1);
        assert_eq!(
            refund.transaction().inputs[0].commitment.as_bytes(),
            shared.output.commitment()
        );
        assert!(refund.verify(&chain_id, 99).is_err());
        refund.verify(&chain_id, 100).expect("valid at H");
        refund.verify(&chain_id, 101).expect("valid after H");
    }

    #[test]
    fn claim_can_only_finalize_by_adapting_the_bound_presignature() {
        let shared = shared_fixture(90);
        let chain_id = *shared.chain.as_bytes();
        let payout_blinding = blinding(6);
        let excess_blinding = payout_blinding
            .sub(&shared.aggregate_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero excess");
        let kernel = unsigned_kernel(10, 0, &excess_blinding);
        let template = ScriptlessTransactionTemplateV1::claim(
            &shared.output,
            vec![output(80, &payout_blinding)],
            kernel,
            [0u8; 32],
        )
        .expect("claim template");
        let transcript = [0x81; 32];
        let adaptor_secret = AdaptorSecret::from_be_bytes(scalar(13)).expect("secret");
        let adaptor_point = adaptor_secret.public_point().expect("T");
        let nonce_secret = SecretKey::from_bytes(&scalar(11)).expect("nonce secret");
        let nonce_point = nonce_secret.public_key();
        let aggregate_nonce_hat =
            aggregate_public_nonces_v1(&[nonce_point, adaptor_point.clone()]).expect("R hat");
        let signing_key =
            PublicKey::from_compressed_bytes(template.transaction.kernels[0].excess.as_bytes())
                .expect("signing key");
        let message = scriptless_kernel_message_digest_v1(&template.transaction.kernels[0]);
        let challenge = schnorr_challenge(
            &aggregate_nonce_hat.to_compressed_bytes(),
            &signing_key,
            &chain_id,
            message.as_bytes(),
        );
        let signing_scalar = k256::Scalar::from_repr((*excess_blinding.as_bytes()).into()).unwrap();
        let nonce_scalar = k256::Scalar::from_repr(scalar(11).into()).unwrap();
        let challenge_scalar = k256::Scalar::from_repr((*challenge.as_bytes()).into()).unwrap();
        let scalar_hat_bytes: [u8; 32] = (nonce_scalar + challenge_scalar * signing_scalar)
            .to_bytes()
            .into();
        let pre_signature = AdaptorPreSignatureV1::new(
            *template.template_hash(),
            adaptor_point,
            aggregate_nonce_hat,
            PartialSig::from_bytes(&scalar_hat_bytes).expect("s hat"),
            transcript,
        );
        let claim = template
            .finalize_claim(&pre_signature, &adaptor_secret, &transcript, &chain_id, 20)
            .expect("adapted claim");

        assert_eq!(claim.role(), ContractTxRoleV1::Claim);
        claim.verify(&chain_id, 20).expect("full verifier");
        let final_signature =
            SchnorrSignature::from_bytes(&claim.transaction().kernels[0].excess_signature)
                .expect("final signature");
        pre_signature
            .extract(
                &final_signature,
                claim.template_hash(),
                &transcript,
                &signing_key,
                &chain_id,
                message.as_bytes(),
            )
            .expect("extract t and verify tG=T");
    }

    #[test]
    fn lifecycle_rejects_wrong_roles_duplicates_and_expired_refunds() {
        let shared = shared_fixture(90);
        let input_blinding = blinding(11);
        let excess_blinding = shared
            .aggregate_blinding
            .sub(&input_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero");
        let duplicate = shared.output.output().clone();
        assert!(ScriptlessTransactionTemplateV1::funding(
            &shared.output,
            vec![TransactionInput {
                commitment: Commitment::commit(100, &input_blinding),
            }],
            vec![duplicate],
            0,
            unsigned_kernel(10, 0, &excess_blinding),
            [0u8; 32],
        )
        .is_err());

        let payout_blinding = blinding(7);
        let spend_excess = payout_blinding
            .sub(&shared.aggregate_blinding)
            .expect("difference")
            .require_nonzero()
            .expect("nonzero");
        assert!(ScriptlessTransactionTemplateV1::refund(
            &shared.output,
            vec![output(79, &payout_blinding)],
            unsigned_kernel(11, 10, &spend_excess),
            [0u8; 32],
            10,
        )
        .is_err());
        assert!(ScriptlessTransactionTemplateV1::claim(
            &shared.output,
            vec![output(79, &payout_blinding)],
            unsigned_kernel(11, 10, &spend_excess),
            [0u8; 32],
        )
        .is_err());
    }
}

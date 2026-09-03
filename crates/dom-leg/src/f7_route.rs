//! Opaque production-route preparation boundary for the F7 real DOM leg.
//!
//! This module deliberately keeps the DOM shared-blinding capability,
//! collaborative Bulletproof statement/output and Wallet V3 bound templates
//! behind one non-cloneable type. Cross-chain orchestration may inspect only
//! their public bindings; it cannot import, relabel or serialize any DOM
//! signing share or shared-output authority.

use std::fs::{self, File};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cap_std::fs::Dir;
use counterparty_api::AdaptorPointBytes;
use dom_adaptor::{
    aggregate_shared_commitment_v1, combine_decoy_capsule_v1,
    contribute_vault_backed_blinding_share_v1, initial_transcript_hash_v1,
    resume_vault_backed_blinding_share_after_restart_v1, AcceptedSigningSessionV1, BpStatementV1,
    CollaborativeRangeProof, ContractKindV1, DirectionV1, ParticipantIdentityV1,
    ParticipantRosterV1, PurposeV1, RestartedSessionBlindingShareV1,
    SessionBlindingShareCapabilityV1, SharedBlindingRestartRequestV1, SharedCommitmentV1,
    TrustedChainIdV1, VerifiedSharedOutputV1,
};
use dom_core::Hash256;
use dom_crypto::recovery::RecoveryCapsule;
use dom_crypto::PublicKey;
use dom_scriptless_crypto::{
    authoritative_storage_hash_v1, generate_storage_ids, Passphrase, StorageHashDomainV1,
};
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1,
};
use dom_scriptless_store::{
    verify_operational_m8_funding_gate_evidence_v1, BudgetPolicyProfileV1, BudgetPolicyV1,
    ConsumedClaimSigningAuthorizationV1, ContractsSessionStoreV1,
    DomTransactionValidationContextV1, DurableTransportOutcomeV1, FundingBroadcastV1,
    OperationalBpContinuationStageV1, OperationalM8FundingGateVerificationRequestV1,
    PreparedOperationalM8FundingGateV1, SessionChainProjectionV1, SessionIrreversibleV1,
    SessionPhaseV1, SessionRecordFieldsV1, SessionRecordV1, SessionStoreError,
    SessionTxObservationV1, BUDGET_POLICY_LEN,
};
use dom_scriptless_transport::{
    MessageTypeV1, SessionReceiverV1, TransportParticipantV1, UnsignedMessageV1,
};
use zeroize::Zeroizing;

use crate::f7_wallet::F7ProductionParticipantLayoutV1;
use crate::{
    F7DomDsc1CheckpointV1, F7DomDsc1FaultControllerV1, F7DomDsc1FaultDirectiveV1,
    F7OfficialWalletPairV1, F7OperationalSigningContextV1, F7ProductionContractsCompositionV1,
    F7ProductionParticipantAuthoritiesV1, F7VerifiedDomRefundArtifactV1, F7WalletBoundDomClaimV1,
    F7WalletBoundDomFundingV1, F7WalletBoundDomRefundV1, F7WalletCompositorError,
    F7WalletPreSignedDomClaimV1,
};

const MIN_AUTHORITY_SECRET_BYTES: u64 = 16;
const MAX_AUTHORITY_SECRET_BYTES: u64 = 1024;
const SESSION_STORE_ROOT: &str = "sessions";
const NONCE_VAULT_ROOTS: [[&str; 3]; 2] = [
    ["nonce-a", "nonce-a-funding", "nonce-a-claim"],
    ["nonce-b", "nonce-b-funding", "nonce-b-claim"],
];
const IDENTITY_STORE_ROOTS: [&str; 2] = ["identity-a", "identity-b"];

/// Exact public funding shape frozen before any Wallet V3 reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F7DomFundingShapeV1 {
    local_debit_noms: [u64; 2],
    fee_noms: u64,
    expected_input_count: u32,
    expected_output_count: u32,
    shared_output_position: usize,
}

impl F7DomFundingShapeV1 {
    /// Validates the two local debits and one aggregate transaction shape.
    pub fn new(
        local_debit_noms: [u64; 2],
        fee_noms: u64,
        expected_input_count: u32,
        expected_output_count: u32,
        shared_output_position: usize,
    ) -> Result<Self, F7DomRoutePreparationErrorV1> {
        if fee_noms == 0
            || expected_input_count == 0
            || expected_output_count == 0
            || shared_output_position >= expected_output_count as usize
            || local_debit_noms == [0, 0]
        {
            return Err(F7DomRoutePreparationErrorV1::InvalidRequest);
        }
        Ok(Self {
            local_debit_noms,
            fee_noms,
            expected_input_count,
            expected_output_count,
            shared_output_position,
        })
    }

    /// Debit assigned to each canonical participant slot.
    #[must_use]
    pub const fn local_debit_noms(&self) -> [u64; 2] {
        self.local_debit_noms
    }

    /// Single aggregate funding fee.
    #[must_use]
    pub const fn fee_noms(&self) -> u64 {
        self.fee_noms
    }

    /// Frozen aggregate input count.
    #[must_use]
    pub const fn expected_input_count(&self) -> u32 {
        self.expected_input_count
    }

    /// Frozen aggregate output count, including the shared output once.
    #[must_use]
    pub const fn expected_output_count(&self) -> u32 {
        self.expected_output_count
    }

    /// Canonical insertion position of the shared output.
    #[must_use]
    pub const fn shared_output_position(&self) -> usize {
        self.shared_output_position
    }
}

/// Exact public Claim or Refund payout shape for both Wallet V3 peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F7DomPayoutShapeV1 {
    payout_noms: [u64; 2],
    fee_noms: u64,
    expected_output_count: u32,
}

impl F7DomPayoutShapeV1 {
    /// Validates one two-party shared-output spend shape.
    pub fn new(
        payout_noms: [u64; 2],
        fee_noms: u64,
        expected_output_count: u32,
    ) -> Result<Self, F7DomRoutePreparationErrorV1> {
        let nonzero_outputs = payout_noms.iter().filter(|value| **value != 0).count();
        if fee_noms == 0
            || nonzero_outputs == 0
            || nonzero_outputs != expected_output_count as usize
        {
            return Err(F7DomRoutePreparationErrorV1::InvalidRequest);
        }
        Ok(Self {
            payout_noms,
            fee_noms,
            expected_output_count,
        })
    }

    /// Payout assigned to each canonical participant slot.
    #[must_use]
    pub const fn payout_noms(&self) -> [u64; 2] {
        self.payout_noms
    }

    /// Single aggregate kernel fee.
    #[must_use]
    pub const fn fee_noms(&self) -> u64 {
        self.fee_noms
    }

    /// Exact count of nonzero participant outputs.
    #[must_use]
    pub const fn expected_output_count(&self) -> u32 {
        self.expected_output_count
    }
}

/// Public immutable inputs for one real-DOM route preparation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct F7DomRoutePreparationRequestV1 {
    session_id: [u8; 32],
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    shared_value_noms: u64,
    funding: F7DomFundingShapeV1,
    claim: F7DomPayoutShapeV1,
    refund: F7DomPayoutShapeV1,
    funding_tip_height: u64,
    refund_lock_height: u64,
    adaptor_point: AdaptorPointBytes,
    claim_round_start_transcript_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
}

impl core::fmt::Debug for F7DomRoutePreparationRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7DomRoutePreparationRequestV1")
            .field("session_id", &self.session_id)
            .field("settlement_id", &self.settlement_id)
            .field("terms_hash", &self.terms_hash)
            .field("shared_value_noms", &"[frozen economic value]")
            .field("funding", &self.funding)
            .field("claim", &self.claim)
            .field("refund", &self.refund)
            .field("funding_tip_height", &self.funding_tip_height)
            .field("refund_lock_height", &self.refund_lock_height)
            .field("adaptor_point", &self.adaptor_point)
            .field(
                "claim_round_start_transcript_hash",
                &self.claim_round_start_transcript_hash,
            )
            .field("m8_policy_digest", &self.m8_policy_digest)
            .finish()
    }
}

impl F7DomRoutePreparationRequestV1 {
    /// Freezes one complete set of public route/template inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: [u8; 32],
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        shared_value_noms: u64,
        funding: F7DomFundingShapeV1,
        claim: F7DomPayoutShapeV1,
        refund: F7DomPayoutShapeV1,
        funding_tip_height: u64,
        refund_lock_height: u64,
        adaptor_point: AdaptorPointBytes,
        claim_round_start_transcript_hash: [u8; 32],
        m8_policy_digest: [u8; 32],
    ) -> Result<Self, F7DomRoutePreparationErrorV1> {
        let funding_debit_total = checked_sum(funding.local_debit_noms, 0)?;
        let funding_required = shared_value_noms
            .checked_add(funding.fee_noms)
            .ok_or(F7DomRoutePreparationErrorV1::InvalidRequest)?;
        let claim_total = checked_sum(claim.payout_noms, claim.fee_noms)?;
        let refund_total = checked_sum(refund.payout_noms, refund.fee_noms)?;
        if session_id == [0; 32]
            || settlement_id == [0; 32]
            || terms_hash == [0; 32]
            || shared_value_noms == 0
            || funding_debit_total != funding_required
            || claim_total != shared_value_noms
            || refund_total != shared_value_noms
            || refund_lock_height <= funding_tip_height
            || claim_round_start_transcript_hash == [0; 32]
            || m8_policy_digest == [0; 32]
            || dom_crypto::PublicKey::from_compressed_bytes(&adaptor_point.0).is_err()
        {
            return Err(F7DomRoutePreparationErrorV1::InvalidRequest);
        }
        Ok(Self {
            session_id,
            settlement_id,
            terms_hash,
            shared_value_noms,
            funding,
            claim,
            refund,
            funding_tip_height,
            refund_lock_height,
            adaptor_point,
            claim_round_start_transcript_hash,
            m8_policy_digest,
        })
    }

    /// Lifetime-unique DOM signing and Wallet reservation session.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Cross-chain settlement identifier.
    #[must_use]
    pub const fn settlement_id(&self) -> [u8; 32] {
        self.settlement_id
    }

    /// Hash of the accepted route terms.
    #[must_use]
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms_hash
    }

    /// Shared confidential output value.
    #[must_use]
    pub const fn shared_value_noms(&self) -> u64 {
        self.shared_value_noms
    }

    /// Frozen funding shape.
    #[must_use]
    pub const fn funding(&self) -> F7DomFundingShapeV1 {
        self.funding
    }

    /// Frozen Claim payout shape.
    #[must_use]
    pub const fn claim(&self) -> F7DomPayoutShapeV1 {
        self.claim
    }

    /// Frozen Refund payout shape.
    #[must_use]
    pub const fn refund(&self) -> F7DomPayoutShapeV1 {
        self.refund
    }

    /// DOM tip against which the absolute Refund lock was frozen.
    #[must_use]
    pub const fn funding_tip_height(&self) -> u64 {
        self.funding_tip_height
    }

    /// Absolute DOM Refund lock height.
    #[must_use]
    pub const fn refund_lock_height(&self) -> u64 {
        self.refund_lock_height
    }

    /// Route-wide adaptor point `T`.
    #[must_use]
    pub const fn adaptor_point(&self) -> AdaptorPointBytes {
        self.adaptor_point
    }

    /// Exact post-anchor Claim round-start transcript.
    #[must_use]
    pub const fn claim_round_start_transcript_hash(&self) -> [u8; 32] {
        self.claim_round_start_transcript_hash
    }

    /// Frozen Annex M.8 policy digest.
    #[must_use]
    pub const fn m8_policy_digest(&self) -> [u8; 32] {
        self.m8_policy_digest
    }
}

/// Real-chain observations required only while creating a new production
/// route. The embedded route shape remains the sole source of economic and
/// cryptographic public bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F7FreshDomRoutePreparationRequestV1 {
    route: F7DomRoutePreparationRequestV1,
    funding_tip_id: [u8; 32],
    now_unix_seconds: u64,
}

impl F7FreshDomRoutePreparationRequestV1 {
    /// Binds a fresh route to the authenticated DOM tip and wall-clock value
    /// used by the pre-funding M.8 verifier.
    pub fn new(
        route: F7DomRoutePreparationRequestV1,
        funding_tip_id: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<Self, F7DomRoutePreparationErrorV1> {
        if funding_tip_id == [0; 32] || now_unix_seconds == 0 {
            return Err(F7DomRoutePreparationErrorV1::InvalidRequest);
        }
        Ok(Self {
            route,
            funding_tip_id,
            now_unix_seconds,
        })
    }

    /// Complete public route/template request.
    #[must_use]
    pub const fn route(&self) -> F7DomRoutePreparationRequestV1 {
        self.route
    }

    /// Authenticated real-DOM funding-tip identifier.
    #[must_use]
    pub const fn funding_tip_id(&self) -> [u8; 32] {
        self.funding_tip_id
    }

    /// Explicit Unix time supplied to the frozen DOM verifier.
    #[must_use]
    pub const fn now_unix_seconds(&self) -> u64 {
        self.now_unix_seconds
    }
}

/// Reopenable production authority layout retained outside Wallet databases.
///
/// Only public paths and policy/chain bindings are retained. Secret file
/// contents are read only inside the future concrete composition operation;
/// this type has no passphrase accessor and redacts all paths in `Debug`.
pub struct F7ProductionDomRouteAuthorityFactoryV1 {
    parent: PathBuf,
    authority_secret_files: [PathBuf; 4],
    policy: BudgetPolicyV1,
    network_magic: u32,
    genesis_hash: [u8; 32],
    expected_chain_id: [u8; 32],
}

impl core::fmt::Debug for F7ProductionDomRouteAuthorityFactoryV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7ProductionDomRouteAuthorityFactoryV1")
            .field("parent", &"[redacted owner-only directory]")
            .field("authority_secret_files", &"[four owner-only paths]")
            .field("policy_digest", &self.policy.policy_digest())
            .field("network_magic", &self.network_magic)
            .field("genesis_hash", &self.genesis_hash)
            .field("expected_chain_id", &self.expected_chain_id)
            .finish()
    }
}

impl F7ProductionDomRouteAuthorityFactoryV1 {
    /// Builds the closed one-route laboratory policy used by the explicitly
    /// provisional live command.
    ///
    /// The frozen Contracts boundary admits only its production safety
    /// profile. Selecting that profile here enables the same nonce-budget and
    /// retention checks for an engineering run; it is not evidence of project
    /// ratification and must never make the normal `run-route` command
    /// available. The policy identifier is bound to the authenticated DOM
    /// chain, and every limit is fixed rather than caller-selected.
    pub fn new_provisional_lab(
        parent: PathBuf,
        authority_secret_files: [PathBuf; 4],
        network_magic: u32,
        genesis_hash: [u8; 32],
        expected_chain_id: [u8; 32],
    ) -> Result<Self, F7DomRoutePreparationErrorV1> {
        if expected_chain_id == [0; 32] {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let mut bytes = [0_u8; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
        bytes[11] = 1;
        bytes[16..48].copy_from_slice(&expected_chain_id);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
        bytes[112..].copy_from_slice(&digest);
        let policy = BudgetPolicyV1::from_bytes(&bytes)
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        Self::new(
            parent,
            authority_secret_files,
            policy,
            network_magic,
            genesis_hash,
            expected_chain_id,
        )
    }

    /// Authenticates the owner-only authority layout and exact production
    /// policy/DOM identity without opening or creating any Contracts root.
    pub fn new(
        parent: PathBuf,
        authority_secret_files: [PathBuf; 4],
        policy: BudgetPolicyV1,
        network_magic: u32,
        genesis_hash: [u8; 32],
        expected_chain_id: [u8; 32],
    ) -> Result<Self, F7DomRoutePreparationErrorV1> {
        let parent = validate_private_directory(&parent)?;
        let owner = fs::metadata(&parent)
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?
            .uid();
        let scenario_root = parent
            .parent()
            .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let mut canonical_secret_files = Vec::with_capacity(4);
        for path in authority_secret_files {
            canonical_secret_files.push(validate_authority_secret(&path, scenario_root, owner)?);
        }
        if canonical_secret_files
            .iter()
            .enumerate()
            .any(|(index, path)| canonical_secret_files[index + 1..].contains(path))
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let authority_secret_files: [PathBuf; 4] = canonical_secret_files
            .try_into()
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let trusted_chain = TrustedChainIdV1::from_authenticated_genesis(
            network_magic,
            &Hash256::from_bytes(genesis_hash),
        );
        if policy.profile() != BudgetPolicyProfileV1::ProductionRatified
            || network_magic == 0
            || genesis_hash == [0; 32]
            || expected_chain_id == [0; 32]
            || trusted_chain.as_bytes() != &expected_chain_id
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        Ok(Self {
            parent,
            authority_secret_files,
            policy,
            network_magic,
            genesis_hash,
            expected_chain_id,
        })
    }

    /// Canonical authenticated DOM chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> [u8; 32] {
        self.expected_chain_id
    }

    /// Exact ratified production-policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> [u8; 32] {
        *self.policy.policy_digest()
    }

    fn secret_files(&self) -> &[PathBuf; 4] {
        &self.authority_secret_files
    }

    fn parent(&self) -> &Path {
        &self.parent
    }

    fn create_fresh_composition(
        &self,
    ) -> Result<F7ProductionContractsCompositionV1, F7DomRoutePreparationErrorV1> {
        if complete_existing_authority_roots(&self.parent)? {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let scenario_root = self
            .parent
            .parent()
            .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let owner = fs::metadata(&self.parent)
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?
            .uid();
        let [nonce_a_path, identity_a_path, nonce_b_path, identity_b_path] =
            &self.authority_secret_files;
        let nonce_a_bytes = read_authority_secret(nonce_a_path, scenario_root, owner)?;
        let identity_a_bytes = read_authority_secret(identity_a_path, scenario_root, owner)?;
        let nonce_b_bytes = read_authority_secret(nonce_b_path, scenario_root, owner)?;
        let identity_b_bytes = read_authority_secret(identity_b_path, scenario_root, owner)?;
        require_nonce_passphrase_bytes(&nonce_a_bytes)?;
        require_identity_passphrase_bytes(&identity_a_bytes)?;
        require_nonce_passphrase_bytes(&nonce_b_bytes)?;
        require_identity_passphrase_bytes(&identity_b_bytes)?;
        let nonce_a = Passphrase::new(nonce_a_bytes.to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let identity_a = ContractsIdentityPassphraseV1::new(identity_a_bytes.to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let nonce_b = Passphrase::new(nonce_b_bytes.to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let identity_b = ContractsIdentityPassphraseV1::new(identity_b_bytes.to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;

        let parent_file = File::open(&self.parent)
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
        let parent = Arc::new(Dir::from_std_file(parent_file));
        let storage_a = [(); 3].map(|()| {
            generate_storage_ids().map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)
        });
        let [storage_a_base, storage_a_funding, storage_a_claim] = storage_a;
        let storage_a = [storage_a_base?, storage_a_funding?, storage_a_claim?];
        let storage_b = [(); 3].map(|()| {
            generate_storage_ids().map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)
        });
        let [storage_b_base, storage_b_funding, storage_b_claim] = storage_b;
        let storage_b = [storage_b_base?, storage_b_funding?, storage_b_claim?];
        let participants = [
            F7ProductionParticipantAuthoritiesV1::create_purpose_separated_production(
                Arc::clone(&parent),
                NONCE_VAULT_ROOTS[0],
                IDENTITY_STORE_ROOTS[0],
                storage_a,
                &nonce_a,
                &identity_a,
                self.policy.clone(),
            )?,
            F7ProductionParticipantAuthoritiesV1::create_purpose_separated_production(
                Arc::clone(&parent),
                NONCE_VAULT_ROOTS[1],
                IDENTITY_STORE_ROOTS[1],
                storage_b,
                &nonce_b,
                &identity_b,
                self.policy.clone(),
            )?,
        ];
        F7ProductionContractsCompositionV1::create_production(
            parent,
            SESSION_STORE_ROOT,
            self.policy.clone(),
            self.network_magic,
            self.genesis_hash,
            self.expected_chain_id,
            participants,
        )
        .map_err(Into::into)
    }

    fn open_existing_composition(
        &self,
    ) -> Result<F7ProductionContractsCompositionV1, F7DomRoutePreparationErrorV1> {
        require_complete_existing_authority_roots(&self.parent)?;
        let scenario_root = self
            .parent
            .parent()
            .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let owner = fs::metadata(&self.parent)
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?
            .uid();
        let [nonce_a_path, identity_a_path, nonce_b_path, identity_b_path] =
            &self.authority_secret_files;
        let nonce_a_bytes = read_authority_secret(nonce_a_path, scenario_root, owner)?;
        let identity_a_bytes = read_authority_secret(identity_a_path, scenario_root, owner)?;
        let nonce_b_bytes = read_authority_secret(nonce_b_path, scenario_root, owner)?;
        let identity_b_bytes = read_authority_secret(identity_b_path, scenario_root, owner)?;
        require_nonce_passphrase_bytes(&nonce_a_bytes)?;
        require_identity_passphrase_bytes(&identity_a_bytes)?;
        require_nonce_passphrase_bytes(&nonce_b_bytes)?;
        require_identity_passphrase_bytes(&identity_b_bytes)?;
        let nonce_a = [(); 3].map(|()| {
            Passphrase::new(nonce_a_bytes.to_vec())
                .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)
        });
        let [nonce_a_base, nonce_a_funding, nonce_a_claim] = nonce_a;
        let nonce_a = [nonce_a_base?, nonce_a_funding?, nonce_a_claim?];
        let identity_a = ContractsIdentityPassphraseV1::new(identity_a_bytes.to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let nonce_b = [(); 3].map(|()| {
            Passphrase::new(nonce_b_bytes.to_vec())
                .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)
        });
        let [nonce_b_base, nonce_b_funding, nonce_b_claim] = nonce_b;
        let nonce_b = [nonce_b_base?, nonce_b_funding?, nonce_b_claim?];
        let identity_b = ContractsIdentityPassphraseV1::new(identity_b_bytes.to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;

        let parent_file = File::open(&self.parent)
            .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
        let parent = Arc::new(Dir::from_std_file(parent_file));
        let participants = [
            F7ProductionParticipantAuthoritiesV1::open_purpose_separated_production(
                Arc::clone(&parent),
                NONCE_VAULT_ROOTS[0],
                IDENTITY_STORE_ROOTS[0],
                nonce_a,
                &identity_a,
                self.policy.clone(),
            )?,
            F7ProductionParticipantAuthoritiesV1::open_purpose_separated_production(
                Arc::clone(&parent),
                NONCE_VAULT_ROOTS[1],
                IDENTITY_STORE_ROOTS[1],
                nonce_b,
                &identity_b,
                self.policy.clone(),
            )?,
        ];
        F7ProductionContractsCompositionV1::open_production(
            parent,
            SESSION_STORE_ROOT,
            self.policy.clone(),
            self.network_magic,
            self.genesis_hash,
            self.expected_chain_id,
            participants,
        )
        .map_err(Into::into)
    }
}

/// Opaque complete DOM route prepared by the official wallets and production
/// Contracts authorities.
///
/// This value is intentionally non-`Clone`, has no codec and has no public
/// constructor. Its raw DOM statement, output, session shares and templates
/// never cross the `dom-leg` boundary.
pub struct F7PreparedProductionDomRouteV1 {
    request: F7DomRoutePreparationRequestV1,
    chain_id: [u8; 32],
    authority: F7ProductionDomRouteAuthorityFactoryV1,
    _prepared_m8_gate: Option<PreparedOperationalM8FundingGateV1>,
    bp_statement: BpStatementV1,
    shared_output: VerifiedSharedOutputV1,
    _session_shares: [SessionBlindingShareCapabilityV1; 2],
    funding: F7WalletBoundDomFundingV1,
    claim: F7WalletBoundDomClaimV1,
    refund: F7PreparedDomRefundV1,
}

/// Public transaction identities produced by the retained M.8 funding stage.
///
/// Both hashes identify fully signed canonical DOM transactions. No
/// transaction bytes, signer, nonce, share or Store authority is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F7ProductionDomFundingReceiptV1 {
    funding_tx_hash: [u8; 32],
    refund_tx_hash: [u8; 32],
}

impl F7ProductionDomFundingReceiptV1 {
    /// Fully signed canonical DOM funding transaction identifier.
    #[must_use]
    pub const fn funding_tx_hash(self) -> [u8; 32] {
        self.funding_tx_hash
    }

    /// Fully signed canonical pre-funded DOM refund transaction identifier.
    #[must_use]
    pub const fn refund_tx_hash(self) -> [u8; 32] {
        self.refund_tx_hash
    }
}

/// Linear Store-owned funding broadcast paired with its public identities.
///
/// The exact funding bytes remain inside [`FundingBroadcastV1`]. Consuming
/// [`Self::into_broadcast`] is the only production escape from this handle.
pub struct F7PreparedProductionDomFundingV1 {
    broadcast: FundingBroadcastV1,
    receipt: F7ProductionDomFundingReceiptV1,
    post_funding_owner: F7ProductionDomPostFundingOwnerV1,
}

impl core::fmt::Debug for F7PreparedProductionDomFundingV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7PreparedProductionDomFundingV1")
            .field("receipt", &self.receipt)
            .field("broadcast", &"[opaque Store funding authority]")
            .field(
                "post_funding_owner",
                &"[opaque retained DOM claim authorities]",
            )
            .finish()
    }
}

impl F7PreparedProductionDomFundingV1 {
    /// Public identities proven by the retained DOM verifier and Store sink.
    #[must_use]
    pub const fn receipt(&self) -> F7ProductionDomFundingReceiptV1 {
        self.receipt
    }

    /// Consumes the route handle into the sole exact-byte funding attempt.
    #[must_use]
    pub fn into_broadcast(self) -> FundingBroadcastV1 {
        self.broadcast
    }

    /// Splits the exact funding attempt from the still-live post-funding DOM
    /// owner. The owner must be retained across broadcast and real-anchor
    /// validation; dropping it deliberately makes ClaimAdaptor signing
    /// unavailable for this process.
    #[must_use]
    pub fn into_parts(self) -> (FundingBroadcastV1, F7ProductionDomPostFundingOwnerV1) {
        (self.broadcast, self.post_funding_owner)
    }
}

/// Linear owner of the exact post-funding DOM Store and bound Claim template.
///
/// Funding signing reopens the same retained production composition before
/// returning this value. Consequently the runner can issue and consume its
/// post-anchor claim authorization through this exact Store open instance,
/// then hand the resulting linear capability back for the sole ClaimAdaptor
/// round. No Wallet share, nonce authority, transaction bytes or adaptor
/// pre-signature is exposed by this owner.
pub struct F7ProductionDomPostFundingOwnerV1 {
    composition: F7ProductionContractsCompositionV1,
    claim: F7WalletBoundDomClaimV1,
    session_id: [u8; 32],
    claim_round_start_transcript_hash: [u8; 32],
}

impl core::fmt::Debug for F7ProductionDomPostFundingOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7ProductionDomPostFundingOwnerV1")
            .field("session_id", &self.session_id)
            .field("claim_template_hash", &self.claim.template_hash())
            .field(
                "claim_round_start_transcript_hash",
                &self.claim_round_start_transcript_hash,
            )
            .field("composition", &"[opaque retained production authorities]")
            .finish()
    }
}

impl F7ProductionDomPostFundingOwnerV1 {
    /// Lifetime-unique Contracts session retained by this owner.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Exact frozen DOM claim-template digest.
    #[must_use]
    pub const fn claim_template_hash(&self) -> [u8; 32] {
        self.claim.template_hash()
    }

    /// Actual Store transcript at the post-funding ClaimAdaptor boundary.
    ///
    /// This value is read from the durable `FundingBroadcast` head after the
    /// funding sink commits. It is not a caller-selected or precomputed
    /// transcript substitute.
    #[must_use]
    pub const fn claim_round_start_transcript_hash(&self) -> [u8; 32] {
        self.claim_round_start_transcript_hash
    }

    /// Borrows the exact retained Store used by this owner's claim signer.
    ///
    /// The borrow exists so the combined runner can consume its non-forgeable
    /// real-anchor authorization in the same Store open instance. It exposes
    /// no Wallet or nonce-vault authority.
    #[must_use]
    pub const fn contracts_store(&self) -> &ContractsSessionStoreV1 {
        self.composition.session_store()
    }

    /// Executes or resumes the sole post-anchor ClaimAdaptor signing round.
    ///
    /// A transcript equal to the retained round-start selects the fresh path;
    /// any later authenticated `FundingConfirmed` transcript selects only the
    /// restart path. There is no resume-to-fresh fallback and the consumed
    /// authorization must belong to this exact Store/session/template.
    pub fn sign_or_resume_claim(
        self,
        authorization: ConsumedClaimSigningAuthorizationV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7DomRoutePreparationErrorV1> {
        let mut controller = ContinueEveryDsc1CheckpointV1;
        self.sign_or_resume_claim_with_fault(authorization, &mut controller)
    }

    /// Executes or resumes the post-anchor ClaimAdaptor round while exposing
    /// the public durable-prefix checkpoints to a runtime fault controller.
    ///
    /// The controller receives a purpose and a prefix count and nothing else.
    /// Every directive it returns is enacted inside the compositor against the
    /// retained production identity and the real Contracts store, so a probe
    /// cannot be satisfied by anything this caller constructs.
    pub fn sign_or_resume_claim_with_fault(
        self,
        authorization: ConsumedClaimSigningAuthorizationV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7DomRoutePreparationErrorV1> {
        if authorization.session_id() != &self.session_id
            || authorization.claim_template_hash() != &self.claim.template_hash()
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let current = self
            .composition
            .session_store()
            .load_session(self.session_id)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        if current.phase() != SessionPhaseV1::FundingConfirmed {
            return Err(F7DomRoutePreparationErrorV1::Composition);
        }
        let round_is_bound = self
            .composition
            .post_anchor_claim_round_is_bound(&authorization)?;
        // `claim_round_start_transcript_hash` is read from the session head when
        // this owner is reopened, which is only the round *start* while the
        // round has not begun. Once a prefix of the round is durable the head
        // has moved past it, so comparing the authorization's recorded start
        // against it rejects every legitimate resume — which is exactly what a
        // DSC1 claim-prefix cut produces.
        //
        // For a bound round the equality is replaced by a stronger statement,
        // not dropped: `post_anchor_claim_round_is_bound` returns true only
        // because the Contracts store itself reopened the durable round *for
        // this authorization*. The store authenticating the binding against its
        // own durable state is better evidence than this side comparing two
        // local values, and the check below already relies on the same
        // distinction.
        if !round_is_bound
            && (authorization.round_start_transcript_hash()
                != &self.claim_round_start_transcript_hash
                || current.transcript_hash() != self.claim_round_start_transcript_hash)
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let claim_context = self
            .composition
            .bind_operational_transport(self.session_id, self.claim.signing_public_keys())?;
        if round_is_bound {
            self.composition
                .resume_claim_after_real_anchors_with_fault(
                    self.claim,
                    &authorization,
                    &claim_context,
                    fault_controller,
                )
                .map_err(Into::into)
        } else {
            self.composition
                .sign_claim_after_real_anchors_with_fault(
                    self.claim,
                    &authorization,
                    &claim_context,
                    fault_controller,
                )
                .map_err(Into::into)
        }
    }
}

/// Controller that selects no fault at any checkpoint.
struct ContinueEveryDsc1CheckpointV1;

impl F7DomDsc1FaultControllerV1 for ContinueEveryDsc1CheckpointV1 {
    fn at_durable_checkpoint(
        &mut self,
        _checkpoint: F7DomDsc1CheckpointV1,
    ) -> Result<F7DomDsc1FaultDirectiveV1, F7WalletCompositorError> {
        Ok(F7DomDsc1FaultDirectiveV1::Continue)
    }
}

enum F7PreparedDomRefundV1 {
    Bound(F7WalletBoundDomRefundV1),
    Signed {
        template_hash: [u8; 32],
        signing_public_keys: [PublicKey; 2],
        _artifact: F7VerifiedDomRefundArtifactV1,
    },
}

impl F7PreparedDomRefundV1 {
    fn template_hash(&self) -> [u8; 32] {
        match self {
            Self::Bound(refund) => refund.template_hash(),
            Self::Signed { template_hash, .. } => *template_hash,
        }
    }

    fn signing_public_keys(&self) -> [PublicKey; 2] {
        match self {
            Self::Bound(refund) => refund.signing_public_keys(),
            Self::Signed {
                signing_public_keys,
                ..
            } => signing_public_keys.clone(),
        }
    }
}

impl core::fmt::Debug for F7PreparedProductionDomRouteV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7PreparedProductionDomRouteV1")
            .field("session_id", &self.request.session_id)
            .field("settlement_id", &self.request.settlement_id)
            .field("chain_id", &self.chain_id)
            .field("shared_output_commitment", &self.shared_output.commitment())
            .field("funding_template_hash", &self.funding.template_hash())
            .field("claim_template_hash", &self.claim.template_hash())
            .field("refund_template_hash", &self.refund.template_hash())
            .field("reopen_authority", &self.authority)
            .field("prepared_m8_gate", &"[opaque Store authority]")
            .finish()
    }
}

impl F7PreparedProductionDomRouteV1 {
    /// Lifetime-unique DOM signing/Wallet reservation session.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.request.session_id
    }

    /// Cross-chain settlement identifier.
    #[must_use]
    pub const fn settlement_id(&self) -> [u8; 32] {
        self.request.settlement_id
    }

    /// Hash of the accepted route terms.
    #[must_use]
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.request.terms_hash
    }

    /// Shared confidential-output value frozen by the accepted route terms.
    #[must_use]
    pub const fn shared_value_noms(&self) -> u64 {
        self.request.shared_value_noms
    }

    /// Route-wide public adaptor point `T`.
    #[must_use]
    pub const fn adaptor_point(&self) -> AdaptorPointBytes {
        self.request.adaptor_point
    }

    /// Canonical pre-funding M.8 policy digest.
    #[must_use]
    pub const fn m8_policy_digest(&self) -> [u8; 32] {
        self.request.m8_policy_digest
    }

    /// Authenticated DOM chain identity.
    #[must_use]
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    /// Public shared-output commitment only.
    #[must_use]
    pub fn shared_output_commitment(&self) -> [u8; 33] {
        *self.shared_output.commitment()
    }

    /// Frozen canonical funding template hash.
    #[must_use]
    pub const fn funding_template_hash(&self) -> [u8; 32] {
        self.funding.template_hash()
    }

    /// Frozen canonical Claim template hash.
    #[must_use]
    pub const fn claim_template_hash(&self) -> [u8; 32] {
        self.claim.template_hash()
    }

    /// Frozen canonical Refund template hash.
    #[must_use]
    pub fn refund_template_hash(&self) -> [u8; 32] {
        self.refund.template_hash()
    }

    /// Absolute DOM Refund lock height.
    #[must_use]
    pub const fn refund_lock_height(&self) -> u64 {
        self.request.refund_lock_height
    }

    /// Authoritative collaborative Bulletproof statement digest.
    #[must_use]
    pub fn bp_statement_hash(&self) -> [u8; 32] {
        self.bp_statement.statement_hash()
    }

    /// Funding signer keys in frozen DOM signing-index order.
    #[must_use]
    pub fn funding_signing_public_keys(&self) -> [[u8; 33]; 2] {
        self.funding
            .signing_public_keys()
            .map(|key| key.to_compressed_bytes())
    }

    /// Claim signer keys in frozen DOM signing-index order.
    #[must_use]
    pub fn claim_signing_public_keys(&self) -> [[u8; 33]; 2] {
        self.claim
            .signing_public_keys()
            .map(|key| key.to_compressed_bytes())
    }

    /// Refund signer keys in frozen DOM signing-index order.
    #[must_use]
    pub fn refund_signing_public_keys(&self) -> [[u8; 33]; 2] {
        self.refund
            .signing_public_keys()
            .map(|key| key.to_compressed_bytes())
    }

    /// Consumes or reopens the exact retained M.8 funding-signing round.
    ///
    /// Both `ReadyToFund` votes are completed through the Store's typed,
    /// restart-safe next-vote authority before issuance. A `RefundSigned`
    /// head issues a fresh process-local authorization; a
    /// `FundingAuthorized` head reimports only the already-issued authority
    /// and resumes the matching nonce-vault reservations. No fallback may
    /// replace a retained funding round after restart.
    pub fn sign_or_resume_funding(
        self,
        current_height: u64,
    ) -> Result<F7PreparedProductionDomFundingV1, F7DomRoutePreparationErrorV1> {
        let mut controller = ContinueEveryDsc1CheckpointV1;
        self.sign_or_resume_funding_with_fault(current_height, &mut controller)
    }

    /// Same M.8 funding round, with the runtime fault controller attached.
    ///
    /// This is the Funding-purpose counterpart of
    /// [`F7ProductionDomPostFundingOwnerV1::sign_or_resume_claim_with_fault`],
    /// and exists for the same reason: without it a scenario carrying a
    /// Funding-purpose DSC1 prefix cut or equivocation runs as though it
    /// carried no fault at all.
    pub fn sign_or_resume_funding_with_fault(
        self,
        current_height: u64,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7PreparedProductionDomFundingV1, F7DomRoutePreparationErrorV1> {
        let Self {
            request,
            chain_id,
            authority,
            _prepared_m8_gate: prepared_m8_gate,
            bp_statement,
            shared_output: _,
            _session_shares: _,
            funding,
            claim,
            refund,
        } = self;
        // Read the signed refund identity before the gate is demanded. A route
        // resumed after its funding was already broadcast has no gate left to
        // read it from, because the gate is consumed by construction.
        let signed_refund_tx_hash = match &refund {
            F7PreparedDomRefundV1::Signed {
                _artifact: artifact,
                ..
            } => Some(artifact.tx_hash()),
            F7PreparedDomRefundV1::Bound(_) => None,
        };

        let mut composition = authority.open_existing_composition()?;
        if composition.trusted_chain_id() != &chain_id {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let head_phase = composition
            .session_store()
            .load_session(request.session_id)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?
            .phase();

        // Resumed after the funding was already authorized and recorded.
        //
        // A crash can land here because this method drives Contracts all the
        // way to `FundingBroadcast` before the runner commits its own earlier
        // events, so a restart injected at a runner stage before funding finds
        // Contracts already past it. Nothing may be issued or signed again. The
        // byte-identical funding is reloaded through the store's own
        // retransmission path, which itself requires the one-shot authorization
        // to be durably consumed and the `FundingBroadcast` successor to belong
        // to the authenticated session history, so this reconstructs an
        // existing authorization and never creates a second one.
        if matches!(
            head_phase,
            SessionPhaseV1::FundingBroadcast | SessionPhaseV1::FundingConfirmed
        ) {
            // A resumed route carries a bound refund rather than the signed
            // artifact, so the identity comes from the durable gate record,
            // which keeps it after the gate itself is consumed.
            let refund_tx_hash = match signed_refund_tx_hash {
                Some(hash) => hash,
                None => composition
                    .session_store()
                    .durable_m8_refund_tx_hash(request.session_id)
                    .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
            };
            if refund_tx_hash == [0; 32] {
                return Err(F7DomRoutePreparationErrorV1::Composition);
            }
            let retransmission = composition
                .session_store()
                .resend_funding_broadcast(request.session_id)
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let funding_tx_hash = retransmission.funding_tx_hash();
            if funding_tx_hash == [0; 32] || funding_tx_hash == refund_tx_hash {
                return Err(F7DomRoutePreparationErrorV1::Composition);
            }
            let broadcast = retransmission.into_broadcast();
            drop(composition);
            let post_funding_composition = authority.open_existing_composition()?;
            let post_funding_head = post_funding_composition
                .session_store()
                .load_session(request.session_id)
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let claim_round_start_transcript_hash = post_funding_head.transcript_hash();
            if claim_round_start_transcript_hash == [0; 32]
                || claim.session_id() != request.session_id
            {
                return Err(F7DomRoutePreparationErrorV1::Composition);
            }
            return Ok(F7PreparedProductionDomFundingV1 {
                broadcast,
                receipt: F7ProductionDomFundingReceiptV1 {
                    funding_tx_hash,
                    refund_tx_hash,
                },
                post_funding_owner: F7ProductionDomPostFundingOwnerV1 {
                    composition: post_funding_composition,
                    claim,
                    session_id: request.session_id,
                    claim_round_start_transcript_hash,
                },
            });
        }

        let prepared_m8_gate = prepared_m8_gate
            .ok_or(F7DomRoutePreparationErrorV1::M8FundingGateAuthorityUnavailable)?;
        let refund_tx_hash = prepared_m8_gate.refund_tx_hash();
        if refund_tx_hash == [0; 32]
            || signed_refund_tx_hash.is_some_and(|hash| hash != refund_tx_hash)
        {
            return Err(F7DomRoutePreparationErrorV1::Composition);
        }
        let funding_context = composition
            .bind_operational_transport(request.session_id, funding.signing_public_keys())?;
        {
            let identities = [
                composition.participant_identity_store(0)?,
                composition.participant_identity_store(1)?,
            ];
            persist_ready_to_fund_votes(
                composition.session_store(),
                identities,
                &funding_context,
                &prepared_m8_gate,
            )?;
        }
        let phase = composition
            .session_store()
            .load_session(request.session_id)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?
            .phase();
        let resume = match phase {
            SessionPhaseV1::RefundSigned => false,
            SessionPhaseV1::FundingAuthorized => true,
            _ => return Err(F7DomRoutePreparationErrorV1::Composition),
        };
        let authorization = if resume {
            funding.resume_prepared_production_m8_funding(
                prepared_m8_gate,
                &bp_statement,
                composition.session_store_mut(),
            )?
        } else {
            funding.issue_prepared_production_m8_funding(
                prepared_m8_gate,
                &bp_statement,
                composition.session_store_mut(),
            )?
        };
        let (mut store, participants, retained_chain) = composition.into_canonical_parts()?;
        if retained_chain.as_bytes() != &chain_id {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let [participant_a, participant_b] = participants;
        let (vault_a, identity_a) = participant_a.into_parts_for_purpose(PurposeV1::Funding)?;
        let (vault_b, identity_b) = participant_b.into_parts_for_purpose(PurposeV1::Funding)?;
        let identities = [&identity_a, &identity_b];
        let (broadcast, funding_tx_hash) = if resume {
            funding.resume_sign_finalize_and_persist_production_with_tx_hash_and_fault(
                authorization,
                &mut store,
                identities,
                [vault_a, vault_b],
                &funding_context,
                current_height,
                fault_controller,
            )?
        } else {
            funding.sign_finalize_and_persist_production_with_tx_hash_and_fault(
                authorization,
                &mut store,
                identities,
                [vault_a, vault_b],
                &funding_context,
                current_height,
                fault_controller,
            )?
        };
        drop(store);
        drop(identity_a);
        drop(identity_b);
        if funding_tx_hash == [0; 32] || funding_tx_hash == refund_tx_hash {
            return Err(F7DomRoutePreparationErrorV1::Composition);
        }
        let post_funding_composition = authority.open_existing_composition()?;
        let post_funding_head = post_funding_composition
            .session_store()
            .load_session(request.session_id)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let claim_round_start_transcript_hash = post_funding_head.transcript_hash();
        if post_funding_head.phase() != SessionPhaseV1::FundingBroadcast
            || claim_round_start_transcript_hash == [0; 32]
            || claim.session_id() != request.session_id
        {
            return Err(F7DomRoutePreparationErrorV1::Composition);
        }
        Ok(F7PreparedProductionDomFundingV1 {
            broadcast,
            receipt: F7ProductionDomFundingReceiptV1 {
                funding_tx_hash,
                refund_tx_hash,
            },
            post_funding_owner: F7ProductionDomPostFundingOwnerV1 {
                composition: post_funding_composition,
                claim,
                session_id: request.session_id,
                claim_round_start_transcript_hash,
            },
        })
    }

    /// Reopens only the retained post-funding Store and Claim authority.
    ///
    /// This restart entry is available exclusively after the original M.8
    /// funding authority was durably consumed into `FundingBroadcast`. It
    /// accepts either that exact head or its authenticated `FundingConfirmed`
    /// successor, whose transcript is deliberately preserved as the Claim
    /// round start. The exact artifact, consumption and historical broadcast
    /// are reauthenticated through the Store, but the resulting retransmission
    /// capability is dropped without dispatch. No funding signing round,
    /// anchor transition or transaction submission is repeated. At
    /// `FundingConfirmed`, the combined runner remains the sole caller that
    /// rehydrates the consumed post-anchor Claim authorization.
    pub fn reopen_post_funding_owner(
        self,
    ) -> Result<F7ProductionDomPostFundingOwnerV1, F7DomRoutePreparationErrorV1> {
        let Self {
            request,
            chain_id,
            authority,
            _prepared_m8_gate: prepared_m8_gate,
            bp_statement: _,
            shared_output: _,
            _session_shares: _,
            funding: _,
            claim,
            refund: _,
        } = self;
        if prepared_m8_gate.is_some() {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }

        let composition = authority.open_existing_composition()?;
        if composition.trusted_chain_id() != &chain_id {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let current = composition
            .session_store()
            .load_session(request.session_id)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let claim_round_start_transcript_hash = current.transcript_hash();
        // The refund-path phases resume through this owner too: a
        // refund-outcome route whose session already marched to
        // `RefundEligible`/`RefundBroadcast` re-enters here on resume
        // (F-20260819T000139Z). The funding retransmission below stays valid in
        // those phases because it validates the historical record at the
        // broadcast revision, not the current phase.
        if !matches!(
            current.phase(),
            SessionPhaseV1::FundingBroadcast
                | SessionPhaseV1::FundingConfirmed
                | SessionPhaseV1::RefundEligible
                | SessionPhaseV1::RefundBroadcast
        ) || current.terms_hash() != request.terms_hash
            || claim_round_start_transcript_hash == [0; 32]
            || claim.session_id() != request.session_id
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let retransmission = composition
            .session_store()
            .resend_funding_broadcast(request.session_id)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        drop(retransmission);

        Ok(F7ProductionDomPostFundingOwnerV1 {
            composition,
            claim,
            session_id: request.session_id,
            claim_round_start_transcript_hash,
        })
    }
}

impl F7OfficialWalletPairV1 {
    /// Creates a new production DOM route, completes the collaborative
    /// Bulletproof, prepares all Wallet templates, signs the refund before
    /// funding, and persists the exact M.8 gate.
    ///
    /// Secret-bearing shares, capsule material, round-two payloads, signing
    /// authorities and transaction bytes never leave `dom-leg`. The returned
    /// value exposes only public commitments and retains the linear authorities
    /// required by later funding/claim/refund stages.
    pub fn prepare_fresh_production_dom_route(
        &mut self,
        fresh: F7FreshDomRoutePreparationRequestV1,
        authority: F7ProductionDomRouteAuthorityFactoryV1,
    ) -> Result<F7PreparedProductionDomRouteV1, F7DomRoutePreparationErrorV1> {
        let mut controller = ContinueEveryDsc1CheckpointV1;
        self.prepare_fresh_production_dom_route_with_fault(fresh, authority, &mut controller)
    }

    /// Same fresh preparation, with the runtime fault controller attached to
    /// the Refund-purpose DSC1 round it performs.
    ///
    /// Refunds are signed here, before any funding exists, which is what I5
    /// requires. A Refund-purpose prefix cut or equivocation therefore has to
    /// be offered at this point or nowhere.
    pub fn prepare_fresh_production_dom_route_with_fault(
        &mut self,
        fresh: F7FreshDomRoutePreparationRequestV1,
        authority: F7ProductionDomRouteAuthorityFactoryV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7PreparedProductionDomRouteV1, F7DomRoutePreparationErrorV1> {
        let request = fresh.route;
        if self.chain_id() != authority.expected_chain_id
            || request.session_id == [0; 32]
            || complete_existing_authority_roots(authority.parent())?
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }

        let mut composition = authority.create_fresh_composition()?;
        let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
            authority.network_magic,
            &Hash256::from_bytes(authority.genesis_hash),
        );
        let layout = composition.participant_layout()?;

        let session_shares = {
            let [vault_a, vault_b] = composition.participant_nonce_vaults_mut(&layout)?;
            let pending_a = contribute_vault_backed_blinding_share_v1(
                &trusted_chain_id,
                request.session_id,
                &layout.roster,
                layout.directions[0],
                0,
                request.terms_hash,
                vault_a,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let pending_b = contribute_vault_backed_blinding_share_v1(
                &trusted_chain_id,
                request.session_id,
                &layout.roster,
                layout.directions[1],
                1,
                request.terms_hash,
                vault_b,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let decoy_a = pending_a
                .derive_decoy_contribution_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let decoy_b = pending_b
                .derive_decoy_contribution_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let decoy_b_commitment = decoy_b.commitment();
            let capsule = combine_decoy_capsule_v1(
                &decoy_a.into_reveal(),
                &decoy_b.into_reveal(),
                &decoy_b_commitment,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let share_a = pending_a
                .bind_recovery_capsule_restartable_v1(&capsule, vault_a)
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            let share_b = pending_b
                .bind_recovery_capsule_restartable_v1(&capsule, vault_b)
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
            ([share_a, share_b], capsule)
        };
        let (mut session_shares, capsule) = session_shares;

        let participant_roster = participant_roster_for_session(
            &composition,
            &trusted_chain_id,
            &layout,
            [&session_shares[0], &session_shares[1]],
        )?;
        let initial_transcript = initial_transcript_hash_v1(
            &trusted_chain_id,
            &request.session_id,
            ContractKindV1::WitnessOrTimeout,
            &participant_roster,
        );
        let initial = SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id: request.session_id,
                revision: 0,
                phase: SessionPhaseV1::SharesRevealed,
                terms_hash: request.terms_hash,
                transcript_hash: initial_transcript,
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: false,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 1,
                },
                chain: SessionChainProjectionV1 {
                    tip_id: fresh.funding_tip_id,
                    tip_height: request.funding_tip_height,
                    funding: SessionTxObservationV1::Unknown,
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            &[],
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        composition
            .session_store()
            .create_session(&initial)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let initial_context = composition.bind_operational_transport(
            request.session_id,
            [
                session_shares[0].public_key().clone(),
                session_shares[1].public_key().clone(),
            ],
        )?;
        if initial_context.roster() != &participant_roster {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }

        let contributions = [
            session_shares[0]
                .blinding_contribution_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
            session_shares[1]
                .blinding_contribution_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
        ];
        let capsule_hash = *dom_crypto::blake2b_256(capsule.as_bytes()).as_bytes();
        let shared_commitment = aggregate_shared_commitment_v1(
            &trusted_chain_id,
            request.session_id,
            &layout.roster,
            request.shared_value_noms,
            request.terms_hash,
            capsule_hash,
            &contributions,
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let bp_statement = BpStatementV1::new(
            &trusted_chain_id,
            request.session_id,
            layout.roster.to_vec(),
            request.shared_value_noms,
            session_shares
                .iter()
                .map(|share| share.public_key().clone())
                .collect(),
            PublicKey::from_compressed_bytes(shared_commitment.commitment_bytes())
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
            Some(capsule_hash),
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let (shared_output, mut next_sequences, mut transport_receiver) =
            complete_fresh_collaborative_bp(
                &mut composition,
                &layout,
                &initial_context,
                &trusted_chain_id,
                [&session_shares[0], &session_shares[1]],
                &bp_statement,
                &capsule,
                &shared_commitment,
            )?;

        let reservations = self
            .prepare_or_resume_route_reservations(
                &request,
                *shared_output.commitment(),
                layout.canonical_to_authority,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let templates = self
            .compose_route_templates(
                &request,
                reservations,
                [&session_shares[0], &session_shares[1]],
                &shared_output,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        persist_fresh_template_commitments(
            &composition,
            &initial_context,
            &mut transport_receiver,
            &mut next_sequences,
            &request,
            templates.funding.template_hash(),
            templates.claim.template_hash(),
            templates.refund.template_hash(),
        )?;

        let current = composition
            .session_store()
            .load_session(request.session_id)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let refund_signing = current
            .advance(
                current.revision(),
                SessionPhaseV1::RefundSigning,
                current.transcript_hash(),
                current.irreversible(),
                current.chain(),
                current.encrypted_payload(),
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        composition
            .session_store()
            .advance_session(current.revision(), &refund_signing)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;

        let refund_signing_keys = templates.refund.signing_public_keys();
        let refund_context = composition
            .bind_operational_transport(request.session_id, refund_signing_keys.clone())?;
        let refund_template_hash = templates.refund.template_hash();
        let refund_template = templates.refund.transaction_template().clone();
        let claim_template = templates.claim.transaction_template().clone();
        let claim_adaptor_point = PublicKey::from_compressed_bytes(&request.adaptor_point.0)
            .map_err(|_| F7DomRoutePreparationErrorV1::InvalidRequest)?;
        let backup_acknowledgements = [
            session_shares[0]
                .take_durable_backup_ack_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
            session_shares[1]
                .take_durable_backup_ack_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
        ];

        let (store, participants, retained_chain) = composition.into_canonical_parts()?;
        if retained_chain.as_bytes() != trusted_chain_id.as_bytes() {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let [participant_a, participant_b] = participants;
        let (vault_a, identity_a) = participant_a.into_parts_for_purpose(PurposeV1::Refund)?;
        let (vault_b, identity_b) = participant_b.into_parts_for_purpose(PurposeV1::Refund)?;
        let identities = [&identity_a, &identity_b];
        let signed_refund = templates
            .refund
            .sign_and_finalize_production_with_fault(
                &store,
                identities,
                [vault_a, vault_b],
                &refund_context,
                fault_controller,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let accepted_refund_round = store
            .resume_operational_signing_session(
                trusted_chain_id,
                request.session_id,
                PurposeV1::Refund,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        for message in accepted_refund_round.accepted_signing_messages() {
            transport_receiver
                .accept(message, SessionPhaseV1::RefundSigning)
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        }
        next_sequences[0] = next_sequences[0]
            .checked_add(3)
            .ok_or(F7DomRoutePreparationErrorV1::Composition)?;
        next_sequences[1] = next_sequences[1]
            .checked_add(3)
            .ok_or(F7DomRoutePreparationErrorV1::Composition)?;
        persist_final_refund(
            &store,
            identities,
            &refund_context,
            &mut transport_receiver,
            0,
            next_sequences[0],
            signed_refund.canonical_bytes(),
        )?;

        let evidence = verify_operational_m8_funding_gate_evidence_v1(
            OperationalM8FundingGateVerificationRequestV1 {
                session_id: request.session_id,
                terms_hash: request.terms_hash,
                m8_policy_digest: request.m8_policy_digest,
                refund_bytes: signed_refund.canonical_bytes(),
                refund_unlock_height: request.refund_lock_height,
                claim_template: &claim_template,
                claim_kernel_index: 0,
                claim_adaptor_point: &claim_adaptor_point,
                refund_template: &refund_template,
                dom_context: DomTransactionValidationContextV1::new(
                    request.funding_tip_height,
                    authority.expected_chain_id,
                    fresh.now_unix_seconds,
                ),
                shared_blinding_bindings: [
                    session_shares[0].binding(),
                    session_shares[1].binding(),
                ],
                bp_statement: &bp_statement,
                backup_acknowledgements: &backup_acknowledgements,
            },
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let prepared_m8_gate = store
            .prepare_operational_m8_funding_gate_authority(evidence)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;

        Ok(F7PreparedProductionDomRouteV1 {
            request,
            chain_id: authority.expected_chain_id,
            authority,
            _prepared_m8_gate: Some(prepared_m8_gate),
            bp_statement,
            shared_output,
            _session_shares: session_shares,
            funding: templates.funding,
            claim: templates.claim,
            refund: F7PreparedDomRefundV1::Signed {
                template_hash: refund_template_hash,
                signing_public_keys: refund_signing_keys,
                _artifact: signed_refund,
            },
        })
    }

    /// Reopens one already-bootstrapped opaque production DOM route.
    ///
    /// This entry never creates the initial session or selects a chain tip.
    /// It accepts only two existing capsule-bound shares, a complete Store-
    /// authenticated `0x05..0x0a` collaborative-Bulletproof transcript and an
    /// already-prepared M.8 gate. Any earlier prefix remains unavailable until
    /// the lower authorities can resume every vault/DSC1 crash cut without a
    /// raw share, retained reveal, round-two share or caller-derived transcript.
    pub fn prepare_or_resume_production_dom_route(
        &mut self,
        request: F7DomRoutePreparationRequestV1,
        authority: F7ProductionDomRouteAuthorityFactoryV1,
    ) -> Result<F7PreparedProductionDomRouteV1, F7DomRoutePreparationErrorV1> {
        if self.chain_id() != authority.expected_chain_id
            || request.session_id == [0; 32]
            || authority.parent().as_os_str().is_empty()
            || authority
                .secret_files()
                .iter()
                .any(|path| path.as_os_str().is_empty())
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        if !complete_existing_authority_roots(&authority.parent)? {
            return Err(F7DomRoutePreparationErrorV1::ProductionBootstrapAuthorityUnavailable);
        }
        let mut composition = authority.open_existing_composition()?;
        let current = match composition.session_store().load_session(request.session_id) {
            Ok(current) => current,
            Err(SessionStoreError::SessionNotFound) => {
                return Err(F7DomRoutePreparationErrorV1::ProductionBootstrapAuthorityUnavailable)
            }
            Err(_) => return Err(F7DomRoutePreparationErrorV1::Composition),
        };
        if current.terms_hash() != request.terms_hash {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }

        let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
            authority.network_magic,
            &Hash256::from_bytes(authority.genesis_hash),
        );
        let layout = composition.participant_layout()?;
        let restart_requests = [0_u16, 1_u16].map(|participant_index| {
            SharedBlindingRestartRequestV1::new(
                &trusted_chain_id,
                request.session_id,
                &layout.roster,
                layout.directions[usize::from(participant_index)],
                participant_index,
                request.terms_hash,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)
        });
        let [restart_a, restart_b] = restart_requests;
        let [vault_a, vault_b] = composition.participant_nonce_vaults_mut(&layout)?;
        let share_a = resume_vault_backed_blinding_share_after_restart_v1(restart_a?, vault_a)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let share_b = resume_vault_backed_blinding_share_after_restart_v1(restart_b?, vault_b)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let (session_shares, capsule) = match (share_a, share_b) {
            (
                RestartedSessionBlindingShareV1::Bound {
                    capability: first,
                    capsule: first_capsule,
                },
                RestartedSessionBlindingShareV1::Bound {
                    capability: second,
                    capsule: second_capsule,
                },
            ) if first_capsule.as_bytes() == second_capsule.as_bytes() => {
                ([first, second], first_capsule)
            }
            _ => return Err(F7DomRoutePreparationErrorV1::ProductionBootstrapAuthorityUnavailable),
        };
        let capsule_hash = *dom_crypto::blake2b_256(capsule.as_bytes()).as_bytes();
        if session_shares[0].binding().participant_index() != 0
            || session_shares[1].binding().participant_index() != 1
            || session_shares
                .iter()
                .any(|share| share.binding().capsule_hash() != &capsule_hash)
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let contributions = [
            session_shares[0]
                .blinding_contribution_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
            session_shares[1]
                .blinding_contribution_v1()
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
        ];
        let shared_commitment = aggregate_shared_commitment_v1(
            &trusted_chain_id,
            request.session_id,
            &layout.roster,
            request.shared_value_noms,
            request.terms_hash,
            capsule_hash,
            &contributions,
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let bp_statement = BpStatementV1::new(
            &trusted_chain_id,
            request.session_id,
            layout.roster.to_vec(),
            request.shared_value_noms,
            session_shares
                .iter()
                .map(|share| share.public_key().clone())
                .collect(),
            PublicKey::from_compressed_bytes(shared_commitment.commitment_bytes())
                .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
            Some(capsule_hash),
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let continuation = composition
            .session_store()
            .resume_operational_bp_continuation(
                trusted_chain_id,
                request.session_id,
                request.terms_hash,
                &bp_statement,
                &capsule,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let finalizer_mask = continuation.accepted_participants();
        if continuation.chain_id() != authority.expected_chain_id
            || continuation.session_id() != request.session_id
            || continuation.terms_hash() != request.terms_hash
            || continuation.statement_hash() != bp_statement.statement_hash()
            || continuation.stage() != OperationalBpContinuationStageV1::Complete
            || !matches!(finalizer_mask, [true, false] | [false, true])
        {
            return Err(F7DomRoutePreparationErrorV1::CollaborativeBpContinuationIncomplete);
        }
        let final_proof = continuation
            .into_final_proof()
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let finalizer_index = usize::from(final_proof.finalizer_participant_index());
        if finalizer_index >= session_shares.len() || !finalizer_mask[finalizer_index] {
            return Err(F7DomRoutePreparationErrorV1::Composition);
        }
        let shared_output = VerifiedSharedOutputV1::from_collaborative_proof_and_capsule(
            &shared_commitment,
            final_proof.into_proof(),
            Some(&capsule),
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;

        let prepared_m8_gate = match current.phase() {
            // The refund-path phases sit past funding exactly like
            // `FundingConfirmed`: the gate was consumed when funding was
            // authorized, so there is nothing to reopen. A refund-outcome route
            // resumed after its session marched to `RefundEligible` or
            // `RefundBroadcast` (F-20260819T000139Z re-entry) lands here.
            SessionPhaseV1::FundingBroadcast
            | SessionPhaseV1::FundingConfirmed
            | SessionPhaseV1::RefundEligible
            | SessionPhaseV1::RefundBroadcast => None,
            // The operational M.8 funding gate exists from `RefundSigned`
            // until funding is authorized. `ClaimSigning` and `ClaimPrepared`
            // are the phases in between, so a route resumed there holds a
            // durable, unconsumed gate and must reopen it. The Contracts store
            // accepts the same four phases; both sides have to agree or a
            // restart before funding cannot recover.
            SessionPhaseV1::RefundSigned
            | SessionPhaseV1::ClaimSigning
            | SessionPhaseV1::ClaimPrepared
            | SessionPhaseV1::FundingAuthorized => Some(
                composition
                    .session_store()
                    .resume_operational_m8_funding_gate_authority(request.session_id)
                    .map_err(|error| match error {
                        SessionStoreError::FundingAuthorityUnavailable
                        | SessionStoreError::SessionNotFound => {
                            F7DomRoutePreparationErrorV1::M8FundingGateAuthorityUnavailable
                        }
                        _ => F7DomRoutePreparationErrorV1::Composition,
                    })?,
            ),
            _ => return Err(F7DomRoutePreparationErrorV1::M8FundingGateAuthorityUnavailable),
        };
        let reservations = self
            .prepare_or_resume_route_reservations(
                &request,
                *shared_output.commitment(),
                layout.canonical_to_authority,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let templates = self
            .compose_route_templates(
                &request,
                reservations,
                [&session_shares[0], &session_shares[1]],
                &shared_output,
            )
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;

        Ok(F7PreparedProductionDomRouteV1 {
            request,
            chain_id: authority.expected_chain_id,
            authority,
            _prepared_m8_gate: prepared_m8_gate,
            bp_statement,
            shared_output,
            _session_shares: session_shares,
            funding: templates.funding,
            claim: templates.claim,
            refund: F7PreparedDomRefundV1::Bound(templates.refund),
        })
    }
}

fn participant_roster_for_session(
    composition: &F7ProductionContractsCompositionV1,
    trusted_chain_id: &TrustedChainIdV1,
    layout: &F7ProductionParticipantLayoutV1,
    shares: [&SessionBlindingShareCapabilityV1; 2],
) -> Result<ParticipantRosterV1, F7DomRoutePreparationErrorV1> {
    let mut entries = Vec::with_capacity(2);
    // `participant_index` is the canonical participant index and walks several parallel arrays at once; iterating one of them would hide that.
    #[allow(clippy::needless_range_loop)]
    for participant_index in 0..2 {
        let authority_slot = layout.canonical_to_authority[participant_index];
        let identity = composition
            .participant_identity_store(
                u16::try_from(authority_slot)
                    .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
            )?
            .reference();
        let identity_public_key = PublicKey::from_compressed_bytes(identity.schnorr_public_key())
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let entry = ParticipantIdentityV1::new(
            trusted_chain_id,
            identity_public_key,
            shares[participant_index].public_key().clone(),
            layout.directions[participant_index],
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        if entry.participant_id() != &layout.roster[participant_index] {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        entries.push(entry);
    }
    ParticipantRosterV1::new(entries).map_err(|_| F7DomRoutePreparationErrorV1::Composition)
}

fn receiver_for_context(
    context: &F7OperationalSigningContextV1,
    phase: SessionPhaseV1,
    transcript_hash: [u8; 32],
) -> Result<SessionReceiverV1, F7DomRoutePreparationErrorV1> {
    let entries = context.roster().entries();
    let initiator = entries
        .iter()
        .find(|entry| entry.direction() == DirectionV1::Initiator)
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let responder = entries
        .iter()
        .find(|entry| entry.direction() == DirectionV1::Responder)
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let participants = [initiator, responder].map(|entry| {
        TransportParticipantV1::new(
            *entry.participant_id(),
            entry.identity_public_key().clone(),
            entry.direction(),
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)
    });
    let [initiator, responder] = participants;
    SessionReceiverV1::new(
        *context.trusted_chain_id(),
        context.session_id(),
        [initiator?, responder?],
        phase,
        transcript_hash,
    )
    .map_err(|_| F7DomRoutePreparationErrorV1::Composition)
}

#[allow(clippy::too_many_arguments)]
fn accept_composition_message(
    composition: &F7ProductionContractsCompositionV1,
    context: &F7OperationalSigningContextV1,
    receiver: &mut SessionReceiverV1,
    current: &mut SessionRecordV1,
    participant_index: usize,
    sequence: u64,
    kind: MessageTypeV1,
    payload: &[u8],
    accepted_phase: SessionPhaseV1,
) -> Result<(), F7DomRoutePreparationErrorV1> {
    let participant = context
        .roster()
        .entries()
        .get(participant_index)
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let references = composition
        .session_store()
        .transport_identity_references(context.session_id())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let reference = references
        .iter()
        .find(|reference| reference.participant_id() == participant.participant_id())
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let identity = (0_u16..2)
        .find_map(|slot| {
            composition
                .participant_identity_store(slot)
                .ok()
                .filter(|identity| {
                    identity.reference().key_reference() == reference.key_reference()
                })
        })
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let unsigned = UnsignedMessageV1::new(
        kind,
        *context.trusted_chain_id(),
        context.session_id(),
        *participant.participant_id(),
        sequence,
        current.transcript_hash(),
        payload.to_vec(),
    )
    .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let signed = identity
        .sign_exact_dsc1_for_session(unsigned, reference)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let volatile = receiver
        .accept(signed.as_bytes(), accepted_phase)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let successor = current
        .advance(
            current.revision(),
            accepted_phase,
            volatile.transcript_hash,
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    match composition
        .session_store()
        .accept_transport_message(signed.as_bytes(), &successor, None)
    {
        Ok(DurableTransportOutcomeV1::Accepted(receipt))
            if !receipt.duplicate
                && receipt.message_digest == volatile.message_digest
                && receipt.transcript_hash == volatile.transcript_hash => {}
        _ => return Err(F7DomRoutePreparationErrorV1::Composition),
    }
    *current = composition
        .session_store()
        .load_session(context.session_id())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn complete_fresh_collaborative_bp(
    composition: &mut F7ProductionContractsCompositionV1,
    layout: &F7ProductionParticipantLayoutV1,
    context: &F7OperationalSigningContextV1,
    trusted_chain_id: &TrustedChainIdV1,
    shares: [&SessionBlindingShareCapabilityV1; 2],
    statement: &BpStatementV1,
    capsule: &RecoveryCapsule,
    shared_commitment: &SharedCommitmentV1,
) -> Result<(VerifiedSharedOutputV1, [u64; 2], SessionReceiverV1), F7DomRoutePreparationErrorV1> {
    let mut current = composition
        .session_store()
        .load_session(context.session_id())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let mut receiver = receiver_for_context(context, current.phase(), current.transcript_hash())?;
    let mut next_sequences = [0_u64; 2];
    let drivers = [
        shares[0]
            .bind_collaborative_range_proof_v1(statement, capsule.as_bytes().to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
        shares[1]
            .bind_collaborative_range_proof_v1(statement, capsule.as_bytes().to_vec())
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?,
    ];
    let (pending_a, common_commit_a, pending_b, common_commit_b) = {
        let [vault_a, vault_b] = composition.participant_nonce_vaults_mut(layout)?;
        let (pending_a, common_commit_a) = shares[0]
            .begin_collaborative_range_proof_v1(statement, vault_a)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let (pending_b, common_commit_b) = shares[1]
            .begin_collaborative_range_proof_v1(statement, vault_b)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        (pending_a, common_commit_a, pending_b, common_commit_b)
    };
    let common_reveal_a = pending_a.reveal_bytes();
    let common_reveal_b = pending_b.reveal_bytes();
    for (participant_index, payload) in [common_commit_a.as_slice(), common_commit_b.as_slice()]
        .into_iter()
        .enumerate()
    {
        accept_composition_message(
            composition,
            context,
            &mut receiver,
            &mut current,
            participant_index,
            next_sequences[participant_index],
            MessageTypeV1::BpCommonCommit,
            payload,
            SessionPhaseV1::BpCommonCommitted,
        )?;
        next_sequences[participant_index] += 1;
    }
    for (participant_index, payload) in [common_reveal_a.as_ref(), common_reveal_b.as_ref()]
        .into_iter()
        .enumerate()
    {
        accept_composition_message(
            composition,
            context,
            &mut receiver,
            &mut current,
            participant_index,
            next_sequences[participant_index],
            MessageTypeV1::BpCommonReveal,
            payload,
            SessionPhaseV1::BpCommonEstablished,
        )?;
        next_sequences[participant_index] += 1;
    }
    let continuation = composition
        .session_store()
        .resume_operational_bp_continuation(
            *trusted_chain_id,
            context.session_id(),
            current.terms_hash(),
            statement,
            capsule,
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let local_a = continuation
        .finish_common_nonce(pending_a)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let local_b = continuation
        .finish_common_nonce(pending_b)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let round1_a = drivers[0]
        .round1(statement, &local_a)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let round1_b = drivers[1]
        .round1(statement, &local_b)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let round1_commit_a = round1_a.reveal_commitment();
    let round1_commit_b = round1_b.reveal_commitment();
    for (participant_index, payload) in [round1_commit_a.as_slice(), round1_commit_b.as_slice()]
        .into_iter()
        .enumerate()
    {
        accept_composition_message(
            composition,
            context,
            &mut receiver,
            &mut current,
            participant_index,
            next_sequences[participant_index],
            MessageTypeV1::BpRoundCommit,
            payload,
            SessionPhaseV1::BpNonceCommitted,
        )?;
        next_sequences[participant_index] += 1;
    }
    let round1_payloads = [round1_a.to_bytes(), round1_b.to_bytes()];
    for (participant_index, payload) in round1_payloads.iter().enumerate() {
        accept_composition_message(
            composition,
            context,
            &mut receiver,
            &mut current,
            participant_index,
            next_sequences[participant_index],
            MessageTypeV1::BpRound1,
            payload,
            SessionPhaseV1::BpRound1Complete,
        )?;
        next_sequences[participant_index] += 1;
    }
    let aggregate_round1 = composition
        .session_store()
        .resume_operational_bp_continuation(
            *trusted_chain_id,
            context.session_id(),
            current.terms_hash(),
            statement,
            capsule,
        )
        .and_then(|continuation| continuation.aggregate_round1())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let (round2_a, round2_b) = {
        let [vault_a, vault_b] = composition.participant_nonce_vaults_mut(layout)?;
        let round2_a = drivers[0]
            .round2_vault_backed_v1(statement, &local_a, &aggregate_round1, vault_a)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?
            .into_zeroizing_bytes();
        let round2_b = drivers[1]
            .round2_vault_backed_v1(statement, &local_b, &aggregate_round1, vault_b)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?
            .into_zeroizing_bytes();
        (round2_a, round2_b)
    };
    for (participant_index, payload) in [round2_a.as_ref(), round2_b.as_ref()]
        .into_iter()
        .enumerate()
    {
        accept_composition_message(
            composition,
            context,
            &mut receiver,
            &mut current,
            participant_index,
            next_sequences[participant_index],
            MessageTypeV1::BpRound2,
            payload,
            SessionPhaseV1::BpRound2Complete,
        )?;
        next_sequences[participant_index] += 1;
    }
    let (aggregate_round1, aggregate_round2) = composition
        .session_store()
        .resume_operational_bp_continuation(
            *trusted_chain_id,
            context.session_id(),
            current.terms_hash(),
            statement,
            capsule,
        )
        .and_then(|continuation| continuation.into_finalize_aggregates())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let proof = {
        let [vault_a, _] = composition.participant_nonce_vaults_mut(layout)?;
        drivers[0]
            .finalize_vault_backed_v1(statement, 0, &aggregate_round1, &aggregate_round2, vault_a)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?
            .into_proof()
    };
    accept_composition_message(
        composition,
        context,
        &mut receiver,
        &mut current,
        0,
        next_sequences[0],
        MessageTypeV1::BpFinal,
        proof.as_bytes(),
        SessionPhaseV1::OutputFinalized,
    )?;
    next_sequences[0] += 1;
    let final_proof = composition
        .session_store()
        .resume_operational_bp_continuation(
            *trusted_chain_id,
            context.session_id(),
            current.terms_hash(),
            statement,
            capsule,
        )
        .and_then(|continuation| continuation.into_final_proof())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    if final_proof.finalizer_participant_index() != 0 {
        return Err(F7DomRoutePreparationErrorV1::Composition);
    }
    let shared_output = VerifiedSharedOutputV1::from_collaborative_proof_and_capsule(
        shared_commitment,
        final_proof.into_proof(),
        Some(capsule),
    )
    .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    Ok((shared_output, next_sequences, receiver))
}

#[allow(clippy::too_many_arguments)]
fn persist_fresh_template_commitments(
    composition: &F7ProductionContractsCompositionV1,
    context: &F7OperationalSigningContextV1,
    receiver: &mut SessionReceiverV1,
    next_sequences: &mut [u64; 2],
    request: &F7DomRoutePreparationRequestV1,
    funding_template_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    refund_template_hash: [u8; 32],
) -> Result<(), F7DomRoutePreparationErrorV1> {
    let mut payload = [0_u8; 160];
    payload[..32].copy_from_slice(&funding_template_hash);
    payload[32..64].copy_from_slice(&claim_template_hash);
    payload[64..96].copy_from_slice(&refund_template_hash);
    payload[96..128].copy_from_slice(&request.terms_hash);
    payload[128..].copy_from_slice(&request.m8_policy_digest);
    let mut current = composition
        .session_store()
        .load_session(request.session_id)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    // `participant_index` is passed as a value as well as used to index.
    #[allow(clippy::needless_range_loop)]
    for participant_index in 0..2 {
        accept_composition_message(
            composition,
            context,
            receiver,
            &mut current,
            participant_index,
            next_sequences[participant_index],
            MessageTypeV1::TxTemplateCommit,
            &payload,
            SessionPhaseV1::TemplatesCommitted,
        )?;
        next_sequences[participant_index] += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_final_refund(
    store: &ContractsSessionStoreV1,
    identities: [&ContractsTransportIdentityStoreV1; 2],
    context: &F7OperationalSigningContextV1,
    receiver: &mut SessionReceiverV1,
    participant_index: usize,
    sequence: u64,
    refund_bytes: &[u8],
) -> Result<(), F7DomRoutePreparationErrorV1> {
    let mut current = store
        .load_session(context.session_id())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    if receiver.transcript_hash() != &current.transcript_hash()
        || receiver.phase() != SessionPhaseV1::RefundSigning
    {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    let participant = context
        .roster()
        .entries()
        .get(participant_index)
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let references = store
        .transport_identity_references(context.session_id())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let reference = references
        .iter()
        .find(|reference| reference.participant_id() == participant.participant_id())
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let identity = identities
        .into_iter()
        .find(|identity| identity.reference().key_reference() == reference.key_reference())
        .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let unsigned = UnsignedMessageV1::new(
        MessageTypeV1::FinalRefund,
        *context.trusted_chain_id(),
        context.session_id(),
        *participant.participant_id(),
        sequence,
        current.transcript_hash(),
        refund_bytes.to_vec(),
    )
    .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let signed = identity
        .sign_exact_dsc1_for_session(unsigned, reference)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let volatile = receiver
        .accept(signed.as_bytes(), SessionPhaseV1::RefundSigned)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    let successor = current
        .advance(
            current.revision(),
            SessionPhaseV1::RefundSigned,
            volatile.transcript_hash,
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    match store.accept_transport_message(signed.as_bytes(), &successor, None) {
        Ok(DurableTransportOutcomeV1::Accepted(receipt))
            if !receipt.duplicate
                && receipt.message_digest == volatile.message_digest
                && receipt.transcript_hash == volatile.transcript_hash => {}
        _ => return Err(F7DomRoutePreparationErrorV1::Composition),
    }
    current = store
        .load_session(context.session_id())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    if current.phase() != SessionPhaseV1::RefundSigned {
        return Err(F7DomRoutePreparationErrorV1::Composition);
    }
    Ok(())
}

fn persist_ready_to_fund_votes(
    store: &ContractsSessionStoreV1,
    identities: [&ContractsTransportIdentityStoreV1; 2],
    context: &F7OperationalSigningContextV1,
    prepared: &PreparedOperationalM8FundingGateV1,
) -> Result<(), F7DomRoutePreparationErrorV1> {
    let references = store
        .transport_identity_references(context.session_id())
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    for _ in 0..2 {
        let Some(vote) = store
            .prepare_next_operational_m8_ready_to_fund_vote(prepared)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?
        else {
            return Ok(());
        };
        if vote.session_id() != context.session_id()
            || vote.payload() != prepared.ready_to_fund_vote_payload()
            || !context
                .roster()
                .entries()
                .iter()
                .any(|participant| participant.participant_id() == &vote.participant_id())
        {
            return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
        }
        let reference = references
            .iter()
            .find(|reference| reference.participant_id() == &vote.participant_id())
            .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let identity = identities
            .iter()
            .find(|identity| identity.reference().key_reference() == reference.key_reference())
            .ok_or(F7DomRoutePreparationErrorV1::AuthorityBinding)?;
        let unsigned = UnsignedMessageV1::new(
            MessageTypeV1::ReadyToFund,
            *context.trusted_chain_id(),
            vote.session_id(),
            vote.participant_id(),
            vote.sequence(),
            vote.previous_transcript_hash(),
            vote.payload().to_vec(),
        )
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        let signed = identity
            .sign_exact_dsc1_for_session(unsigned, reference)
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
        store
            .accept_prepared_operational_m8_ready_to_fund_vote(prepared, vote, signed.as_bytes())
            .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?;
    }
    if store
        .prepare_next_operational_m8_ready_to_fund_vote(prepared)
        .map_err(|_| F7DomRoutePreparationErrorV1::Composition)?
        .is_some()
    {
        return Err(F7DomRoutePreparationErrorV1::Composition);
    }
    Ok(())
}

/// Fail-closed opaque production-route preparation error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum F7DomRoutePreparationErrorV1 {
    /// Public economic, timing, transcript or adaptor binding is invalid.
    #[error("invalid F7 DOM route preparation request")]
    InvalidRequest,
    /// Owner-only authority paths could not be authenticated.
    #[error("F7 DOM production authority filesystem rejected")]
    AuthorityFilesystem,
    /// Production policy, chain identity or authority layout diverged.
    #[error("F7 DOM production authority binding rejected")]
    AuthorityBinding,
    /// The retained Wallet/Contracts/DOM composition rejected the operation.
    #[error("F7 DOM production composition rejected")]
    Composition,
    /// The retained Contracts Store rejected the operation with its existing
    /// public redacted category. No protocol bytes or private material are
    /// included in this source.
    #[error("F7 DOM production Contracts session rejected: {0}")]
    ContractsSessionSource(#[source] SessionStoreError),
    /// The real initial session/tip bootstrap is absent. Reopening never
    /// creates a caller-selected substitute.
    #[error("real DOM production bootstrap authority is unavailable")]
    ProductionBootstrapAuthorityUnavailable,
    /// The authenticated collaborative-Bulletproof journal has not reached
    /// its sole complete proof, so no fresh round replaces it.
    #[error("collaborative Bulletproof continuation is incomplete")]
    CollaborativeBpContinuationIncomplete,
    /// The exact Store-owned M.8 funding gate is not yet durable.
    #[error("prepared M.8 funding-gate authority is unavailable")]
    M8FundingGateAuthorityUnavailable,
}

impl From<F7WalletCompositorError> for F7DomRoutePreparationErrorV1 {
    fn from(error: F7WalletCompositorError) -> Self {
        match error {
            F7WalletCompositorError::ContractsSessionSource(source) => {
                Self::ContractsSessionSource(source)
            }
            _ => Self::Composition,
        }
    }
}

fn checked_sum(values: [u64; 2], fee: u64) -> Result<u64, F7DomRoutePreparationErrorV1> {
    values[0]
        .checked_add(values[1])
        .and_then(|sum| sum.checked_add(fee))
        .ok_or(F7DomRoutePreparationErrorV1::InvalidRequest)
}

fn complete_existing_authority_roots(parent: &Path) -> Result<bool, F7DomRoutePreparationErrorV1> {
    let owner = fs::metadata(parent)
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?
        .uid();
    let roots = [
        SESSION_STORE_ROOT,
        NONCE_VAULT_ROOTS[0][0],
        NONCE_VAULT_ROOTS[0][1],
        NONCE_VAULT_ROOTS[0][2],
        IDENTITY_STORE_ROOTS[0],
        NONCE_VAULT_ROOTS[1][0],
        NONCE_VAULT_ROOTS[1][1],
        NONCE_VAULT_ROOTS[1][2],
        IDENTITY_STORE_ROOTS[1],
    ];
    let mut present = [false; 9];
    for (index, root) in roots.into_iter().enumerate() {
        let path = parent.join(root);
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.permissions().mode() & 0o777 != 0o700
                    || metadata.uid() != owner
                {
                    return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
                }
                present[index] = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(F7DomRoutePreparationErrorV1::AuthorityFilesystem),
        }
    }
    if present.iter().all(|value| !value) {
        return Ok(false);
    }
    if present.iter().any(|value| !value) {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    Ok(true)
}

fn require_complete_existing_authority_roots(
    parent: &Path,
) -> Result<(), F7DomRoutePreparationErrorV1> {
    if complete_existing_authority_roots(parent)? {
        Ok(())
    } else {
        Err(F7DomRoutePreparationErrorV1::ProductionBootstrapAuthorityUnavailable)
    }
}

fn read_authority_secret(
    path: &Path,
    scenario_root: &Path,
    expected_owner: u32,
) -> Result<Zeroizing<Vec<u8>>, F7DomRoutePreparationErrorV1> {
    let canonical = validate_authority_secret(path, scenario_root, expected_owner)?;
    let before = fs::symlink_metadata(&canonical)
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    let mut file =
        File::open(&canonical).map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    let opened = file
        .metadata()
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    if before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || before.uid() != opened.uid()
        || before.mode() != opened.mode()
        || before.len() != opened.len()
        || before.nlink() != opened.nlink()
    {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityBinding)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    (&mut file)
        .take(MAX_AUTHORITY_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    let after = fs::symlink_metadata(&canonical)
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.uid() != opened.uid()
        || after.mode() != opened.mode()
        || after.len() != opened.len()
        || after.nlink() != opened.nlink()
        || bytes.len() != capacity
    {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    Ok(bytes)
}

fn require_nonce_passphrase_bytes(bytes: &[u8]) -> Result<(), F7DomRoutePreparationErrorV1> {
    if !(8..=1024).contains(&bytes.len()) || std::str::from_utf8(bytes).is_err() {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    Ok(())
}

fn require_identity_passphrase_bytes(bytes: &[u8]) -> Result<(), F7DomRoutePreparationErrorV1> {
    if !(16..=1024).contains(&bytes.len()) || bytes.contains(&0) {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<PathBuf, F7DomRoutePreparationErrorV1> {
    if !path.is_absolute() {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    path.canonicalize()
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)
}

fn validate_authority_secret(
    path: &Path,
    scenario_root: &Path,
    expected_owner: u32,
) -> Result<PathBuf, F7DomRoutePreparationErrorV1> {
    if !path.is_absolute() {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != expected_owner
        || metadata.nlink() != 1
        || !(MIN_AUTHORITY_SECRET_BYTES..=MAX_AUTHORITY_SECRET_BYTES).contains(&metadata.len())
    {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| F7DomRoutePreparationErrorV1::AuthorityFilesystem)?;
    if !canonical.starts_with(scenario_root) {
        return Err(F7DomRoutePreparationErrorV1::AuthorityBinding);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;

    const SECP256K1_GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn request() -> Result<F7DomRoutePreparationRequestV1, F7DomRoutePreparationErrorV1> {
        F7DomRoutePreparationRequestV1::new(
            [1; 32],
            [2; 32],
            [3; 32],
            100,
            F7DomFundingShapeV1::new([60, 42], 2, 2, 3, 1)?,
            F7DomPayoutShapeV1::new([98, 0], 2, 1)?,
            F7DomPayoutShapeV1::new([59, 39], 2, 2)?,
            100,
            120,
            AdaptorPointBytes(SECP256K1_GENERATOR),
            [4; 32],
            [5; 32],
        )
    }

    #[test]
    fn request_accepts_exact_balance_and_rejects_economic_or_point_drift(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(request().is_ok());
        let funding = F7DomFundingShapeV1::new([60, 42], 2, 2, 3, 1)?;
        let claim = F7DomPayoutShapeV1::new([98, 0], 2, 1)?;
        let refund = F7DomPayoutShapeV1::new([59, 39], 2, 2)?;
        let invalid_balance = F7DomRoutePreparationRequestV1::new(
            [1; 32],
            [2; 32],
            [3; 32],
            101,
            funding,
            claim,
            refund,
            100,
            120,
            AdaptorPointBytes(SECP256K1_GENERATOR),
            [4; 32],
            [5; 32],
        );
        assert!(invalid_balance.is_err());
        let old_underfunded_shape = F7DomRoutePreparationRequestV1::new(
            [1; 32],
            [2; 32],
            [3; 32],
            100,
            F7DomFundingShapeV1::new([60, 38], 2, 2, 3, 1)?,
            claim,
            refund,
            100,
            120,
            AdaptorPointBytes(SECP256K1_GENERATOR),
            [4; 32],
            [5; 32],
        );
        assert!(old_underfunded_shape.is_err());
        let invalid_point = F7DomRoutePreparationRequestV1::new(
            [1; 32],
            [2; 32],
            [3; 32],
            100,
            funding,
            claim,
            refund,
            100,
            120,
            AdaptorPointBytes([0; 33]),
            [4; 32],
            [5; 32],
        );
        assert!(invalid_point.is_err());
        Ok(())
    }

    #[test]
    fn payout_shape_binds_nonzero_output_count() {
        assert!(F7DomPayoutShapeV1::new([98, 0], 2, 1).is_ok());
        assert!(F7DomPayoutShapeV1::new([98, 0], 2, 2).is_err());
        assert!(F7DomPayoutShapeV1::new([0, 0], 2, 0).is_err());
    }

    #[test]
    fn authority_secret_rejects_wrong_mode_without_repair() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let scenario = temporary.path().canonicalize()?;
        let owner = fs::metadata(&scenario)?.uid();
        let secret = scenario.join("authority.secret");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&secret)?;
        use std::io::Write as _;
        file.write_all(b"0123456789abcdef")?;
        file.sync_all()?;
        drop(file);
        assert!(validate_authority_secret(&secret, &scenario, owner).is_ok());
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o640))?;
        assert!(validate_authority_secret(&secret, &scenario, owner).is_err());
        assert_eq!(fs::metadata(secret)?.permissions().mode() & 0o777, 0o640);
        Ok(())
    }

    #[test]
    fn existing_production_roots_are_all_or_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        assert!(!complete_existing_authority_roots(temporary.path())?);
        let roots = [
            SESSION_STORE_ROOT,
            NONCE_VAULT_ROOTS[0][0],
            NONCE_VAULT_ROOTS[0][1],
            NONCE_VAULT_ROOTS[0][2],
            IDENTITY_STORE_ROOTS[0],
            NONCE_VAULT_ROOTS[1][0],
            NONCE_VAULT_ROOTS[1][1],
            NONCE_VAULT_ROOTS[1][2],
            IDENTITY_STORE_ROOTS[1],
        ];
        for (index, root) in roots.into_iter().enumerate() {
            let path = temporary.path().join(root);
            fs::create_dir(&path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            if index + 1 == roots.len() {
                assert!(complete_existing_authority_roots(temporary.path())?);
            } else {
                assert!(matches!(
                    complete_existing_authority_roots(temporary.path()),
                    Err(F7DomRoutePreparationErrorV1::AuthorityBinding)
                ));
            }
        }
        Ok(())
    }
}

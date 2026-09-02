//! Additive F7 composition boundary for the official Wallet V3.
//!
//! D-005 continues to hold: only `dom-leg` names DOM signing and transaction
//! authority types. The cross-chain runner receives a closed, verified claim
//! artifact and never a generic DOM transaction supplied by its caller.

use std::sync::Arc;

use cap_std::fs::Dir;
use counterparty_api::RevealedSecretBytes;
use dom_adaptor::{
    advance_transcript_hash_v1, aggregate_public_nonces_v1,
    aggregate_transaction_offset_contributions_v1, binding_factor_v1, canonical_template_v1,
    finalize_plain_signature_v1, AcceptedOperationalSigningSessionV1, AcceptedSigningSessionV1,
    AdaptorPreSignatureV1, AdaptorSecret, BindingContextV1, BpStatementV1, CommitmentExportedV1,
    ContractKindV1, ContractTxRoleV1, DirectionV1, NonceCommitmentV1, NonceRevealV1, NonceVaultV1,
    OperationalClaimTransactionSinkV1, OperationalFundingAuthorizationError,
    OperationalM8FundingAuthorizationV1, PartialSignatureV1, ParticipantIdentityV1,
    ParticipantPublicNoncesV1, ParticipantRosterV1, PurposeV1, ResentArtifactV1,
    RestartedPartialAuthorizedV1, RestartedReservationV1, RevealExportedV1,
    ScriptlessTransactionTemplateV1, SessionBlindingShareCapabilityV1, SigningPhaseV1,
    SigningShareV1, TrustedChainIdV1, ValidatedSigningRoundStateV1, VaultBackedSignerError,
    VaultBackedSignerV1, VerifiedClaimTransactionV1, VerifiedScriptlessTransactionV1,
    VerifiedSharedOutputV1,
};
use dom_consensus::{validate_transaction, Transaction, TransactionKernel, ValidationContext};
use dom_core::{Amount, BlockHeight, Timestamp, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{blake2b_256, pedersen::Commitment, PublicKey, SchnorrSignature};
use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
use dom_scriptless_crypto::{Passphrase, StorageIdsV1};
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1, IdentityStoreError,
};
use dom_scriptless_primitives::scriptless_add_public_points;
use dom_scriptless_store::{
    BudgetPolicyProfileV1, BudgetPolicyV1, CanonicalCodecError,
    ConsumedClaimSigningAuthorizationV1, ContractsNonceVaultV1,
    ContractsReservationLookupCustodyV1, ContractsSessionStoreV1,
    ContractsSigningSessionAuthorityV1, DurableTransportOutcomeV1, FundingBroadcastV1,
    InventoryError, PreparedOperationalM8FundingGateV1, SessionPhaseV1, SessionStoreError,
    SessionTransportIdentityReferenceV1, SessionTransportParticipantV1,
};
use dom_scriptless_transport::{MessageTypeV1, SignedMessageV1, TransportError, UnsignedMessageV1};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet_core::{
    CoreError, ScriptlessFundingCompositionV1, ScriptlessFundingReservationSummaryV1,
    ScriptlessPayoutCompositionV1, ScriptlessPayoutReservationSummaryV1,
    ScriptlessTemplateParticipantSetV1, WalletService,
};

use crate::LegError;

/// Fail-closed errors emitted by the Wallet V3/DOM composition boundary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum F7WalletCompositorError {
    /// Wallet V3 rejected a reservation, binding, restart state or handoff.
    #[error("official Wallet V3 rejected the Scriptless handoff")]
    Wallet,
    /// The frozen DOM authority rejected a template, signature or secret.
    #[error("frozen DOM authority rejected the Scriptless transaction")]
    Dom,
    /// The two official wallets do not describe one identical two-party route.
    #[error("wallet pair is not bound to one identical DOM route")]
    Binding,
    /// A retained production Contracts session store rejected the operation.
    #[error("production Contracts session store rejected the operation")]
    ContractsSession,
    /// A retained production Contracts session store rejected the operation
    /// with its already-redacted public failure category.
    #[error("production Contracts session store rejected the operation: {0}")]
    ContractsSessionSource(#[source] SessionStoreError),
    /// A retained production Contracts nonce vault rejected the operation.
    #[error("production Contracts nonce vault rejected the operation")]
    ContractsVault,
    /// The independent Contracts transport-identity keystore rejected the operation.
    #[error("production Contracts identity store rejected the operation")]
    ContractsIdentity,
    /// The canonical DSC1 transport codec rejected the operation.
    #[error("production Contracts transport rejected the operation")]
    ContractsTransport,
    /// The integrated retained-vault signer failed closed.
    #[error("production Contracts signer rejected the operation")]
    ContractsSigner,
    /// The integrated retained-vault signer failed with its already-redacted
    /// public authority category.
    #[error("production Contracts signer rejected the operation: {0}")]
    ContractsSignerSource(#[source] VaultBackedSignerError<InventoryError, SessionStoreError>),
    /// The signing-round state machine rejected a public protocol transition.
    #[error("production Contracts signing protocol rejected the operation: {0}")]
    ContractsSignerProtocol(#[source] dom_adaptor::AdaptorError),
    /// A configured F7 fault boundary stopped the round at an authenticated
    /// durable checkpoint.
    #[error("F7 DSC1 fault boundary requested a controlled stop")]
    FaultBoundary,
}

impl From<CoreError> for F7WalletCompositorError {
    fn from(_: CoreError) -> Self {
        Self::Wallet
    }
}

impl From<dom_adaptor::AdaptorError> for F7WalletCompositorError {
    fn from(_: dom_adaptor::AdaptorError) -> Self {
        Self::Dom
    }
}

impl From<dom_wallet_core_recovery::RecoveryMaterialError> for F7WalletCompositorError {
    fn from(_: dom_wallet_core_recovery::RecoveryMaterialError) -> Self {
        Self::Wallet
    }
}

impl From<LegError> for F7WalletCompositorError {
    fn from(_: LegError) -> Self {
        Self::Dom
    }
}

impl From<SessionStoreError> for F7WalletCompositorError {
    fn from(error: SessionStoreError) -> Self {
        Self::ContractsSessionSource(error)
    }
}

impl From<InventoryError> for F7WalletCompositorError {
    fn from(_: InventoryError) -> Self {
        Self::ContractsVault
    }
}

impl From<IdentityStoreError> for F7WalletCompositorError {
    fn from(_: IdentityStoreError) -> Self {
        Self::ContractsIdentity
    }
}

impl From<TransportError> for F7WalletCompositorError {
    fn from(_: TransportError) -> Self {
        Self::ContractsTransport
    }
}

impl From<CanonicalCodecError> for F7WalletCompositorError {
    fn from(_: CanonicalCodecError) -> Self {
        Self::ContractsSession
    }
}

impl From<OperationalFundingAuthorizationError<SessionStoreError>> for F7WalletCompositorError {
    fn from(_: OperationalFundingAuthorizationError<SessionStoreError>) -> Self {
        Self::ContractsSession
    }
}

/// Closed economic purpose reported at an opaque DSC1 durable checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum F7DomDsc1PurposeV1 {
    /// Pre-funding DOM transaction signature.
    Funding,
    /// Pre-signed height-locked recovery transaction.
    Refund,
    /// Post-anchor adaptor-signature Claim round.
    Claim,
}

/// Public, secret-free checkpoint emitted only after the Contracts Store has
/// durably accepted an exact canonical DSC1 prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F7DomDsc1CheckpointV1 {
    purpose: F7DomDsc1PurposeV1,
    durable_prefix_len: u8,
}

impl F7DomDsc1CheckpointV1 {
    fn new(purpose: PurposeV1, durable_prefix_len: usize) -> Result<Self, F7WalletCompositorError> {
        let durable_prefix_len =
            u8::try_from(durable_prefix_len).map_err(|_| F7WalletCompositorError::Binding)?;
        if durable_prefix_len > 6 {
            return Err(F7WalletCompositorError::Binding);
        }
        let purpose = match purpose {
            PurposeV1::Funding => F7DomDsc1PurposeV1::Funding,
            PurposeV1::Refund => F7DomDsc1PurposeV1::Refund,
            PurposeV1::ClaimAdaptor => F7DomDsc1PurposeV1::Claim,
            PurposeV1::Sponsor | PurposeV1::RefundAdaptor => {
                return Err(F7WalletCompositorError::Binding)
            }
        };
        Ok(Self {
            purpose,
            durable_prefix_len,
        })
    }

    /// Economic purpose of the retained round.
    #[must_use]
    pub const fn purpose(&self) -> F7DomDsc1PurposeV1 {
        self.purpose
    }

    /// Exact number of canonical 0x0c/0x0d/0x0e envelopes already durable.
    #[must_use]
    pub const fn durable_prefix_len(&self) -> u8 {
        self.durable_prefix_len
    }
}

/// Closed fault/probe directive enacted entirely inside `dom-leg`.
///
/// No signed envelope, nonce, partial, transaction object or Store authority
/// crosses this API. Reorder/equivocation probes are signed by the retained
/// production identity and checked by the real Store before control returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum F7DomDsc1FaultDirectiveV1 {
    /// Continue with the next canonical message.
    Continue,
    /// Return at this already-durable prefix. A worker may persist its own
    /// authenticated marker before requesting this directive.
    StopAtDurablePrefix,
    /// Resubmit the last exact accepted envelope and require duplicate ACK.
    ReplayLastExact,
    /// Submit a validly signed sequence-gap envelope before the next canonical
    /// envelope and require rejection without Store mutation.
    RejectNextReordered,
    /// Submit a validly signed same-key alternate payload for the last
    /// accepted envelope and require durable `FailedClosed` equivocation.
    PersistLastEquivocation,
}

/// Runtime-owned callback for controlled DSC1 crash/adversarial scenarios.
///
/// Implementations receive only a public purpose and prefix count. The
/// production compositor owns and enacts every directive against retained
/// identities and the concrete Contracts Store.
pub trait F7DomDsc1FaultControllerV1 {
    /// Selects one action after the reported prefix is durable.
    fn at_durable_checkpoint(
        &mut self,
        checkpoint: F7DomDsc1CheckpointV1,
    ) -> Result<F7DomDsc1FaultDirectiveV1, F7WalletCompositorError>;

    /// Carries one canonical DSC1 transport message from sender to recipient
    /// and returns the bytes the recipient must adjudicate.
    ///
    /// The default is the identity: the exact bytes the sender produced are the
    /// exact bytes the recipient adjudicates, which is what this compositor has
    /// always done, so every existing caller is byte-for-byte unchanged. The F7
    /// laboratory overrides it to carry those bytes through a real Relay and
    /// return what it read back, so that losing the Relay genuinely loses route
    /// progress instead of being invisible to the route.
    ///
    /// An implementation MUST NOT alter the message. The caller compares the
    /// returned bytes against the sender's own and fails closed on any
    /// difference, so a transport can never become a second adjudicator: the
    /// Contracts session store remains the only authority over the message.
    fn carry(&mut self, canonical: &[u8]) -> Result<Vec<u8>, F7WalletCompositorError> {
        Ok(canonical.to_vec())
    }
}

struct NoopF7DomDsc1FaultControllerV1;

impl F7DomDsc1FaultControllerV1 for NoopF7DomDsc1FaultControllerV1 {
    fn at_durable_checkpoint(
        &mut self,
        _checkpoint: F7DomDsc1CheckpointV1,
    ) -> Result<F7DomDsc1FaultDirectiveV1, F7WalletCompositorError> {
        Ok(F7DomDsc1FaultDirectiveV1::Continue)
    }
}

/// Concrete production operational signer selected for the F7 DOM leg.
///
/// The type fixes all three authorities statically: the filesystem-backed
/// Contracts nonce vault, the Store-owned reservation-lookup custody borrow,
/// and the Store's operational global-journal session authority. No test or
/// evidence-only implementation can inhabit this alias.
pub type F7ContractsOperationalSignerV1<'store> = VaultBackedSignerV1<
    ContractsNonceVaultV1,
    ContractsReservationLookupCustodyV1<'store>,
    ContractsSigningSessionAuthorityV1,
>;

/// Public inputs that bind one production two-party operational signer.
///
/// The roster is the exact participant-ID ordered DOM roster, not wallet
/// signing-index order. The independent identity stores must already have
/// been bound to the same session in the Contracts Store. Construction
/// validates both mappings before any nonce vault can be opened.
pub struct F7OperationalSigningContextV1 {
    trusted_chain_id: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: ParticipantRosterV1,
}

impl core::fmt::Debug for F7OperationalSigningContextV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7OperationalSigningContextV1")
            .field("trusted_chain_id", self.trusted_chain_id.as_bytes())
            .field("session_id", &self.session_id)
            .field("participants", &self.roster.entries().len())
            .finish()
    }
}

impl F7OperationalSigningContextV1 {
    /// Validates one exact two-participant production signing context.
    pub fn new(
        trusted_chain_id: TrustedChainIdV1,
        session_id: [u8; 32],
        roster: ParticipantRosterV1,
    ) -> Result<Self, F7WalletCompositorError> {
        if trusted_chain_id.as_bytes() == &[0; 32]
            || session_id == [0; 32]
            || roster.entries().len() != 2
        {
            return Err(F7WalletCompositorError::Binding);
        }
        Ok(Self {
            trusted_chain_id,
            session_id,
            roster,
        })
    }

    /// Lifetime-unique Contracts session.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Exact DOM trusted-chain identifier.
    #[must_use]
    pub const fn trusted_chain_id(&self) -> &[u8; 32] {
        self.trusted_chain_id.as_bytes()
    }

    /// Exact participant-ID ordered roster.
    #[must_use]
    pub const fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }
}

/// One participant's two independent retained production authorities.
///
/// The identity keystore is deliberately separate from the signing-nonce
/// vault. Neither authority exposes private key or nonce bytes, implements
/// `Clone`, or can be replaced by an in-memory test fixture through this API.
pub struct F7ProductionParticipantAuthoritiesV1 {
    base_nonce_vault: ContractsNonceVaultV1,
    funding_nonce_vault: Option<ContractsNonceVaultV1>,
    claim_nonce_vault: Option<ContractsNonceVaultV1>,
    identity_store: ContractsTransportIdentityStoreV1,
}

/// Stable private mapping from canonical participant-ID order to the retained
/// Wallet/Contracts authority slots.
///
/// This value never crosses `dom-leg`. The same permutation owns shared
/// blinding, Wallet reservations, signing shares, identity stores and signing
/// nonce vaults for Funding, Claim and Refund even when each transaction has a
/// different G1a signing-key order.
pub(crate) struct F7ProductionParticipantLayoutV1 {
    pub(crate) roster: [[u8; 32]; 2],
    pub(crate) canonical_to_authority: [usize; 2],
    pub(crate) directions: [DirectionV1; 2],
}

impl core::fmt::Debug for F7ProductionParticipantAuthoritiesV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7ProductionParticipantAuthoritiesV1")
            .field("base_nonce_vault", &"[retained production authority]")
            .field(
                "purpose_nonce_vaults",
                &"[opaque Funding and Claim authorities]",
            )
            .field("identity_store", &"[retained production authority]")
            .finish_non_exhaustive()
    }
}

impl F7ProductionParticipantAuthoritiesV1 {
    /// Creates and retains independent production vault and identity roots.
    ///
    /// Root creation is fail closed but cannot be filesystem-atomic across
    /// two independent authorities. If the second root fails, the first stays
    /// durably initialized and must be reopened rather than recreated.
    #[allow(clippy::too_many_arguments)]
    pub fn create_production(
        parent: Arc<Dir>,
        nonce_vault_root: &str,
        identity_root: &str,
        storage_ids: StorageIdsV1,
        nonce_vault_passphrase: &Passphrase,
        identity_passphrase: &ContractsIdentityPassphraseV1,
        policy: BudgetPolicyV1,
    ) -> Result<Self, F7WalletCompositorError> {
        require_distinct_roots(nonce_vault_root, identity_root)?;
        require_production_policy(&policy)?;
        let nonce_vault = ContractsNonceVaultV1::create_production(
            parent.clone(),
            nonce_vault_root,
            storage_ids,
            nonce_vault_passphrase,
            policy,
        )?;
        let identity_store = ContractsTransportIdentityStoreV1::create_production(
            parent,
            identity_root,
            identity_passphrase,
        )?;
        Ok(Self {
            base_nonce_vault: nonce_vault,
            funding_nonce_vault: None,
            claim_nonce_vault: None,
            identity_store,
        })
    }

    /// Creates the production participant with disjoint nonce roots for the
    /// base/Refund, Funding and ClaimAdaptor authorities.
    ///
    /// The identity authority remains shared so every purpose authenticates
    /// the same participant, while each nonce vault retains an independent
    /// lifetime session-collision and clock/budget history. This constructor
    /// is the only one used by the live F7 route factory.
    #[allow(clippy::too_many_arguments)]
    pub fn create_purpose_separated_production(
        parent: Arc<Dir>,
        nonce_vault_roots: [&str; 3],
        identity_root: &str,
        storage_ids: [StorageIdsV1; 3],
        nonce_vault_passphrase: &Passphrase,
        identity_passphrase: &ContractsIdentityPassphraseV1,
        policy: BudgetPolicyV1,
    ) -> Result<Self, F7WalletCompositorError> {
        require_distinct_purpose_roots(nonce_vault_roots, identity_root)?;
        require_production_policy(&policy)?;
        let [base_storage, funding_storage, claim_storage] = storage_ids;
        let base_nonce_vault = ContractsNonceVaultV1::create_production(
            parent.clone(),
            nonce_vault_roots[0],
            base_storage,
            nonce_vault_passphrase,
            policy.clone(),
        )?;
        let funding_nonce_vault = ContractsNonceVaultV1::create_production(
            parent.clone(),
            nonce_vault_roots[1],
            funding_storage,
            nonce_vault_passphrase,
            policy.clone(),
        )?;
        let claim_nonce_vault = ContractsNonceVaultV1::create_production(
            parent.clone(),
            nonce_vault_roots[2],
            claim_storage,
            nonce_vault_passphrase,
            policy,
        )?;
        let identity_store = ContractsTransportIdentityStoreV1::create_production(
            parent,
            identity_root,
            identity_passphrase,
        )?;
        Ok(Self {
            base_nonce_vault,
            funding_nonce_vault: Some(funding_nonce_vault),
            claim_nonce_vault: Some(claim_nonce_vault),
            identity_store,
        })
    }

    /// Reopens and authenticates both retained production roots after restart.
    pub fn open_production(
        parent: Arc<Dir>,
        nonce_vault_root: &str,
        identity_root: &str,
        nonce_vault_passphrase: Passphrase,
        identity_passphrase: &ContractsIdentityPassphraseV1,
        policy: BudgetPolicyV1,
    ) -> Result<Self, F7WalletCompositorError> {
        require_distinct_roots(nonce_vault_root, identity_root)?;
        require_production_policy(&policy)?;
        let nonce_vault = ContractsNonceVaultV1::open_production(
            parent.clone(),
            nonce_vault_root,
            nonce_vault_passphrase,
            policy,
        )?;
        let identity_store = ContractsTransportIdentityStoreV1::open_production(
            parent,
            identity_root,
            identity_passphrase,
        )?;
        Ok(Self {
            base_nonce_vault: nonce_vault,
            funding_nonce_vault: None,
            claim_nonce_vault: None,
            identity_store,
        })
    }

    /// Reopens all three purpose-separated nonce roots and the one retained
    /// participant identity after restart.
    pub fn open_purpose_separated_production(
        parent: Arc<Dir>,
        nonce_vault_roots: [&str; 3],
        identity_root: &str,
        nonce_vault_passphrases: [Passphrase; 3],
        identity_passphrase: &ContractsIdentityPassphraseV1,
        policy: BudgetPolicyV1,
    ) -> Result<Self, F7WalletCompositorError> {
        require_distinct_purpose_roots(nonce_vault_roots, identity_root)?;
        require_production_policy(&policy)?;
        let [base_passphrase, funding_passphrase, claim_passphrase] = nonce_vault_passphrases;
        let base_nonce_vault = ContractsNonceVaultV1::open_production(
            parent.clone(),
            nonce_vault_roots[0],
            base_passphrase,
            policy.clone(),
        )?;
        let funding_nonce_vault = ContractsNonceVaultV1::open_production(
            parent.clone(),
            nonce_vault_roots[1],
            funding_passphrase,
            policy.clone(),
        )?;
        let claim_nonce_vault = ContractsNonceVaultV1::open_production(
            parent.clone(),
            nonce_vault_roots[2],
            claim_passphrase,
            policy,
        )?;
        let identity_store = ContractsTransportIdentityStoreV1::open_production(
            parent,
            identity_root,
            identity_passphrase,
        )?;
        Ok(Self {
            base_nonce_vault,
            funding_nonce_vault: Some(funding_nonce_vault),
            claim_nonce_vault: Some(claim_nonce_vault),
            identity_store,
        })
    }

    /// Public-only reference to the independently retained transport identity.
    #[must_use]
    pub const fn identity_reference(
        &self,
    ) -> &dom_scriptless_identity_store::ContractsTransportIdentityReferenceV1 {
        self.identity_store.reference()
    }

    /// Borrows the retained identity authority for exact DSC1 signing/Noise.
    #[must_use]
    pub const fn identity_store(&self) -> &ContractsTransportIdentityStoreV1 {
        &self.identity_store
    }

    /// Consumes the participant composition into the concrete production
    /// nonce vault and still-retained independent identity authority.
    #[must_use]
    pub fn into_parts(self) -> (ContractsNonceVaultV1, ContractsTransportIdentityStoreV1) {
        (self.base_nonce_vault, self.identity_store)
    }

    /// Consumes the participant into the nonce authority selected by the
    /// authenticated signing purpose and its unchanged identity authority.
    pub fn into_parts_for_purpose(
        self,
        purpose: PurposeV1,
    ) -> Result<(ContractsNonceVaultV1, ContractsTransportIdentityStoreV1), F7WalletCompositorError>
    {
        let Self {
            base_nonce_vault,
            funding_nonce_vault,
            claim_nonce_vault,
            identity_store,
        } = self;
        let nonce_vault = match purpose {
            PurposeV1::Refund => base_nonce_vault,
            PurposeV1::Funding => funding_nonce_vault.ok_or(F7WalletCompositorError::Binding)?,
            PurposeV1::ClaimAdaptor => claim_nonce_vault.ok_or(F7WalletCompositorError::Binding)?,
            PurposeV1::Sponsor | PurposeV1::RefundAdaptor => {
                return Err(F7WalletCompositorError::Binding)
            }
        };
        Ok((nonce_vault, identity_store))
    }
}

/// Production Contracts composition shared by both official Wallet V3 peers.
///
/// It retains one global session journal and exactly two distinct participant
/// vault/identity pairs. The session store and every nonce vault must carry the
/// same explicitly ratified production budget policy.
pub struct F7ProductionContractsCompositionV1 {
    session_store: ContractsSessionStoreV1,
    participants: [F7ProductionParticipantAuthoritiesV1; 2],
    trusted_chain_id: TrustedChainIdV1,
}

impl core::fmt::Debug for F7ProductionContractsCompositionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7ProductionContractsCompositionV1")
            .field("trusted_chain_id", &self.trusted_chain_id.as_bytes())
            .field("participants", &2)
            .finish_non_exhaustive()
    }
}

impl F7ProductionContractsCompositionV1 {
    /// Creates the production session journal and binds two already-retained
    /// participant authorities to an authenticated DOM genesis identity.
    #[allow(clippy::too_many_arguments)]
    pub fn create_production(
        parent: Arc<Dir>,
        session_store_root: &str,
        policy: BudgetPolicyV1,
        network_magic: u32,
        genesis_hash: [u8; 32],
        expected_chain_id: [u8; 32],
        participants: [F7ProductionParticipantAuthoritiesV1; 2],
    ) -> Result<Self, F7WalletCompositorError> {
        require_production_policy(&policy)?;
        // The retained dual-custody journal is an evidence store: the
        // production-ratified budgets are preserved byte-for-byte and only
        // the store's ingress profile differs. Participant vaults keep the
        // production-ratified policy untouched.
        let store_policy = policy
            .evidence_profile_variant()
            .map_err(|_| F7WalletCompositorError::Binding)?;
        let session_store = ContractsSessionStoreV1::create_evidence_only(
            parent,
            session_store_root,
            store_policy,
        )?;
        Self::from_parts(
            session_store,
            participants,
            network_magic,
            genesis_hash,
            expected_chain_id,
        )
    }

    /// Reopens the production session journal and binds two reopened
    /// participant authorities to the same authenticated DOM genesis.
    #[allow(clippy::too_many_arguments)]
    pub fn open_production(
        parent: Arc<Dir>,
        session_store_root: &str,
        policy: BudgetPolicyV1,
        network_magic: u32,
        genesis_hash: [u8; 32],
        expected_chain_id: [u8; 32],
        participants: [F7ProductionParticipantAuthoritiesV1; 2],
    ) -> Result<Self, F7WalletCompositorError> {
        require_production_policy(&policy)?;
        let store_policy = policy
            .evidence_profile_variant()
            .map_err(|_| F7WalletCompositorError::Binding)?;
        let session_store =
            ContractsSessionStoreV1::open_evidence_only(parent, session_store_root, store_policy)?;
        Self::from_parts(
            session_store,
            participants,
            network_magic,
            genesis_hash,
            expected_chain_id,
        )
    }

    fn from_parts(
        session_store: ContractsSessionStoreV1,
        participants: [F7ProductionParticipantAuthoritiesV1; 2],
        network_magic: u32,
        genesis_hash: [u8; 32],
        expected_chain_id: [u8; 32],
    ) -> Result<Self, F7WalletCompositorError> {
        // The journal must carry exactly the evidence variant of a
        // production-ratified budget set; any other profile is refused.
        if session_store.policy().profile() != BudgetPolicyProfileV1::EvidenceOnly {
            return Err(F7WalletCompositorError::Binding);
        }
        let first = participants[0].identity_reference();
        let second = participants[1].identity_reference();
        if first.key_reference() == second.key_reference()
            || first.noise_public_key() == second.noise_public_key()
            || first.schnorr_public_key() == second.schnorr_public_key()
            || network_magic == 0
            || genesis_hash == [0; 32]
            || expected_chain_id == [0; 32]
        {
            return Err(F7WalletCompositorError::Binding);
        }
        let genesis = dom_core::Hash256::from_bytes(genesis_hash);
        let trusted_chain_id =
            TrustedChainIdV1::from_authenticated_genesis(network_magic, &genesis);
        if trusted_chain_id.as_bytes() != &expected_chain_id {
            return Err(F7WalletCompositorError::Binding);
        }
        Ok(Self {
            session_store,
            participants,
            trusted_chain_id,
        })
    }

    /// Exact chain identifier derived through the frozen DOM authority.
    #[must_use]
    pub const fn trusted_chain_id(&self) -> &[u8; 32] {
        self.trusted_chain_id.as_bytes()
    }

    /// Retained global operational session journal.
    #[must_use]
    pub const fn session_store(&self) -> &ContractsSessionStoreV1 {
        &self.session_store
    }

    /// Mutable journal authority required only by the linear funding sink.
    #[must_use]
    pub fn session_store_mut(&mut self) -> &mut ContractsSessionStoreV1 {
        &mut self.session_store
    }

    /// Borrows one retained participant identity authority by canonical index.
    pub fn participant_identity_store(
        &self,
        participant_index: u16,
    ) -> Result<&ContractsTransportIdentityStoreV1, F7WalletCompositorError> {
        self.participants
            .get(usize::from(participant_index))
            .map(F7ProductionParticipantAuthoritiesV1::identity_store)
            .ok_or(F7WalletCompositorError::Binding)
    }

    /// Derives the role-stable participant-ID ordering without exposing the
    /// retained identity or nonce authorities.
    pub(crate) fn participant_layout(
        &self,
    ) -> Result<F7ProductionParticipantLayoutV1, F7WalletCompositorError> {
        let slot_directions = [DirectionV1::Initiator, DirectionV1::Responder];
        let mut entries = Vec::with_capacity(2);
        for (authority_slot, direction) in slot_directions.into_iter().enumerate() {
            let identity = self.participants[authority_slot].identity_reference();
            let identity_public_key =
                PublicKey::from_compressed_bytes(identity.schnorr_public_key())
                    .map_err(|_| F7WalletCompositorError::ContractsIdentity)?;
            let participant = ParticipantIdentityV1::new(
                &self.trusted_chain_id,
                identity_public_key.clone(),
                identity_public_key,
                direction,
            )?;
            entries.push((*participant.participant_id(), authority_slot, direction));
        }
        entries.sort_by_key(|entry| entry.0);
        if entries[0].0 >= entries[1].0 || entries[0].1 == entries[1].1 {
            return Err(F7WalletCompositorError::Binding);
        }
        Ok(F7ProductionParticipantLayoutV1 {
            roster: [entries[0].0, entries[1].0],
            canonical_to_authority: [entries[0].1, entries[1].1],
            directions: [entries[0].2, entries[1].2],
        })
    }

    /// Borrows both retained shared-blinding/signing vaults in the same
    /// canonical participant order returned by [`Self::participant_layout`].
    pub(crate) fn participant_nonce_vaults_mut(
        &mut self,
        layout: &F7ProductionParticipantLayoutV1,
    ) -> Result<[&mut ContractsNonceVaultV1; 2], F7WalletCompositorError> {
        let [first, second] = &mut self.participants;
        Ok(match layout.canonical_to_authority {
            [0, 1] => [&mut first.base_nonce_vault, &mut second.base_nonce_vault],
            [1, 0] => [&mut second.base_nonce_vault, &mut first.base_nonce_vault],
            _ => return Err(F7WalletCompositorError::Binding),
        })
    }

    /// Consumes the composition with both participant authorities in the same
    /// stable participant-ID order used by Wallet reservation/template
    /// composition. Purpose-specific G1a sorting happens only after each vault
    /// remains paired with its owning Wallet signing share.
    pub(crate) fn into_canonical_parts(
        self,
    ) -> Result<
        (
            ContractsSessionStoreV1,
            [F7ProductionParticipantAuthoritiesV1; 2],
            TrustedChainIdV1,
        ),
        F7WalletCompositorError,
    > {
        let layout = self.participant_layout()?;
        let Self {
            session_store,
            participants,
            trusted_chain_id,
        } = self;
        let participants = match layout.canonical_to_authority {
            [0, 1] => participants,
            [1, 0] => {
                let [first, second] = participants;
                [second, first]
            }
            _ => return Err(F7WalletCompositorError::Binding),
        };
        Ok((session_store, participants, trusted_chain_id))
    }

    /// Reports whether the exact post-anchor Claim signing binding is already
    /// durable for this consumed authority.
    ///
    /// Only an absent binding selects the fresh path. Every other Store error
    /// is propagated, so a stale, corrupt or mismatched retained round cannot
    /// fall back to fresh nonce allocation.
    pub(crate) fn post_anchor_claim_round_is_bound(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
    ) -> Result<bool, F7WalletCompositorError> {
        match self
            .session_store
            .resume_post_anchor_dom_claim_signing_session(authorization, self.trusted_chain_id)
        {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Consumes the complete retained production composition to execute the
    /// one post-anchor ClaimAdaptor round.
    ///
    /// The consumed Store authorization is borrowed throughout and every
    /// nonce-bearing operation stays inside the concrete Contracts vaults.
    /// No generic signer, raw share, or replaceable Store trait crosses this
    /// boundary. Reopening after a crash must reconstruct this composition and
    /// pass `resume_consumed_post_anchor_dom_claim_signing` from the same Store.
    pub fn sign_claim_after_real_anchors(
        self,
        bound_claim: F7WalletBoundDomClaimV1,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        context: &F7OperationalSigningContextV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_claim_after_real_anchors_inner(
            bound_claim,
            authorization,
            context,
            OperationalRoundInvocationV1::Fresh,
            &mut fault_controller,
        )
    }

    /// Executes the fresh post-anchor Claim round while exposing only public
    /// durable-prefix checkpoints to the runtime fault controller.
    pub(crate) fn sign_claim_after_real_anchors_with_fault(
        self,
        bound_claim: F7WalletBoundDomClaimV1,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        context: &F7OperationalSigningContextV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        self.sign_claim_after_real_anchors_inner(
            bound_claim,
            authorization,
            context,
            OperationalRoundInvocationV1::Fresh,
            fault_controller,
        )
    }

    /// Reopens the exact post-anchor Claim round from retained authorities.
    ///
    /// This entry never invokes the fresh-claim nonce path. If all six DSC1
    /// messages are durable, it returns only the Store-reconstructed aggregate.
    pub fn resume_claim_after_real_anchors(
        self,
        bound_claim: F7WalletBoundDomClaimV1,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        context: &F7OperationalSigningContextV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_claim_after_real_anchors_inner(
            bound_claim,
            authorization,
            context,
            OperationalRoundInvocationV1::ResumeAfterRestart,
            &mut fault_controller,
        )
    }

    /// Continues the retained post-anchor Claim round with no fresh nonce
    /// fallback and an opaque durable-prefix controller.
    pub(crate) fn resume_claim_after_real_anchors_with_fault(
        self,
        bound_claim: F7WalletBoundDomClaimV1,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        context: &F7OperationalSigningContextV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        self.sign_claim_after_real_anchors_inner(
            bound_claim,
            authorization,
            context,
            OperationalRoundInvocationV1::ResumeAfterRestart,
            fault_controller,
        )
    }

    fn sign_claim_after_real_anchors_inner(
        self,
        bound_claim: F7WalletBoundDomClaimV1,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        context: &F7OperationalSigningContextV1,
        invocation: OperationalRoundInvocationV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        let (session_store, participants, trusted_chain_id) = self.into_canonical_parts()?;
        if trusted_chain_id.as_bytes() != context.trusted_chain_id()
            || authorization.session_id() != &context.session_id()
        {
            return Err(F7WalletCompositorError::Binding);
        }
        let [first, second] = participants;
        let (first_vault, first_identity) =
            first.into_parts_for_purpose(PurposeV1::ClaimAdaptor)?;
        let (second_vault, second_identity) =
            second.into_parts_for_purpose(PurposeV1::ClaimAdaptor)?;
        match invocation {
            OperationalRoundInvocationV1::Fresh => bound_claim
                .sign_pre_signature_after_real_anchors_with_fault(
                    authorization,
                    &session_store,
                    [&first_identity, &second_identity],
                    [first_vault, second_vault],
                    context,
                    fault_controller,
                ),
            OperationalRoundInvocationV1::ResumeAfterRestart => bound_claim
                .resume_pre_signature_after_real_anchors_with_fault(
                    authorization,
                    &session_store,
                    [&first_identity, &second_identity],
                    [first_vault, second_vault],
                    context,
                    fault_controller,
                ),
        }
    }

    /// Binds the public participant roster and independent identity records
    /// into the retained Store before any operational signing round starts.
    ///
    /// `participant_signing_keys` is indexed by the stable canonical
    /// participant-ID order, not by the purpose-specific G1a signing index.
    /// The frozen roster derives G1a ordering internally. Both Store writes
    /// are immutable and exact-idempotent.
    pub fn bind_operational_transport(
        &self,
        session_id: [u8; 32],
        participant_signing_keys: [PublicKey; 2],
    ) -> Result<F7OperationalSigningContextV1, F7WalletCompositorError> {
        if session_id == [0; 32] || participant_signing_keys[0] == participant_signing_keys[1] {
            return Err(F7WalletCompositorError::Binding);
        }
        let layout = self.participant_layout()?;
        let mut direction_entries = Vec::with_capacity(2);
        // `participant_index` is the canonical participant index and walks several parallel arrays at once; iterating one of them would hide that.
        #[allow(clippy::needless_range_loop)]
        for participant_index in 0..2 {
            let authority_slot = layout.canonical_to_authority[participant_index];
            let direction = layout.directions[participant_index];
            let identity = self.participants[authority_slot].identity_reference();
            let identity_public_key =
                PublicKey::from_compressed_bytes(identity.schnorr_public_key())
                    .map_err(|_| F7WalletCompositorError::ContractsIdentity)?;
            let entry = ParticipantIdentityV1::new(
                &self.trusted_chain_id,
                identity_public_key,
                participant_signing_keys[participant_index].clone(),
                direction,
            )?;
            if entry.participant_id() != &layout.roster[participant_index] {
                return Err(F7WalletCompositorError::Binding);
            }
            direction_entries.push(entry);
        }
        let roster = ParticipantRosterV1::new(direction_entries.clone())?;
        let [initiator_index, responder_index] = match layout.directions {
            [DirectionV1::Initiator, DirectionV1::Responder] => [0, 1],
            [DirectionV1::Responder, DirectionV1::Initiator] => [1, 0],
            _ => return Err(F7WalletCompositorError::Binding),
        };
        let initiator = &direction_entries[initiator_index];
        let responder = &direction_entries[responder_index];
        let transport_participants = [
            SessionTransportParticipantV1::new(
                *initiator.participant_id(),
                initiator.identity_public_key().clone(),
                initiator.direction(),
            )?,
            SessionTransportParticipantV1::new(
                *responder.participant_id(),
                responder.identity_public_key().clone(),
                responder.direction(),
            )?,
        ];
        self.session_store.bind_transport_roster(
            session_id,
            *self.trusted_chain_id.as_bytes(),
            transport_participants,
        )?;
        let references = [
            self.participants[layout.canonical_to_authority[initiator_index]]
                .identity_reference()
                .bind_session_participant(*initiator.participant_id())?,
            self.participants[layout.canonical_to_authority[responder_index]]
                .identity_reference()
                .bind_session_participant(*responder.participant_id())?,
        ];
        self.session_store
            .bind_transport_identity_references(session_id, references)?;
        F7OperationalSigningContextV1::new(self.trusted_chain_id, session_id, roster)
    }

    /// Consumes the composition into its concrete production authorities.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ContractsSessionStoreV1,
        [F7ProductionParticipantAuthoritiesV1; 2],
        TrustedChainIdV1,
    ) {
        (self.session_store, self.participants, self.trusted_chain_id)
    }
}

fn require_production_policy(policy: &BudgetPolicyV1) -> Result<(), F7WalletCompositorError> {
    if policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
        return Err(F7WalletCompositorError::Binding);
    }
    Ok(())
}

fn require_distinct_roots(first: &str, second: &str) -> Result<(), F7WalletCompositorError> {
    if first.is_empty() || second.is_empty() || first == second {
        return Err(F7WalletCompositorError::Binding);
    }
    Ok(())
}

fn require_distinct_purpose_roots(
    nonce_vault_roots: [&str; 3],
    identity_root: &str,
) -> Result<(), F7WalletCompositorError> {
    if identity_root.is_empty()
        || nonce_vault_roots.iter().any(|root| root.is_empty())
        || nonce_vault_roots.contains(&identity_root)
        || nonce_vault_roots[0] == nonce_vault_roots[1]
        || nonce_vault_roots[0] == nonce_vault_roots[2]
        || nonce_vault_roots[1] == nonce_vault_roots[2]
    {
        return Err(F7WalletCompositorError::Binding);
    }
    Ok(())
}

struct OperationalRoundOutputV1 {
    partials: [PartialSignatureV1; 2],
    reveals: [NonceRevealV1; 2],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OperationalRoundInvocationV1 {
    Fresh,
    ResumeAfterRestart,
}

// One variant carries the round output and the other is a marker; boxing the
// payload would add an allocation on the hot signing path to flatten a value
// that is constructed once per round.
#[allow(clippy::large_enum_variant)]
enum OperationalRoundCompletionV1 {
    Material(OperationalRoundOutputV1),
    CompletePostAnchorClaim,
}

type F7ContractsReservationHandleV1 = <ContractsNonceVaultV1 as NonceVaultV1>::ReservationHandle;

enum ParticipantAfterCommitmentV1 {
    Commitment(CommitmentExportedV1<F7ContractsReservationHandleV1>),
    Reveal(RevealExportedV1<F7ContractsReservationHandleV1>),
    Partial(RestartedPartialAuthorizedV1),
}

// Both variants are produced once per participant per round; the size gap is
// inherent to the two shapes and boxing would move a reveal onto the heap.
#[allow(clippy::large_enum_variant)]
enum ParticipantAfterRevealV1 {
    Reveal(RevealExportedV1<F7ContractsReservationHandleV1>),
    Partial(RestartedPartialAuthorizedV1),
}

struct AcceptedRoundArtifactsV1 {
    prefix_len: usize,
    commitments: [Option<Vec<u8>>; 2],
    reveals: [Option<Vec<u8>>; 2],
    partials: [Option<Vec<u8>>; 2],
}

impl AcceptedRoundArtifactsV1 {
    fn empty(prefix_len: usize) -> Self {
        Self {
            prefix_len,
            commitments: [None, None],
            reveals: [None, None],
            partials: [None, None],
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn complete_production_operational_round_with_fault_v1(
    session_store: &ContractsSessionStoreV1,
    identity_stores: [&ContractsTransportIdentityStoreV1; 2],
    nonce_vaults: [ContractsNonceVaultV1; 2],
    context: &F7OperationalSigningContextV1,
    purpose: PurposeV1,
    transaction_template: &dom_consensus::Transaction,
    adaptor_point: Option<PublicKey>,
    signing_shares: [SigningShareV1; 2],
    post_anchor_claim_authorization: Option<&ConsumedClaimSigningAuthorizationV1>,
    invocation: OperationalRoundInvocationV1,
    fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
) -> Result<OperationalRoundCompletionV1, F7WalletCompositorError> {
    if context.session_id == [0; 32] {
        return Err(F7WalletCompositorError::Binding);
    }
    match (
        purpose,
        adaptor_point.as_ref(),
        post_anchor_claim_authorization,
    ) {
        (PurposeV1::ClaimAdaptor, Some(_), Some(_))
        | (PurposeV1::Funding | PurposeV1::Refund, None, None) => {}
        _ => return Err(F7WalletCompositorError::Binding),
    }
    let mut signer_parts = nonce_vaults
        .into_iter()
        .zip(signing_shares)
        .collect::<Vec<_>>();
    signer_parts.sort_by_key(|(_, share)| share.public_key().to_compressed_bytes());
    if signer_parts.len() != 2 || signer_parts[0].1.public_key() == signer_parts[1].1.public_key() {
        return Err(F7WalletCompositorError::Binding);
    }
    let public_keys = [
        signer_parts[0].1.public_key().clone(),
        signer_parts[1].1.public_key().clone(),
    ];
    for (signing_index, key) in public_keys.iter().enumerate() {
        let entry = context
            .roster
            .entries()
            .iter()
            .find(|entry| entry.signing_public_key() == key)
            .ok_or(F7WalletCompositorError::Binding)?;
        if usize::from(context.roster.signing_index(entry.participant_id())?) != signing_index {
            return Err(F7WalletCompositorError::Binding);
        }
    }

    let first_session = match (post_anchor_claim_authorization, invocation) {
        (Some(authorization), OperationalRoundInvocationV1::Fresh) => session_store
            .bind_post_anchor_dom_claim_signing_session(
                authorization,
                context.trusted_chain_id,
                ContractKindV1::WitnessOrTimeout,
                context.roster.clone(),
                transaction_template.clone(),
                0,
            )?,
        (Some(authorization), OperationalRoundInvocationV1::ResumeAfterRestart) => session_store
            .resume_post_anchor_dom_claim_signing_session(
                authorization,
                context.trusted_chain_id,
            )?,
        (None, OperationalRoundInvocationV1::Fresh) => session_store
            .bind_operational_signing_session(
                context.trusted_chain_id,
                context.session_id,
                ContractKindV1::WitnessOrTimeout,
                purpose,
                context.roster.clone(),
                transaction_template.clone(),
                0,
                adaptor_point.clone(),
            )?,
        (None, OperationalRoundInvocationV1::ResumeAfterRestart) => session_store
            .resume_operational_signing_session(
                context.trusted_chain_id,
                context.session_id,
                purpose,
            )?,
    };
    let second_session = match post_anchor_claim_authorization {
        Some(authorization) => session_store.resume_post_anchor_dom_claim_signing_session(
            authorization,
            context.trusted_chain_id,
        )?,
        None => session_store.resume_operational_signing_session(
            context.trusted_chain_id,
            context.session_id,
            purpose,
        )?,
    };
    let sender_sequence_bases = *first_session.sender_sequence_bases();
    if second_session.sender_sequence_bases() != &sender_sequence_bases
        || second_session.round_start_transcript_hash()
            != first_session.round_start_transcript_hash()
    {
        return Err(F7WalletCompositorError::ContractsSession);
    }
    let mut accepted = authenticate_accepted_round_prefix(
        &first_session,
        &second_session,
        context,
        purpose,
        transaction_template,
        sender_sequence_bases,
    )?;
    if invocation == OperationalRoundInvocationV1::Fresh && accepted.prefix_len != 0 {
        return Err(F7WalletCompositorError::ContractsSession);
    }
    let mut fault_directive = fault_controller
        .at_durable_checkpoint(F7DomDsc1CheckpointV1::new(purpose, accepted.prefix_len)?)?;
    require_initial_fault_directive(fault_directive, accepted.prefix_len)?;
    if fault_directive == F7DomDsc1FaultDirectiveV1::StopAtDurablePrefix {
        return Err(F7WalletCompositorError::FaultBoundary);
    }
    if purpose == PurposeV1::ClaimAdaptor && accepted.prefix_len == 6 {
        return Ok(OperationalRoundCompletionV1::CompletePostAnchorClaim);
    }
    let identities = session_store.transport_identity_references(context.session_id)?;
    let mut signers = signer_parts.into_iter().map(|(vault, share)| {
        VaultBackedSignerV1::new_operational(
            vault,
            session_store.reservation_lookup_custody(),
            session_store.operational_signing_session_authority(),
            context.trusted_chain_id,
            share,
        )
    });
    let mut signer_zero = signers.next().ok_or(F7WalletCompositorError::Binding)?;
    let mut signer_one = signers.next().ok_or(F7WalletCompositorError::Binding)?;
    if signers.next().is_some() {
        return Err(F7WalletCompositorError::Binding);
    }
    let mut round_zero = signer_zero
        .begin_operational_signing_round(first_session)
        .map_err(F7WalletCompositorError::ContractsSignerSource)?;
    let mut round_one = signer_one
        .begin_operational_signing_round(second_session)
        .map_err(F7WalletCompositorError::ContractsSignerSource)?;
    let restarted_zero =
        open_participant_reservation(&mut signer_zero, &mut round_zero, invocation)?;
    let restarted_one = open_participant_reservation(&mut signer_one, &mut round_one, invocation)?;
    let commitment_state_zero = advance_participant_to_commitment(
        &mut signer_zero,
        &mut round_zero,
        restarted_zero,
        0,
        &mut accepted.commitments,
    )?;
    let commitment_state_one = advance_participant_to_commitment(
        &mut signer_one,
        &mut round_one,
        restarted_one,
        1,
        &mut accepted.commitments,
    )?;
    require_complete_payload_stage(&accepted.commitments)?;
    test_stage_prefix_crash_hook(0);

    persist_stage_messages(
        session_store,
        identity_stores,
        &identities,
        context,
        purpose,
        sender_sequence_bases,
        accepted.prefix_len,
        0,
        2,
        MessageTypeV1::SigNonceCommit,
        SigningPhaseV1::SigNonceCommit,
        &accepted.commitments,
        &mut round_zero,
        &mut round_one,
        post_anchor_claim_authorization,
        fault_controller,
        &mut fault_directive,
    )?;

    // A reveal authority is bound to the participant's protocol-roster index:
    // protocol participant k must observe exactly k prior reveals. Signers and
    // payload slots remain in G1a signing-index order, so drive this stage in
    // protocol order and durably feed each message to both rounds before the
    // next participant computes. On restart, an already accepted reveal is
    // recovered and compared but its durable prefix is not written again.
    let mut signers = [signer_zero, signer_one];
    let mut rounds = [round_zero, round_one];
    let mut commitment_states = [Some(commitment_state_zero), Some(commitment_state_one)];
    let mut reveal_states = [None, None];
    for protocol_index in 0..2 {
        let participant = context
            .roster
            .entries()
            .get(protocol_index)
            .ok_or(F7WalletCompositorError::Binding)?;
        let signing_index =
            usize::from(context.roster.signing_index(participant.participant_id())?);
        let commitment_state = commitment_states
            .get_mut(signing_index)
            .and_then(Option::take)
            .ok_or(F7WalletCompositorError::ContractsSigner)?;
        let reveal_state = advance_participant_to_reveal(
            signers
                .get_mut(signing_index)
                .ok_or(F7WalletCompositorError::Binding)?,
            rounds
                .get_mut(signing_index)
                .ok_or(F7WalletCompositorError::Binding)?,
            commitment_state,
            signing_index,
            &mut accepted.reveals,
        )?;
        reveal_states[signing_index] = Some(reveal_state);
        let [round_zero, round_one] = &mut rounds;
        persist_stage_messages(
            session_store,
            identity_stores,
            &identities,
            context,
            purpose,
            sender_sequence_bases,
            accepted.prefix_len,
            protocol_index,
            protocol_index + 1,
            MessageTypeV1::SigNonceReveal,
            SigningPhaseV1::SigNonceReveal,
            &accepted.reveals,
            round_zero,
            round_one,
            post_anchor_claim_authorization,
            fault_controller,
            &mut fault_directive,
        )?;
    }
    require_complete_payload_stage(&accepted.reveals)?;
    let reveal_state_zero = reveal_states[0]
        .take()
        .ok_or(F7WalletCompositorError::ContractsSigner)?;
    let reveal_state_one = reveal_states[1]
        .take()
        .ok_or(F7WalletCompositorError::ContractsSigner)?;
    let [signer_zero, signer_one] = &mut signers;
    let [round_zero, round_one] = &mut rounds;
    advance_participant_to_partial(
        signer_zero,
        round_zero,
        reveal_state_zero,
        0,
        &mut accepted.partials,
    )?;
    advance_participant_to_partial(
        signer_one,
        round_one,
        reveal_state_one,
        1,
        &mut accepted.partials,
    )?;
    require_complete_payload_stage(&accepted.partials)?;
    persist_stage_messages(
        session_store,
        identity_stores,
        &identities,
        context,
        purpose,
        sender_sequence_bases,
        accepted.prefix_len,
        0,
        2,
        MessageTypeV1::PartialSignature,
        SigningPhaseV1::SigPartial,
        &accepted.partials,
        round_zero,
        round_one,
        post_anchor_claim_authorization,
        fault_controller,
        &mut fault_directive,
    )?;
    if fault_directive != F7DomDsc1FaultDirectiveV1::Continue {
        return Err(F7WalletCompositorError::FaultBoundary);
    }
    let reveals = [
        NonceRevealV1::from_bytes(
            accepted.reveals[0]
                .as_deref()
                .ok_or(F7WalletCompositorError::ContractsSession)?,
        )?,
        NonceRevealV1::from_bytes(
            accepted.reveals[1]
                .as_deref()
                .ok_or(F7WalletCompositorError::ContractsSession)?,
        )?,
    ];
    let partials = [
        PartialSignatureV1::from_bytes(
            accepted.partials[0]
                .as_deref()
                .ok_or(F7WalletCompositorError::ContractsSession)?,
        )?,
        PartialSignatureV1::from_bytes(
            accepted.partials[1]
                .as_deref()
                .ok_or(F7WalletCompositorError::ContractsSession)?,
        )?,
    ];
    Ok(OperationalRoundCompletionV1::Material(
        OperationalRoundOutputV1 { partials, reveals },
    ))
}

fn authenticate_accepted_round_prefix(
    first_session: &dom_scriptless_store::AcceptedContractsSigningSessionV1,
    second_session: &dom_scriptless_store::AcceptedContractsSigningSessionV1,
    context: &F7OperationalSigningContextV1,
    purpose: PurposeV1,
    transaction_template: &dom_consensus::Transaction,
    sender_sequence_bases: [u64; 2],
) -> Result<AcceptedRoundArtifactsV1, F7WalletCompositorError> {
    let first_messages: Vec<Vec<u8>> = first_session
        .accepted_signing_messages()
        .map(<[u8]>::to_vec)
        .collect();
    let second_messages: Vec<Vec<u8>> = second_session
        .accepted_signing_messages()
        .map(<[u8]>::to_vec)
        .collect();
    if first_messages != second_messages || first_messages.len() > 6 {
        return Err(F7WalletCompositorError::ContractsSession);
    }
    let (_, template_hash) = canonical_template_v1(transaction_template)?;
    let mut artifacts = AcceptedRoundArtifactsV1::empty(first_messages.len());
    for (position, bytes) in first_messages.iter().enumerate() {
        let protocol_index = position % 2;
        let stage_index = position / 2;
        let expected_kind = match stage_index {
            0 => MessageTypeV1::SigNonceCommit,
            1 => MessageTypeV1::SigNonceReveal,
            2 => MessageTypeV1::PartialSignature,
            _ => return Err(F7WalletCompositorError::ContractsSession),
        };
        let participant = context
            .roster
            .entries()
            .get(protocol_index)
            .ok_or(F7WalletCompositorError::Binding)?;
        let signing_index =
            usize::from(context.roster.signing_index(participant.participant_id())?);
        let expected_sequence = sender_sequence_bases[protocol_index]
            .checked_add(u64::try_from(stage_index).map_err(|_| F7WalletCompositorError::Binding)?)
            .ok_or(F7WalletCompositorError::Binding)?;
        let signed = SignedMessageV1::decode_exact(bytes)?;
        let unsigned = signed.unsigned();
        if unsigned.kind() != expected_kind
            || unsigned.chain_id() != context.trusted_chain_id.as_bytes()
            || unsigned.session_id() != &context.session_id
            || unsigned.sender_id() != participant.participant_id()
            || unsigned.sequence() != expected_sequence
        {
            return Err(F7WalletCompositorError::ContractsSession);
        }
        let payload = unsigned.payload();
        match expected_kind {
            MessageTypeV1::SigNonceCommit => {
                let parsed = NonceCommitmentV1::from_bytes(payload)?;
                if parsed.purpose() != purpose
                    || usize::from(parsed.participant_index()) != signing_index
                {
                    return Err(F7WalletCompositorError::ContractsSession);
                }
                install_exact_payload(
                    artifacts
                        .commitments
                        .get_mut(signing_index)
                        .ok_or(F7WalletCompositorError::Binding)?,
                    payload.to_vec(),
                )?;
            }
            MessageTypeV1::SigNonceReveal => {
                let parsed = NonceRevealV1::from_bytes(payload)?;
                if parsed.purpose() != purpose
                    || usize::from(parsed.participant_index()) != signing_index
                {
                    return Err(F7WalletCompositorError::ContractsSession);
                }
                install_exact_payload(
                    artifacts
                        .reveals
                        .get_mut(signing_index)
                        .ok_or(F7WalletCompositorError::Binding)?,
                    payload.to_vec(),
                )?;
            }
            MessageTypeV1::PartialSignature => {
                let parsed = PartialSignatureV1::from_bytes(payload)?;
                if parsed.purpose() != purpose
                    || usize::from(parsed.participant_index()) != signing_index
                    || parsed.template_hash() != &template_hash
                {
                    return Err(F7WalletCompositorError::ContractsSession);
                }
                install_exact_payload(
                    artifacts
                        .partials
                        .get_mut(signing_index)
                        .ok_or(F7WalletCompositorError::Binding)?,
                    payload.to_vec(),
                )?;
            }
            _ => return Err(F7WalletCompositorError::ContractsSession),
        }
    }
    Ok(artifacts)
}

fn open_participant_reservation(
    signer: &mut F7ContractsOperationalSignerV1<'_>,
    round: &mut ValidatedSigningRoundStateV1,
    invocation: OperationalRoundInvocationV1,
) -> Result<RestartedReservationV1<F7ContractsReservationHandleV1>, F7WalletCompositorError> {
    match invocation {
        OperationalRoundInvocationV1::Fresh => signer
            .claim_fresh(
                round
                    .take_derivation_base()
                    .map_err(F7WalletCompositorError::ContractsSignerProtocol)?,
            )
            .map(RestartedReservationV1::PreDerivation)
            .map_err(F7WalletCompositorError::ContractsSignerSource),
        OperationalRoundInvocationV1::ResumeAfterRestart => signer
            .resume_claimed_after_restart(round)
            .map_err(F7WalletCompositorError::ContractsSignerSource),
    }
}

fn advance_participant_to_commitment(
    signer: &mut F7ContractsOperationalSignerV1<'_>,
    round: &mut ValidatedSigningRoundStateV1,
    state: RestartedReservationV1<F7ContractsReservationHandleV1>,
    signing_index: usize,
    payloads: &mut [Option<Vec<u8>>; 2],
) -> Result<ParticipantAfterCommitmentV1, F7WalletCompositorError> {
    match state {
        RestartedReservationV1::PreDerivation(reserved) => {
            let (state, commitment) = signer
                .derive_and_export_commitment(reserved)
                .map_err(F7WalletCompositorError::ContractsSignerSource)?;
            install_exact_payload_at(payloads, signing_index, commitment.to_bytes().to_vec())?;
            Ok(ParticipantAfterCommitmentV1::Commitment(state))
        }
        RestartedReservationV1::AfterCommitment(state) => {
            let resent = signer
                .resend_commitment_from_restarted(&state, round)
                .map_err(F7WalletCompositorError::ContractsSignerSource)?;
            let ResentArtifactV1::NonceCommitment(commitment) = resent else {
                return Err(F7WalletCompositorError::ContractsSigner);
            };
            install_exact_payload_at(payloads, signing_index, commitment.to_bytes().to_vec())?;
            Ok(ParticipantAfterCommitmentV1::Commitment(state))
        }
        RestartedReservationV1::AfterReveal(state) => {
            Ok(ParticipantAfterCommitmentV1::Reveal(state))
        }
        RestartedReservationV1::PartialAuthorized(state) => {
            Ok(ParticipantAfterCommitmentV1::Partial(state))
        }
        RestartedReservationV1::TerminalBeforePublicMaterial(_) => {
            Err(F7WalletCompositorError::ContractsSigner)
        }
    }
}

fn advance_participant_to_reveal(
    signer: &mut F7ContractsOperationalSignerV1<'_>,
    round: &mut ValidatedSigningRoundStateV1,
    state: ParticipantAfterCommitmentV1,
    signing_index: usize,
    payloads: &mut [Option<Vec<u8>>; 2],
) -> Result<ParticipantAfterRevealV1, F7WalletCompositorError> {
    match state {
        ParticipantAfterCommitmentV1::Commitment(state) => {
            let authority = round
                .take_commitment_round()
                .map_err(F7WalletCompositorError::ContractsSignerProtocol)?;
            let (state, reveal) = signer
                .export_reveal(state, authority)
                .map_err(F7WalletCompositorError::ContractsSignerSource)?;
            install_exact_payload_at(payloads, signing_index, reveal.to_bytes().to_vec())?;
            Ok(ParticipantAfterRevealV1::Reveal(state))
        }
        ParticipantAfterCommitmentV1::Reveal(state) => {
            let resent = signer
                .resend_reveal_from_restarted(&state, round)
                .map_err(F7WalletCompositorError::ContractsSignerSource)?;
            let ResentArtifactV1::NonceReveal(reveal) = resent else {
                return Err(F7WalletCompositorError::ContractsSigner);
            };
            install_exact_payload_at(payloads, signing_index, reveal.to_bytes().to_vec())?;
            Ok(ParticipantAfterRevealV1::Reveal(state))
        }
        ParticipantAfterCommitmentV1::Partial(state) => {
            Ok(ParticipantAfterRevealV1::Partial(state))
        }
    }
}

fn advance_participant_to_partial(
    signer: &mut F7ContractsOperationalSignerV1<'_>,
    round: &mut ValidatedSigningRoundStateV1,
    state: ParticipantAfterRevealV1,
    signing_index: usize,
    payloads: &mut [Option<Vec<u8>>; 2],
) -> Result<(), F7WalletCompositorError> {
    let partial = match state {
        ParticipantAfterRevealV1::Reveal(state) => {
            let authority = round
                .take_reveal_round()
                .map_err(F7WalletCompositorError::ContractsSignerProtocol)?;
            let (_terminal, partial) = signer
                .sign_and_export_partial(state, authority)
                .map_err(F7WalletCompositorError::ContractsSignerSource)?;
            partial
        }
        ParticipantAfterRevealV1::Partial(state) => {
            let resent = signer
                .resend_partial_from_restarted(&state, round)
                .map_err(F7WalletCompositorError::ContractsSignerSource)?;
            let ResentArtifactV1::PartialSignature(partial) = resent else {
                return Err(F7WalletCompositorError::ContractsSigner);
            };
            partial
        }
    };
    install_exact_payload_at(payloads, signing_index, partial.to_bytes().to_vec())
}

fn install_exact_payload_at(
    payloads: &mut [Option<Vec<u8>>; 2],
    signing_index: usize,
    payload: Vec<u8>,
) -> Result<(), F7WalletCompositorError> {
    let slot = payloads
        .get_mut(signing_index)
        .ok_or(F7WalletCompositorError::Binding)?;
    install_exact_payload(slot, payload)
}

fn install_exact_payload(
    slot: &mut Option<Vec<u8>>,
    payload: Vec<u8>,
) -> Result<(), F7WalletCompositorError> {
    match slot {
        Some(existing) if existing == &payload => Ok(()),
        Some(_) => Err(F7WalletCompositorError::ContractsSigner),
        None => {
            *slot = Some(payload);
            Ok(())
        }
    }
}

fn require_complete_payload_stage(
    payloads: &[Option<Vec<u8>>; 2],
) -> Result<(), F7WalletCompositorError> {
    if payloads.iter().all(Option::is_some) {
        Ok(())
    } else {
        Err(F7WalletCompositorError::ContractsSigner)
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_stage_messages(
    session_store: &ContractsSessionStoreV1,
    identity_stores: [&ContractsTransportIdentityStoreV1; 2],
    identities: &[SessionTransportIdentityReferenceV1; 2],
    context: &F7OperationalSigningContextV1,
    purpose: PurposeV1,
    sender_sequence_bases: [u64; 2],
    accepted_prefix_len: usize,
    first_protocol_index: usize,
    protocol_index_exclusive_end: usize,
    kind: MessageTypeV1,
    signing_phase: SigningPhaseV1,
    payloads_by_signing_index: &[Option<Vec<u8>>; 2],
    first_round: &mut ValidatedSigningRoundStateV1,
    second_round: &mut ValidatedSigningRoundStateV1,
    post_anchor_claim_authorization: Option<&ConsumedClaimSigningAuthorizationV1>,
    fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    fault_directive: &mut F7DomDsc1FaultDirectiveV1,
) -> Result<(), F7WalletCompositorError> {
    let economic_phase = economic_phase_for_purpose(purpose);
    let stage_offset = match kind {
        MessageTypeV1::SigNonceCommit => 0,
        MessageTypeV1::SigNonceReveal => 1,
        MessageTypeV1::PartialSignature => 2,
        _ => return Err(F7WalletCompositorError::Binding),
    };
    if accepted_prefix_len > 6
        || first_protocol_index > protocol_index_exclusive_end
        || protocol_index_exclusive_end > 2
    {
        return Err(F7WalletCompositorError::ContractsSession);
    }
    let stage_start = stage_offset * 2;
    let first_missing_protocol_index = accepted_prefix_len
        .saturating_sub(stage_start)
        .min(2)
        .max(first_protocol_index);
    // The range does not start at zero and the index also selects a sequence base.
    #[allow(clippy::needless_range_loop)]
    for protocol_index in first_missing_protocol_index..protocol_index_exclusive_end {
        let participant = &context.roster.entries()[protocol_index];
        let signing_index =
            usize::from(context.roster.signing_index(participant.participant_id())?);
        let current = session_store.load_session(context.session_id)?;
        if current.phase() != economic_phase {
            return Err(F7WalletCompositorError::ContractsSession);
        }
        let sender_reference = identities
            .iter()
            .find(|reference| reference.participant_id() == participant.participant_id())
            .ok_or(F7WalletCompositorError::Binding)?;
        let identity_store = identity_stores
            .iter()
            .find(|store| store.reference().key_reference() == sender_reference.key_reference())
            .ok_or(F7WalletCompositorError::Binding)?;
        let sequence = sender_sequence_bases[protocol_index]
            .checked_add(u64::try_from(stage_offset).map_err(|_| F7WalletCompositorError::Binding)?)
            .ok_or(F7WalletCompositorError::Binding)?;
        let payload = payloads_by_signing_index
            .get(signing_index)
            .and_then(Option::as_ref)
            .ok_or(F7WalletCompositorError::ContractsSigner)?;
        if *fault_directive == F7DomDsc1FaultDirectiveV1::StopAtDurablePrefix {
            return Err(F7WalletCompositorError::FaultBoundary);
        }
        if *fault_directive == F7DomDsc1FaultDirectiveV1::RejectNextReordered {
            probe_reordered_message_rejection(
                session_store,
                identity_store,
                sender_reference,
                participant,
                context,
                kind,
                signing_phase,
                sequence,
                payload,
                &current,
                post_anchor_claim_authorization,
            )?;
            *fault_directive = F7DomDsc1FaultDirectiveV1::Continue;
        } else if *fault_directive != F7DomDsc1FaultDirectiveV1::Continue {
            return Err(F7WalletCompositorError::Binding);
        }
        let unsigned = UnsignedMessageV1::new(
            kind,
            *context.trusted_chain_id.as_bytes(),
            context.session_id,
            *participant.participant_id(),
            sequence,
            current.transcript_hash(),
            payload.clone(),
        )?;
        let signed = identity_store.sign_exact_dsc1_for_session(unsigned, sender_reference)?;
        let next_transcript = advance_transcript_hash_v1(
            &current.transcript_hash(),
            signed.digest(),
            participant.direction(),
            signing_phase,
        );
        let successor = current.advance(
            current.revision(),
            economic_phase,
            next_transcript,
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        // The message travels through the injected transport before the
        // recipient adjudicates it. The default transport is the identity, so
        // production behaviour is byte-for-byte unchanged; the laboratory's
        // Relay-backed transport returns what it read back out of the Relay.
        //
        // A transport that alters the message is refused here rather than
        // accepted downstream: the session store must remain the only
        // adjudicator, so anything but byte-identity fails closed.
        let carried = fault_controller.carry(signed.as_bytes())?;
        if carried.as_slice() != signed.as_bytes() {
            return Err(F7WalletCompositorError::ContractsSession);
        }
        let outcome = match post_anchor_claim_authorization {
            Some(authorization) => session_store.accept_post_anchor_dom_claim_transport_message(
                authorization,
                &carried,
                &successor,
                None,
            )?,
            None => session_store.accept_transport_message(&carried, &successor, None)?,
        };
        match outcome {
            DurableTransportOutcomeV1::Accepted(receipt)
                if !receipt.duplicate
                    && receipt.message_digest == *signed.digest()
                    && receipt.transcript_hash == next_transcript => {}
            _ => return Err(F7WalletCompositorError::ContractsSession),
        }
        test_stage_prefix_crash_hook(stage_start + protocol_index + 1);
        let durable_prefix_len = stage_start + protocol_index + 1;
        let next_directive = fault_controller
            .at_durable_checkpoint(F7DomDsc1CheckpointV1::new(purpose, durable_prefix_len)?)?;
        require_fault_directive_for_prefix(next_directive, durable_prefix_len)?;
        match next_directive {
            F7DomDsc1FaultDirectiveV1::Continue
            | F7DomDsc1FaultDirectiveV1::RejectNextReordered => {
                *fault_directive = next_directive;
            }
            F7DomDsc1FaultDirectiveV1::StopAtDurablePrefix => {
                return Err(F7WalletCompositorError::FaultBoundary);
            }
            F7DomDsc1FaultDirectiveV1::ReplayLastExact => {
                require_exact_duplicate_ack(
                    session_store,
                    signed.as_bytes(),
                    &successor,
                    signed.digest(),
                    next_transcript,
                    post_anchor_claim_authorization,
                )?;
                *fault_directive = F7DomDsc1FaultDirectiveV1::Continue;
            }
            F7DomDsc1FaultDirectiveV1::PersistLastEquivocation => {
                persist_purpose_bound_equivocation(
                    session_store,
                    identity_store,
                    sender_reference,
                    participant,
                    context,
                    kind,
                    sequence,
                    payload,
                    &current,
                    post_anchor_claim_authorization,
                )?;
                return Err(F7WalletCompositorError::FaultBoundary);
            }
        }
        first_round
            .accept_message(signed.as_bytes())
            .map_err(F7WalletCompositorError::ContractsSignerProtocol)?;
        second_round
            .accept_message(signed.as_bytes())
            .map_err(F7WalletCompositorError::ContractsSignerProtocol)?;
    }
    Ok(())
}

fn require_fault_directive_for_prefix(
    directive: F7DomDsc1FaultDirectiveV1,
    durable_prefix_len: usize,
) -> Result<(), F7WalletCompositorError> {
    let valid = match directive {
        F7DomDsc1FaultDirectiveV1::Continue | F7DomDsc1FaultDirectiveV1::StopAtDurablePrefix => {
            true
        }
        F7DomDsc1FaultDirectiveV1::ReplayLastExact
        | F7DomDsc1FaultDirectiveV1::PersistLastEquivocation => durable_prefix_len != 0,
        F7DomDsc1FaultDirectiveV1::RejectNextReordered => durable_prefix_len < 6,
    };
    if valid {
        Ok(())
    } else {
        Err(F7WalletCompositorError::Binding)
    }
}

fn require_initial_fault_directive(
    directive: F7DomDsc1FaultDirectiveV1,
    durable_prefix_len: usize,
) -> Result<(), F7WalletCompositorError> {
    let valid = match directive {
        F7DomDsc1FaultDirectiveV1::Continue | F7DomDsc1FaultDirectiveV1::StopAtDurablePrefix => {
            true
        }
        // A sequence-gap probe acts on the next canonical message and is
        // therefore meaningful only while the retained prefix is incomplete.
        F7DomDsc1FaultDirectiveV1::RejectNextReordered => durable_prefix_len < 6,
        // Exact replay and same-key equivocation require the just-signed
        // envelope retained by `persist_stage_messages`. Reopening never asks
        // the caller for envelope bytes and never fabricates them from payloads.
        F7DomDsc1FaultDirectiveV1::ReplayLastExact
        | F7DomDsc1FaultDirectiveV1::PersistLastEquivocation => false,
    };
    if valid {
        Ok(())
    } else {
        Err(F7WalletCompositorError::Binding)
    }
}

#[allow(clippy::too_many_arguments)]
fn probe_reordered_message_rejection(
    session_store: &ContractsSessionStoreV1,
    identity_store: &ContractsTransportIdentityStoreV1,
    sender_reference: &SessionTransportIdentityReferenceV1,
    participant: &ParticipantIdentityV1,
    context: &F7OperationalSigningContextV1,
    kind: MessageTypeV1,
    signing_phase: SigningPhaseV1,
    sequence: u64,
    payload: &[u8],
    current: &dom_scriptless_store::SessionRecordV1,
    post_anchor_claim_authorization: Option<&ConsumedClaimSigningAuthorizationV1>,
) -> Result<(), F7WalletCompositorError> {
    let gap_sequence = sequence
        .checked_add(1)
        .ok_or(F7WalletCompositorError::Binding)?;
    let unsigned = UnsignedMessageV1::new(
        kind,
        *context.trusted_chain_id.as_bytes(),
        context.session_id,
        *participant.participant_id(),
        gap_sequence,
        current.transcript_hash(),
        payload.to_vec(),
    )?;
    let signed = identity_store.sign_exact_dsc1_for_session(unsigned, sender_reference)?;
    let transcript = advance_transcript_hash_v1(
        &current.transcript_hash(),
        signed.digest(),
        participant.direction(),
        signing_phase,
    );
    let successor = current.advance(
        current.revision(),
        current.phase(),
        transcript,
        current.irreversible(),
        current.chain(),
        current.encrypted_payload(),
    )?;
    let rejected = match post_anchor_claim_authorization {
        Some(authorization) => session_store.accept_post_anchor_dom_claim_transport_message(
            authorization,
            signed.as_bytes(),
            &successor,
            None,
        ),
        None => session_store.accept_transport_message(signed.as_bytes(), &successor, None),
    };
    if !matches!(rejected, Err(SessionStoreError::InvalidTransition))
        || session_store.load_session(context.session_id)?.as_bytes() != current.as_bytes()
    {
        return Err(F7WalletCompositorError::ContractsSession);
    }
    Ok(())
}

fn require_exact_duplicate_ack(
    session_store: &ContractsSessionStoreV1,
    signed_bytes: &[u8],
    successor: &dom_scriptless_store::SessionRecordV1,
    expected_message_digest: &[u8; 32],
    expected_transcript_hash: [u8; 32],
    post_anchor_claim_authorization: Option<&ConsumedClaimSigningAuthorizationV1>,
) -> Result<(), F7WalletCompositorError> {
    let outcome = match post_anchor_claim_authorization {
        Some(authorization) => session_store.accept_post_anchor_dom_claim_transport_message(
            authorization,
            signed_bytes,
            successor,
            None,
        )?,
        None => session_store.accept_transport_message(signed_bytes, successor, None)?,
    };
    match outcome {
        DurableTransportOutcomeV1::Accepted(receipt)
            if receipt.duplicate
                && receipt.message_digest == *expected_message_digest
                && receipt.transcript_hash == expected_transcript_hash =>
        {
            Ok(())
        }
        _ => Err(F7WalletCompositorError::ContractsSession),
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_purpose_bound_equivocation(
    session_store: &ContractsSessionStoreV1,
    identity_store: &ContractsTransportIdentityStoreV1,
    sender_reference: &SessionTransportIdentityReferenceV1,
    participant: &ParticipantIdentityV1,
    context: &F7OperationalSigningContextV1,
    kind: MessageTypeV1,
    sequence: u64,
    payload: &[u8],
    predecessor: &dom_scriptless_store::SessionRecordV1,
    post_anchor_claim_authorization: Option<&ConsumedClaimSigningAuthorizationV1>,
) -> Result<(), F7WalletCompositorError> {
    let mut alternate_payload = payload.to_vec();
    let last = alternate_payload
        .last_mut()
        .ok_or(F7WalletCompositorError::Binding)?;
    *last ^= 1;
    let unsigned = UnsignedMessageV1::new(
        kind,
        *context.trusted_chain_id.as_bytes(),
        context.session_id,
        *participant.participant_id(),
        sequence,
        predecessor.transcript_hash(),
        alternate_payload,
    )?;
    let alternate = identity_store.sign_exact_dsc1_for_session(unsigned, sender_reference)?;
    let current = session_store.load_session(context.session_id)?;
    let failed = current.advance(
        current.revision(),
        SessionPhaseV1::FailedClosed,
        current.transcript_hash(),
        current.irreversible(),
        current.chain(),
        current.encrypted_payload(),
    )?;
    let outcome = match post_anchor_claim_authorization {
        Some(authorization) => session_store.accept_post_anchor_dom_claim_transport_message(
            authorization,
            alternate.as_bytes(),
            &failed,
            Some(&failed),
        )?,
        None => {
            session_store.accept_transport_message(alternate.as_bytes(), &failed, Some(&failed))?
        }
    };
    if outcome != DurableTransportOutcomeV1::EquivocationPersisted
        || session_store.load_session(context.session_id)?.phase() != SessionPhaseV1::FailedClosed
    {
        return Err(F7WalletCompositorError::ContractsSession);
    }
    Ok(())
}

#[cfg(test)]
fn test_stage_prefix_crash_hook(durable_prefix_len: usize) {
    let requested = std::env::var("DOM_F7_DOM_LEG_STAGE_CRASH_PREFIX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    if requested == Some(durable_prefix_len) {
        std::process::abort();
    }
}

#[cfg(not(test))]
const fn test_stage_prefix_crash_hook(_: usize) {}

const fn economic_phase_for_purpose(purpose: PurposeV1) -> SessionPhaseV1 {
    match purpose {
        PurposeV1::Funding => SessionPhaseV1::FundingAuthorized,
        PurposeV1::Refund => SessionPhaseV1::RefundSigning,
        PurposeV1::ClaimAdaptor => SessionPhaseV1::FundingConfirmed,
        // The frozen F7 surface composes no sponsor or refund-adaptor round.
        PurposeV1::Sponsor | PurposeV1::RefundAdaptor => SessionPhaseV1::FailedClosed,
    }
}

#[cfg(test)]
#[path = "f7_wallet_tests.rs"]
mod f7_wallet_tests;

fn finalize_operational_plain_signature_v1(
    context: &F7OperationalSigningContextV1,
    purpose: PurposeV1,
    template: &ScriptlessTransactionTemplateV1,
    output: OperationalRoundOutputV1,
) -> Result<SchnorrSignature, F7WalletCompositorError> {
    if !matches!(purpose, PurposeV1::Funding | PurposeV1::Refund) {
        return Err(F7WalletCompositorError::Binding);
    }
    let mut canonical_keys: Vec<PublicKey> = context
        .roster
        .entries()
        .iter()
        .map(|entry| entry.signing_public_key().clone())
        .collect();
    canonical_keys.sort_by_key(PublicKey::to_compressed_bytes);
    let mut participants = Vec::with_capacity(2);
    for reveal in &output.reveals {
        let index = usize::from(reveal.participant_index());
        let signing_key = canonical_keys
            .get(index)
            .ok_or(F7WalletCompositorError::Binding)?;
        participants.push(ParticipantPublicNoncesV1 {
            participant_index: reveal.participant_index(),
            signing_key: signing_key.clone(),
            first_nonce: reveal.first().clone(),
            second_nonce: reveal.second().clone(),
        });
    }
    participants.sort_by_key(|entry| entry.participant_index);
    let binding = binding_factor_v1(
        &BindingContextV1 {
            chain_id: *context.trusted_chain_id.as_bytes(),
            session_id: context.session_id,
            purpose,
            template_hash: *template.template_hash(),
        },
        &participants,
        None,
    )?;
    let effective_nonces: Vec<PublicKey> = participants
        .iter()
        .map(|entry| binding.bind_public_nonces(&entry.first_nonce, &entry.second_nonce))
        .collect::<Result<_, _>>()?;
    let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)?;
    let aggregate_signing_key = aggregate_public_nonces_v1(&canonical_keys)?;
    let kernel = template
        .transaction_template()
        .kernels
        .first()
        .ok_or(F7WalletCompositorError::Dom)?;
    let message = dom_scriptless_consensus::scriptless_kernel_message_digest_v1(kernel);
    finalize_plain_signature_v1(
        &output.partials,
        purpose,
        template.template_hash(),
        &aggregate_nonce,
        &aggregate_signing_key,
        context.trusted_chain_id.as_bytes(),
        message.as_bytes(),
    )
    .map_err(Into::into)
}

/// A claim template durably bound by both official Wallet V3 instances.
///
/// Construction also asks each wallet for its template-bound opaque signing
/// handoff and checks that the resulting public key occupies the exact frozen
/// participant slot. The composed shares remain opaque inside this value until
/// they are moved into the concrete retained Store signer; no raw wallet or
/// shared-output secret can cross this boundary.
pub struct F7WalletBoundDomClaimV1 {
    template: ScriptlessTransactionTemplateV1,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    signing_shares: [SigningShareV1; 2],
}

/// A funding template bound by both official Wallet V3 instances.
///
/// Its opaque combined signing shares are retained only inside `dom-leg` for
/// the concrete Contracts signer. They have no byte accessor or public escape.
pub struct F7WalletBoundDomFundingV1 {
    template: ScriptlessTransactionTemplateV1,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    signing_shares: [SigningShareV1; 2],
}

impl core::fmt::Debug for F7WalletBoundDomFundingV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7WalletBoundDomFundingV1")
            .field("template_hash", self.template.template_hash())
            .field("signing_shares", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// A pre-authorized refund template bound by both official Wallet V3 instances.
pub struct F7WalletBoundDomRefundV1 {
    template: ScriptlessTransactionTemplateV1,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    signing_shares: [SigningShareV1; 2],
}

impl core::fmt::Debug for F7WalletBoundDomRefundV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7WalletBoundDomRefundV1")
            .field("template_hash", self.template.template_hash())
            .field("signing_shares", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// A fully verified DOM refund ready for the Contracts Store funding gate.
pub struct F7VerifiedDomRefundArtifactV1 {
    verified: VerifiedScriptlessTransactionV1,
    session_id: [u8; 32],
}

/// A canonical DOM claim adaptor pre-signature produced by both production
/// Contracts nonce vaults after the post-anchor authorization is consumed.
///
/// It has no raw constructor, `Clone`, generic codec or public signing entry.
/// The only later operation is adaptation through the bound claim template.
pub struct F7WalletPreSignedDomClaimV1 {
    template: ScriptlessTransactionTemplateV1,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    pre_signature: AdaptorPreSignatureV1,
    transcript_hash: [u8; 32],
}

const MAX_F7_CANONICAL_DOM_CLAIM_BYTES: usize = 16 * 1024 * 1024;

/// Linear verifier for the exact finalized DOM ClaimAdaptor transaction.
///
/// This capability retains the authenticated pre-signature and frozen
/// unsigned transaction needed to extract the route scalar only after a real
/// scanner supplies the byte-identical canonical claim. It has no raw getter,
/// constructor, codec, `Clone` or `Copy` implementation.
pub struct F7WalletDomClaimExtractionV1 {
    unsigned_transaction: Transaction,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    pre_signature: AdaptorPreSignatureV1,
    transcript_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    shared_output_commitment: [u8; 33],
    finalized_tx_hash: [u8; 32],
}

impl core::fmt::Debug for F7WalletDomClaimExtractionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7WalletDomClaimExtractionV1")
            .field("session_id", &self.session_id)
            .field("claim_template_hash", &self.claim_template_hash)
            .field("shared_output_commitment", &self.shared_output_commitment)
            .field("finalized_tx_hash", &self.finalized_tx_hash)
            .field(
                "extraction_authority",
                &"[redacted irreversible pre-signature]",
            )
            .finish()
    }
}

impl F7WalletDomClaimExtractionV1 {
    /// Lifetime-unique DOM session authenticated by the retained signer.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Frozen signature-omitting DOM claim-template digest.
    #[must_use]
    pub const fn claim_template_hash(&self) -> [u8; 32] {
        self.claim_template_hash
    }

    /// Exact shared output spent by the claim.
    #[must_use]
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.shared_output_commitment
    }

    /// Exact fully signed claim transaction expected from canonical evidence.
    #[must_use]
    pub const fn finalized_tx_hash(&self) -> [u8; 32] {
        self.finalized_tx_hash
    }

    /// Revalidates byte-identical canonical claim evidence and extracts the
    /// now-public route scalar through the pinned adaptor verifier.
    ///
    /// The complete DOM transaction verifier runs at `current_height` before
    /// extraction. The signed transaction must reduce to this capability's
    /// frozen unsigned template when its sole kernel signature is removed.
    /// Consuming `self` makes successful extraction a one-shot authority.
    pub fn verify_and_extract(
        self,
        canonical_claim_bytes: &[u8],
        current_height: u64,
    ) -> Result<RevealedSecretBytes, F7WalletCompositorError> {
        if canonical_claim_bytes.is_empty()
            || canonical_claim_bytes.len() > MAX_F7_CANONICAL_DOM_CLAIM_BYTES
        {
            return Err(F7WalletCompositorError::Dom);
        }
        let transaction = Transaction::from_bytes(canonical_claim_bytes)
            .map_err(|_| F7WalletCompositorError::Dom)?;
        let reencoded = transaction
            .to_bytes()
            .map_err(|_| F7WalletCompositorError::Dom)?;
        if reencoded.as_slice() != canonical_claim_bytes
            || *blake2b_256(canonical_claim_bytes).as_bytes() != self.finalized_tx_hash
            || transaction.kernels.len() != 1
            || self.unsigned_transaction.kernels.len() != 1
        {
            return Err(F7WalletCompositorError::Binding);
        }
        validate_transaction(
            &transaction,
            &ValidationContext {
                current_height: BlockHeight(current_height),
                chain_id: self.chain_id,
                now: Timestamp(0),
            },
        )
        .map_err(|_| F7WalletCompositorError::Dom)?;

        let kernel = transaction
            .kernels
            .first()
            .ok_or(F7WalletCompositorError::Dom)?;
        if kernel.excess_signature == [0; 65] {
            return Err(F7WalletCompositorError::Dom);
        }
        let final_signature = SchnorrSignature::from_bytes(&kernel.excess_signature)
            .map_err(|_| F7WalletCompositorError::Dom)?;
        let signing_key = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())
            .map_err(|_| F7WalletCompositorError::Dom)?;
        let kernel_message = scriptless_kernel_message_digest_v1(kernel);

        let mut unsigned_transaction = transaction;
        unsigned_transaction.kernels[0].excess_signature = [0; 65];
        let (_, observed_template_hash) = canonical_template_v1(&unsigned_transaction)?;
        if unsigned_transaction != self.unsigned_transaction
            || observed_template_hash != self.claim_template_hash
            || self.pre_signature.claim_template_hash() != &self.claim_template_hash
            || self.pre_signature.transcript_hash() != &self.transcript_hash
        {
            return Err(F7WalletCompositorError::Binding);
        }

        let revealed = self.pre_signature.extract_revealed_secret_be_bytes(
            &final_signature,
            &self.claim_template_hash,
            &self.transcript_hash,
            &signing_key,
            &self.chain_id,
            kernel_message.as_bytes(),
        )?;
        Ok(RevealedSecretBytes::new(*revealed))
    }
}

impl core::fmt::Debug for F7WalletPreSignedDomClaimV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7WalletPreSignedDomClaimV1")
            .field("template_hash", self.template.template_hash())
            .field("transcript_hash", &self.transcript_hash)
            .field("pre_signature", &"[redacted irreversible material]")
            .finish()
    }
}

impl core::fmt::Debug for F7VerifiedDomRefundArtifactV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7VerifiedDomRefundArtifactV1")
            .field("tx_hash", self.verified.tx_hash())
            .field("canonical_bytes", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for F7WalletBoundDomClaimV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7WalletBoundDomClaimV1")
            .field("template_hash", self.template.template_hash())
            .field("session", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Fully signed canonical DOM claim created only by the frozen adaptor
/// finalizer after both official wallets bound the exact template.
///
/// The type has no public constructor, generic codec, `Clone` or mutable byte
/// access. Consuming it is the only way the F7 runner obtains broadcast bytes.
pub struct F7VerifiedDomClaimArtifactV1 {
    verified: VerifiedClaimTransactionV1,
    session_id: [u8; 32],
}

impl core::fmt::Debug for F7VerifiedDomClaimArtifactV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7VerifiedDomClaimArtifactV1")
            .field("tx_hash", self.verified.tx_hash())
            .field("template_hash", self.verified.template_hash())
            .field("canonical_bytes", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl F7VerifiedDomClaimArtifactV1 {
    /// Canonical DOM transaction identifier.
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        *self.verified.tx_hash()
    }

    /// Signature-omitting claim template hash.
    #[must_use]
    pub const fn template_hash(&self) -> [u8; 32] {
        *self.verified.template_hash()
    }

    /// Lifetime-unique DOM session bound by both wallets.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Exact shared output spent by this claim.
    #[must_use]
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        *self.verified.shared_output_commitment()
    }

    /// Consumes the typed authority into the durable claim sink.
    ///
    /// [AUTHORITY: dom-adaptor] broadcast bytes for a finalized claim exist
    /// only as the sink's persisted value: the claim must be durably
    /// persisted before any externalization, so this artifact exposes no raw
    /// canonical-byte accessor.
    pub fn persist_with_claim_sink_v1<Sink: OperationalClaimTransactionSinkV1>(
        self,
        sink: &mut Sink,
    ) -> core::result::Result<Sink::PersistedClaim, Sink::Error> {
        self.verified.persist_with_claim_sink_v1(sink)
    }
}

/// Builds and binds the exact funding template from two official wallet
/// reservations in canonical participant order.
///
/// The function obtains all inputs, recoverable change, offset contributions
/// and local kernel points from Wallet V3. DOM's frozen helpers alone aggregate
/// offsets and public points, then the canonical template validates structure,
/// proofs and balance before either wallet may release a signing handoff.
#[allow(clippy::too_many_arguments)]
pub fn compose_wallet_pair_funding_template_v1(
    first_wallet: &mut WalletService,
    second_wallet: &mut WalletService,
    reservations: [ScriptlessFundingReservationSummaryV1; 2],
    session_shares: [&SessionBlindingShareCapabilityV1; 2],
    shared_output: &VerifiedSharedOutputV1,
    shared_output_position: usize,
) -> Result<F7WalletBoundDomFundingV1, F7WalletCompositorError> {
    require_canonical_share_order(session_shares)?;
    let first_point = first_wallet.scriptless_funding_prepare_kernel_excess_point(
        reservations[0].reservation_id,
        session_shares[0],
    )?;
    let second_point = second_wallet.scriptless_funding_prepare_kernel_excess_point(
        reservations[1].reservation_id,
        session_shares[1],
    )?;
    let compositions = [
        first_wallet.scriptless_funding_export(reservations[0].reservation_id)?,
        second_wallet.scriptless_funding_export(reservations[1].reservation_id)?,
    ];
    require_funding_compositions(&compositions, shared_output)?;
    let participants = ScriptlessTemplateParticipantSetV1 {
        ordered_offset_contributions: [
            compositions[0].offset_contribution,
            compositions[1].offset_contribution,
        ],
        ordered_kernel_excess_points: [first_point, second_point],
    };
    let offset =
        aggregate_transaction_offset_contributions_v1(&participants.ordered_offset_contributions)?;
    let kernel = unsigned_kernel(
        KERNEL_FEAT_PLAIN,
        compositions[0].funding_fee_noms,
        0,
        &participants.ordered_kernel_excess_points,
    )?;
    let mut inputs = compositions[0].inputs.clone();
    inputs.extend(compositions[1].inputs.iter().cloned());
    let mut outputs = compositions[0].other_outputs.clone();
    outputs.extend(compositions[1].other_outputs.iter().cloned());
    let template = ScriptlessTransactionTemplateV1::funding(
        shared_output,
        inputs,
        outputs,
        shared_output_position,
        kernel,
        offset,
    )?;

    first_wallet.scriptless_funding_bind_template(
        reservations[0].reservation_id,
        &template,
        session_shares[0],
        participants,
    )?;
    second_wallet.scriptless_funding_bind_template(
        reservations[1].reservation_id,
        &template,
        session_shares[1],
        participants,
    )?;
    let first_share = first_wallet
        .scriptless_funding_signing_capability(reservations[0].reservation_id)?
        .compose_local_funding_share_v1(session_shares[0])?;
    let second_share = second_wallet
        .scriptless_funding_signing_capability(reservations[1].reservation_id)?
        .compose_local_funding_share_v1(session_shares[1])?;
    require_exact_participant_slot(&first_share, session_shares[0], &participants)?;
    require_exact_participant_slot(&second_share, session_shares[1], &participants)?;
    Ok(F7WalletBoundDomFundingV1 {
        template,
        chain_id: *session_shares[0].binding().chain_id(),
        session_id: *session_shares[0].binding().session_id(),
        signing_shares: [first_share, second_share],
    })
}

/// Builds and binds an exact claim template from the two distinct official
/// payout reservations.
pub fn compose_wallet_pair_claim_template_v1(
    first_wallet: &mut WalletService,
    second_wallet: &mut WalletService,
    reservations: [ScriptlessPayoutReservationSummaryV1; 2],
    session_shares: [&SessionBlindingShareCapabilityV1; 2],
    shared_output: &VerifiedSharedOutputV1,
) -> Result<F7WalletBoundDomClaimV1, F7WalletCompositorError> {
    let (template, participants) = compose_wallet_pair_spend_template(
        first_wallet,
        second_wallet,
        reservations,
        session_shares,
        shared_output,
        ContractTxRoleV1::Claim,
        0,
    )?;
    bind_wallet_pair_claim_template_v1(
        first_wallet,
        second_wallet,
        reservations,
        session_shares,
        participants,
        template,
    )
}

/// Builds and binds the exact pre-authorized absolute-height refund template
/// from the two role-distinct Wallet V3 payout reservations.
pub fn compose_wallet_pair_refund_template_v1(
    first_wallet: &mut WalletService,
    second_wallet: &mut WalletService,
    reservations: [ScriptlessPayoutReservationSummaryV1; 2],
    session_shares: [&SessionBlindingShareCapabilityV1; 2],
    shared_output: &VerifiedSharedOutputV1,
    funding_tip_height: u64,
) -> Result<F7WalletBoundDomRefundV1, F7WalletCompositorError> {
    let (template, participants) = compose_wallet_pair_spend_template(
        first_wallet,
        second_wallet,
        reservations,
        session_shares,
        shared_output,
        ContractTxRoleV1::Refund,
        funding_tip_height,
    )?;
    first_wallet.scriptless_payout_bind_template(
        reservations[0].reservation_id,
        &template,
        session_shares[0],
        participants,
    )?;
    second_wallet.scriptless_payout_bind_template(
        reservations[1].reservation_id,
        &template,
        session_shares[1],
        participants,
    )?;
    let first_share = first_wallet
        .scriptless_payout_signing_capability(reservations[0].reservation_id)?
        .compose_local_shared_output_spend_share_v1(session_shares[0])?;
    let second_share = second_wallet
        .scriptless_payout_signing_capability(reservations[1].reservation_id)?
        .compose_local_shared_output_spend_share_v1(session_shares[1])?;
    require_exact_participant_slot(&first_share, session_shares[0], &participants)?;
    require_exact_participant_slot(&second_share, session_shares[1], &participants)?;
    Ok(F7WalletBoundDomRefundV1 {
        template,
        chain_id: *session_shares[0].binding().chain_id(),
        session_id: *session_shares[0].binding().session_id(),
        signing_shares: [first_share, second_share],
    })
}

#[allow(clippy::too_many_arguments)]
fn compose_wallet_pair_spend_template(
    first_wallet: &mut WalletService,
    second_wallet: &mut WalletService,
    reservations: [ScriptlessPayoutReservationSummaryV1; 2],
    session_shares: [&SessionBlindingShareCapabilityV1; 2],
    shared_output: &VerifiedSharedOutputV1,
    role: ContractTxRoleV1,
    funding_tip_height: u64,
) -> Result<
    (
        ScriptlessTransactionTemplateV1,
        ScriptlessTemplateParticipantSetV1,
    ),
    F7WalletCompositorError,
> {
    require_canonical_share_order(session_shares)?;
    let first_point = first_wallet.scriptless_payout_prepare_kernel_excess_point(
        reservations[0].reservation_id,
        session_shares[0],
    )?;
    let second_point = second_wallet.scriptless_payout_prepare_kernel_excess_point(
        reservations[1].reservation_id,
        session_shares[1],
    )?;
    let compositions = [
        first_wallet.scriptless_payout_export(reservations[0].reservation_id)?,
        second_wallet.scriptless_payout_export(reservations[1].reservation_id)?,
    ];
    require_payout_compositions(&compositions, shared_output, role)?;
    let participants = ScriptlessTemplateParticipantSetV1 {
        ordered_offset_contributions: [
            compositions[0].offset_contribution,
            compositions[1].offset_contribution,
        ],
        ordered_kernel_excess_points: [first_point, second_point],
    };
    let offset =
        aggregate_transaction_offset_contributions_v1(&participants.ordered_offset_contributions)?;
    let lock_height = match role {
        ContractTxRoleV1::Claim => 0,
        ContractTxRoleV1::Refund => compositions[0].refund_lock_height,
        ContractTxRoleV1::Funding => return Err(F7WalletCompositorError::Binding),
    };
    let features = if role == ContractTxRoleV1::Refund {
        KERNEL_FEAT_HEIGHT_LOCKED
    } else {
        KERNEL_FEAT_PLAIN
    };
    let kernel = unsigned_kernel(
        features,
        compositions[0].kernel_fee_noms,
        lock_height,
        &participants.ordered_kernel_excess_points,
    )?;
    let mut outputs = compositions[0].outputs.clone();
    outputs.extend(compositions[1].outputs.iter().cloned());
    let template = match role {
        ContractTxRoleV1::Claim => {
            ScriptlessTransactionTemplateV1::claim(shared_output, outputs, kernel, offset)?
        }
        ContractTxRoleV1::Refund => ScriptlessTransactionTemplateV1::refund(
            shared_output,
            outputs,
            kernel,
            offset,
            funding_tip_height,
        )?,
        ContractTxRoleV1::Funding => return Err(F7WalletCompositorError::Binding),
    };
    Ok((template, participants))
}

fn unsigned_kernel(
    features: u8,
    fee_noms: u64,
    lock_height: u64,
    participant_points: &[[u8; 33]; 2],
) -> Result<TransactionKernel, F7WalletCompositorError> {
    let points = [
        PublicKey::from_compressed_bytes(&participant_points[0])
            .map_err(|_| F7WalletCompositorError::Dom)?,
        PublicKey::from_compressed_bytes(&participant_points[1])
            .map_err(|_| F7WalletCompositorError::Dom)?,
    ];
    let aggregate =
        scriptless_add_public_points(&points).map_err(|_| F7WalletCompositorError::Dom)?;
    Ok(TransactionKernel {
        features,
        fee: Amount::from_noms(fee_noms).map_err(|_| F7WalletCompositorError::Dom)?,
        lock_height,
        excess: Commitment::from_compressed_bytes(&aggregate.to_compressed_bytes())
            .map_err(|_| F7WalletCompositorError::Dom)?,
        excess_signature: [0; 65],
    })
}

fn require_canonical_share_order(
    shares: [&SessionBlindingShareCapabilityV1; 2],
) -> Result<(), F7WalletCompositorError> {
    if shares[0].binding().participant_index() != 0
        || shares[1].binding().participant_index() != 1
        || shares[0].binding().chain_id() != shares[1].binding().chain_id()
        || shares[0].binding().session_id() != shares[1].binding().session_id()
        || shares[0].binding().session_id() == &[0; 32]
    {
        return Err(F7WalletCompositorError::Binding);
    }
    Ok(())
}

fn require_funding_compositions(
    compositions: &[ScriptlessFundingCompositionV1; 2],
    shared_output: &VerifiedSharedOutputV1,
) -> Result<(), F7WalletCompositorError> {
    let first = &compositions[0];
    let second = &compositions[1];
    let input_count = first.inputs.len().saturating_add(second.inputs.len());
    let output_count = first
        .other_outputs
        .len()
        .saturating_add(second.other_outputs.len())
        .saturating_add(1);
    if first.chain_id != second.chain_id
        || first.session_id != second.session_id
        || first.shared_output_commitment != second.shared_output_commitment
        || first.shared_output_commitment != *shared_output.commitment()
        || first.funding_fee_noms != second.funding_fee_noms
        || first.expected_input_count != second.expected_input_count
        || first.expected_output_count != second.expected_output_count
        || input_count != first.expected_input_count as usize
        || output_count != first.expected_output_count as usize
    {
        return Err(F7WalletCompositorError::Binding);
    }
    Ok(())
}

fn require_payout_compositions(
    compositions: &[ScriptlessPayoutCompositionV1; 2],
    shared_output: &VerifiedSharedOutputV1,
    role: ContractTxRoleV1,
) -> Result<(), F7WalletCompositorError> {
    let first = &compositions[0];
    let second = &compositions[1];
    let output_count = first.outputs.len().saturating_add(second.outputs.len());
    let role_matches = match role {
        ContractTxRoleV1::Claim => first.refund_lock_height == 0 && second.refund_lock_height == 0,
        ContractTxRoleV1::Refund => {
            first.refund_lock_height != 0 && first.refund_lock_height == second.refund_lock_height
        }
        ContractTxRoleV1::Funding => false,
    };
    if !role_matches
        || first.role != second.role
        || first.chain_id != second.chain_id
        || first.session_id != second.session_id
        || first.shared_output_commitment != second.shared_output_commitment
        || first.shared_output_commitment != *shared_output.commitment()
        || first.kernel_fee_noms != second.kernel_fee_noms
        || first.expected_output_count != second.expected_output_count
        || output_count != first.expected_output_count as usize
        || output_count == 0
    {
        return Err(F7WalletCompositorError::Binding);
    }
    Ok(())
}

/// Binds one authoritative claim template to both official wallet databases.
///
/// Both wallet backends must already be attached to the same authenticated
/// frozen DOM chain, both reservations must be durable and exposed, and both
/// session blinding shares must come from concrete retained Contracts vaults.
/// Wallet V3 performs its own restart-safe reservation and template checks.
#[allow(clippy::too_many_arguments)]
pub fn bind_wallet_pair_claim_template_v1(
    first_wallet: &mut WalletService,
    second_wallet: &mut WalletService,
    reservations: [ScriptlessPayoutReservationSummaryV1; 2],
    session_shares: [&SessionBlindingShareCapabilityV1; 2],
    participants: ScriptlessTemplateParticipantSetV1,
    template: ScriptlessTransactionTemplateV1,
) -> Result<F7WalletBoundDomClaimV1, F7WalletCompositorError> {
    if template.role() != ContractTxRoleV1::Claim
        || session_shares[0].binding().chain_id() != session_shares[1].binding().chain_id()
        || session_shares[0].binding().session_id() != session_shares[1].binding().session_id()
        || session_shares[0].binding().session_id() == &[0; 32]
        || session_shares[0].binding().participant_index()
            == session_shares[1].binding().participant_index()
        || template.shared_output_commitment() == &[0; 33]
    {
        return Err(F7WalletCompositorError::Binding);
    }

    first_wallet.scriptless_payout_bind_template(
        reservations[0].reservation_id,
        &template,
        session_shares[0],
        participants,
    )?;
    second_wallet.scriptless_payout_bind_template(
        reservations[1].reservation_id,
        &template,
        session_shares[1],
        participants,
    )?;

    let first_handoff =
        first_wallet.scriptless_payout_signing_capability(reservations[0].reservation_id)?;
    let second_handoff =
        second_wallet.scriptless_payout_signing_capability(reservations[1].reservation_id)?;
    let first_share =
        first_handoff.compose_local_shared_output_spend_share_v1(session_shares[0])?;
    let second_share =
        second_handoff.compose_local_shared_output_spend_share_v1(session_shares[1])?;
    require_exact_participant_slot(&first_share, session_shares[0], &participants)?;
    require_exact_participant_slot(&second_share, session_shares[1], &participants)?;
    Ok(F7WalletBoundDomClaimV1 {
        template,
        chain_id: *session_shares[0].binding().chain_id(),
        session_id: *session_shares[0].binding().session_id(),
        signing_shares: [first_share, second_share],
    })
}

fn require_exact_participant_slot(
    signing_share: &SigningShareV1,
    session_share: &SessionBlindingShareCapabilityV1,
    participants: &ScriptlessTemplateParticipantSetV1,
) -> Result<(), F7WalletCompositorError> {
    let index = usize::from(session_share.binding().participant_index());
    if index >= 2
        || signing_share.public_key().to_compressed_bytes()
            != participants.ordered_kernel_excess_points[index]
    {
        return Err(F7WalletCompositorError::Binding);
    }
    Ok(())
}

impl F7WalletBoundDomFundingV1 {
    /// Frozen canonical funding template hash.
    #[must_use]
    pub const fn template_hash(&self) -> [u8; 32] {
        *self.template.template_hash()
    }

    /// Lifetime-unique session shared by both Wallet V3 reservations.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Read-only template consumed by the concrete operational Contracts
    /// funding authorization and signing session.
    #[must_use]
    pub const fn transaction_template(&self) -> &dom_consensus::Transaction {
        self.template.transaction_template()
    }

    /// Exact trusted chain identifier bound by both Wallet V3 reservations.
    #[must_use]
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    /// Canonical signing public keys, indexed by the frozen DOM signing index.
    /// Private signing shares never cross the composition boundary.
    #[must_use]
    pub fn signing_public_keys(&self) -> [PublicKey; 2] {
        [
            self.signing_shares[0].public_key().clone(),
            self.signing_shares[1].public_key().clone(),
        ]
    }

    /// Consumes the already-issued exact Contracts funding authorization,
    /// signs through both production nonce vaults, verifies the complete DOM
    /// transaction, and atomically persists the Store-owned broadcast bytes.
    ///
    /// The caller cannot bypass the pre-funding gate: issuing `authorization`
    /// is possible only through the frozen template's
    /// `authorize_funding_v1`/`resume_funding_authorization_v1` methods after
    /// the Store has authenticated the refund, backup, frozen M.8 policy,
    /// exact claim template/adaptor binding and both ready-to-fund votes.
    /// Claim adaptor nonces remain prohibited until both real anchors validate.
    pub fn sign_finalize_and_persist_production(
        self,
        authorization: OperationalM8FundingAuthorizationV1,
        session_store: &mut ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        current_height: u64,
    ) -> Result<FundingBroadcastV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_finalize_and_persist_production_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            current_height,
            OperationalRoundInvocationV1::Fresh,
            &mut fault_controller,
        )
        .map(|(broadcast, _)| broadcast)
    }

    /// Continues the exact retained funding round after a process restart.
    ///
    /// Every accepted DSC1 prefix and both nonce-vault reservations are
    /// reauthenticated before the signer can recover or expose an artifact.
    /// There is no fallback to a fresh reservation in this entry point.
    pub fn resume_sign_finalize_and_persist_production(
        self,
        authorization: OperationalM8FundingAuthorizationV1,
        session_store: &mut ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        current_height: u64,
    ) -> Result<FundingBroadcastV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_finalize_and_persist_production_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            current_height,
            OperationalRoundInvocationV1::ResumeAfterRestart,
            &mut fault_controller,
        )
        .map(|(broadcast, _)| broadcast)
    }

    /// Same fresh M.8 funding round with the fault controller attached, but
    /// also returning the public canonical transaction identifier the route
    /// needs. The variant above predates that need and drops it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign_finalize_and_persist_production_with_tx_hash_and_fault(
        self,
        authorization: OperationalM8FundingAuthorizationV1,
        session_store: &mut ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        current_height: u64,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<(FundingBroadcastV1, [u8; 32]), F7WalletCompositorError> {
        self.sign_finalize_and_persist_production_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            current_height,
            OperationalRoundInvocationV1::Fresh,
            fault_controller,
        )
    }

    /// Same retained M.8 funding round with the fault controller attached,
    /// also returning the public canonical transaction identifier.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resume_sign_finalize_and_persist_production_with_tx_hash_and_fault(
        self,
        authorization: OperationalM8FundingAuthorizationV1,
        session_store: &mut ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        current_height: u64,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<(FundingBroadcastV1, [u8; 32]), F7WalletCompositorError> {
        self.sign_finalize_and_persist_production_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            current_height,
            OperationalRoundInvocationV1::ResumeAfterRestart,
            fault_controller,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_finalize_and_persist_production_inner(
        self,
        authorization: OperationalM8FundingAuthorizationV1,
        session_store: &mut ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        current_height: u64,
        invocation: OperationalRoundInvocationV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<(FundingBroadcastV1, [u8; 32]), F7WalletCompositorError> {
        let F7WalletBoundDomFundingV1 {
            template,
            chain_id,
            session_id,
            signing_shares,
        } = self;
        if context.session_id != session_id || context.trusted_chain_id.as_bytes() != &chain_id {
            return Err(F7WalletCompositorError::Binding);
        }
        let output = complete_production_operational_round_with_fault_v1(
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            PurposeV1::Funding,
            template.transaction_template(),
            None,
            signing_shares,
            None,
            invocation,
            fault_controller,
        )?;
        let OperationalRoundCompletionV1::Material(output) = output else {
            return Err(F7WalletCompositorError::ContractsSession);
        };
        let signature = finalize_operational_plain_signature_v1(
            context,
            PurposeV1::Funding,
            &template,
            output,
        )?;
        let verified =
            template.finalize_funding_m8(authorization, signature, &chain_id, current_height)?;
        let transaction_hash = *verified.tx_hash();
        let broadcast = verified
            .persist_with_m8_sink_v1(session_store)
            .map_err(F7WalletCompositorError::from)?;
        Ok((broadcast, transaction_hash))
    }

    /// Consumes the Store-owned prepared gate to issue the one exact funding
    /// authorization for this Wallet-bound template. Private refund/backup
    /// bindings are loaded and authenticated by the Store, never supplied by
    /// this compositor or a runner caller.
    pub(crate) fn issue_prepared_production_m8_funding(
        &self,
        prepared: PreparedOperationalM8FundingGateV1,
        bp_statement: &BpStatementV1,
        session_store: &mut ContractsSessionStoreV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, F7WalletCompositorError> {
        session_store
            .issue_prepared_operational_m8_funding_authorization(
                prepared,
                &self.template,
                bp_statement,
            )
            .map_err(Into::into)
    }

    /// Reimports only the already-issued authorization behind the same opaque
    /// prepared Store gate after restart.
    pub(crate) fn resume_prepared_production_m8_funding(
        &self,
        prepared: PreparedOperationalM8FundingGateV1,
        bp_statement: &BpStatementV1,
        session_store: &mut ContractsSessionStoreV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, F7WalletCompositorError> {
        session_store
            .resume_prepared_operational_m8_funding_authorization(
                prepared,
                &self.template,
                bp_statement,
            )
            .map_err(Into::into)
    }
}

impl F7WalletBoundDomRefundV1 {
    /// Frozen canonical refund template hash.
    #[must_use]
    pub const fn template_hash(&self) -> [u8; 32] {
        *self.template.template_hash()
    }

    /// Lifetime-unique session shared by both Wallet V3 reservations.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Read-only exact refund template for the concrete retained signer.
    #[must_use]
    pub const fn transaction_template(&self) -> &dom_consensus::Transaction {
        self.template.transaction_template()
    }

    /// Canonical signing public keys, indexed by frozen DOM signing index.
    #[must_use]
    pub fn signing_public_keys(&self) -> [PublicKey; 2] {
        [
            self.signing_shares[0].public_key().clone(),
            self.signing_shares[1].public_key().clone(),
        ]
    }

    /// Consumes both Wallet V3 signing shares through two concrete production
    /// Contracts nonce vaults and the retained global DSC1 Store.
    ///
    /// This path is intentionally available before funding because the
    /// bilateral recovery transaction must be fully signed and durable before
    /// funding can be authorized. It cannot produce a Claim adaptor partial.
    pub fn sign_and_finalize_production(
        self,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
    ) -> Result<F7VerifiedDomRefundArtifactV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_and_finalize_production_inner(
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            OperationalRoundInvocationV1::Fresh,
            &mut fault_controller,
        )
    }

    /// Executes fresh Refund signing with only public durable-checkpoint
    /// callbacks crossing the fault boundary.
    pub(crate) fn sign_and_finalize_production_with_fault(
        self,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7VerifiedDomRefundArtifactV1, F7WalletCompositorError> {
        self.sign_and_finalize_production_inner(
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            OperationalRoundInvocationV1::Fresh,
            fault_controller,
        )
    }

    /// Continues the exact retained refund round after a process restart.
    ///
    /// The accepted journal prefix selects only the matching typed vault
    /// continuation. A zero-message restart can reopen a previously claimed
    /// reservation, but can never mint a replacement nonce.
    pub fn resume_sign_and_finalize_production(
        self,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
    ) -> Result<F7VerifiedDomRefundArtifactV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_and_finalize_production_inner(
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            OperationalRoundInvocationV1::ResumeAfterRestart,
            &mut fault_controller,
        )
    }

    fn sign_and_finalize_production_inner(
        self,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        invocation: OperationalRoundInvocationV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7VerifiedDomRefundArtifactV1, F7WalletCompositorError> {
        let F7WalletBoundDomRefundV1 {
            template,
            chain_id,
            session_id,
            signing_shares,
        } = self;
        if context.session_id != session_id || context.trusted_chain_id.as_bytes() != &chain_id {
            return Err(F7WalletCompositorError::Binding);
        }
        let output = complete_production_operational_round_with_fault_v1(
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            PurposeV1::Refund,
            template.transaction_template(),
            None,
            signing_shares,
            None,
            invocation,
            fault_controller,
        )?;
        let OperationalRoundCompletionV1::Material(output) = output else {
            return Err(F7WalletCompositorError::ContractsSession);
        };
        let signature =
            finalize_operational_plain_signature_v1(context, PurposeV1::Refund, &template, output)?;
        let verified = template.finalize_refund(signature, &chain_id)?;
        if verified.role() != ContractTxRoleV1::Refund {
            return Err(F7WalletCompositorError::Dom);
        }
        Ok(F7VerifiedDomRefundArtifactV1 {
            verified,
            session_id,
        })
    }

    /// Evidence-only helper that installs an externally produced two-party
    /// signature and reruns the complete real DOM verifier.
    ///
    /// Production F7 composition must use
    /// [`Self::sign_and_finalize_production`], which is the only build-visible
    /// path outside tests/evidence builds and therefore cannot bypass the two
    /// production nonce vaults or the retained DSC1 journal.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn finalize(
        self,
        final_signature: SchnorrSignature,
    ) -> Result<F7VerifiedDomRefundArtifactV1, F7WalletCompositorError> {
        let verified = self
            .template
            .finalize_refund(final_signature, &self.chain_id)?;
        if verified.role() != ContractTxRoleV1::Refund {
            return Err(F7WalletCompositorError::Dom);
        }
        Ok(F7VerifiedDomRefundArtifactV1 {
            verified,
            session_id: self.session_id,
        })
    }
}

impl F7VerifiedDomRefundArtifactV1 {
    /// Canonical DOM refund transaction identifier.
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        *self.verified.tx_hash()
    }

    /// Lifetime-unique DOM session owning this refund.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Exact shared output spent by this refund.
    #[must_use]
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        *self.verified.shared_output_commitment()
    }

    /// Exact canonical bytes accepted by the DOM verifier.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.verified.canonical_bytes()
    }
}

impl F7WalletBoundDomClaimV1 {
    /// Frozen signature-independent template hash used by the retained signer.
    #[must_use]
    pub const fn template_hash(&self) -> [u8; 32] {
        *self.template.template_hash()
    }

    /// Lifetime-unique session bound by both official wallets.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Read-only template for the concrete Contracts signing-session store.
    #[must_use]
    pub const fn transaction_template(&self) -> &dom_consensus::Transaction {
        self.template.transaction_template()
    }

    /// Canonical signing public keys, indexed by frozen DOM signing index.
    #[must_use]
    pub fn signing_public_keys(&self) -> [PublicKey; 2] {
        [
            self.signing_shares[0].public_key().clone(),
            self.signing_shares[1].public_key().clone(),
        ]
    }

    /// Consumes both official Wallet V3 claim shares only after the retained
    /// Contracts Store has durably consumed the unique real-anchor authority.
    ///
    /// `authorization` cannot be constructed or cloned by this crate. Its
    /// immutable Store record binds the real DOM and Bitcoin funding anchors,
    /// frozen M.8 policy, this exact template, predecessor transcript and
    /// adaptor point. The specialized Store signing and transport entrypoints
    /// reauthenticate that record before every nonce-bearing transition.
    pub fn sign_pre_signature_after_real_anchors(
        self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_pre_signature_after_real_anchors_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            OperationalRoundInvocationV1::Fresh,
            &mut fault_controller,
        )
    }

    /// Executes the fresh post-anchor Claim round with an opaque public
    /// checkpoint controller and the consumed Store authorization.
    pub(crate) fn sign_pre_signature_after_real_anchors_with_fault(
        self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        self.sign_pre_signature_after_real_anchors_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            OperationalRoundInvocationV1::Fresh,
            fault_controller,
        )
    }

    /// Continues the exact post-anchor Claim round after a process restart.
    ///
    /// Prefixes one through five reopen only their Store-authenticated,
    /// stage-typed vault state. A complete six-message round bypasses all
    /// nonce-vault access and reopens the immutable Store-owned aggregate.
    pub fn resume_pre_signature_after_real_anchors(
        self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        let mut fault_controller = NoopF7DomDsc1FaultControllerV1;
        self.sign_pre_signature_after_real_anchors_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            OperationalRoundInvocationV1::ResumeAfterRestart,
            &mut fault_controller,
        )
    }

    /// Continues the post-anchor Claim round through exact retained prefixes
    /// with no fresh nonce fallback and an opaque checkpoint controller.
    pub(crate) fn resume_pre_signature_after_real_anchors_with_fault(
        self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        self.sign_pre_signature_after_real_anchors_inner(
            authorization,
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            OperationalRoundInvocationV1::ResumeAfterRestart,
            fault_controller,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_pre_signature_after_real_anchors_inner(
        self,
        authorization: &ConsumedClaimSigningAuthorizationV1,
        session_store: &ContractsSessionStoreV1,
        identity_stores: [&ContractsTransportIdentityStoreV1; 2],
        nonce_vaults: [ContractsNonceVaultV1; 2],
        context: &F7OperationalSigningContextV1,
        invocation: OperationalRoundInvocationV1,
        fault_controller: &mut dyn F7DomDsc1FaultControllerV1,
    ) -> Result<F7WalletPreSignedDomClaimV1, F7WalletCompositorError> {
        let F7WalletBoundDomClaimV1 {
            template,
            chain_id,
            session_id,
            signing_shares,
        } = self;
        if context.session_id != session_id
            || context.trusted_chain_id.as_bytes() != &chain_id
            || authorization.session_id() != &session_id
            || authorization.claim_template_hash() != template.template_hash()
        {
            return Err(F7WalletCompositorError::Binding);
        }
        let adaptor_point = authorization.adaptor_point().clone();
        let completion = complete_production_operational_round_with_fault_v1(
            session_store,
            identity_stores,
            nonce_vaults,
            context,
            PurposeV1::ClaimAdaptor,
            template.transaction_template(),
            Some(adaptor_point.clone()),
            signing_shares,
            Some(authorization),
            invocation,
            fault_controller,
        )?;
        match completion {
            OperationalRoundCompletionV1::Material(_)
            | OperationalRoundCompletionV1::CompletePostAnchorClaim => {}
        }
        let authenticated = session_store.reconstruct_post_anchor_dom_claim_pre_signature(
            authorization,
            context.trusted_chain_id,
        )?;
        if authenticated.session_id() != &session_id
            || authenticated.claim_template_hash() != template.template_hash()
        {
            return Err(F7WalletCompositorError::ContractsSession);
        }
        let transcript_hash = *authenticated.reveal_transcript_hash();
        let pre_signature = authenticated.into_pre_signature();
        Ok(F7WalletPreSignedDomClaimV1 {
            template,
            chain_id,
            session_id,
            pre_signature,
            transcript_hash,
        })
    }
}

impl F7WalletPreSignedDomClaimV1 {
    /// Bound claim template hash authenticated by Wallet V3 and the Store.
    #[must_use]
    pub const fn template_hash(&self) -> [u8; 32] {
        *self.pre_signature.claim_template_hash()
    }

    /// Post-anchor signing-round transcript bound into the adaptor equation.
    #[must_use]
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Applies the now-public route scalar and reruns the full frozen DOM
    /// transaction verifier. No alternate transcript can be supplied here.
    pub fn finalize(
        self,
        revealed: &RevealedSecretBytes,
        current_height: u64,
    ) -> Result<F7VerifiedDomClaimArtifactV1, F7WalletCompositorError> {
        let (artifact, extraction) = self.finalize_with_extraction(revealed, current_height)?;
        drop(extraction);
        Ok(artifact)
    }

    /// Finalizes the exact DOM claim while retaining a linear extraction
    /// capability for later canonical on-chain evidence.
    ///
    /// The returned verifier contains no route scalar and exposes no raw
    /// pre-signature or transaction template. It accepts only the exact fully
    /// signed claim produced here and reruns consensus validation before the
    /// pinned adaptor extractor may reveal the now-public scalar.
    pub fn finalize_with_extraction(
        self,
        revealed: &RevealedSecretBytes,
        current_height: u64,
    ) -> Result<(F7VerifiedDomClaimArtifactV1, F7WalletDomClaimExtractionV1), F7WalletCompositorError>
    {
        let Self {
            template,
            chain_id,
            session_id,
            pre_signature,
            transcript_hash,
        } = self;
        let unsigned_transaction = template.transaction_template().clone();
        let claim_template_hash = *pre_signature.claim_template_hash();
        let secret = AdaptorSecret::from_be_bytes(revealed.expose_scalar_bytes())?;
        let verified = template.finalize_claim(
            &pre_signature,
            &secret,
            &transcript_hash,
            &chain_id,
            current_height,
        )?;
        if verified.role() != ContractTxRoleV1::Claim
            || verified.template_hash() != &claim_template_hash
            || verified.tx_hash() == &[0; 32]
            || verified.shared_output_commitment() == &[0; 33]
        {
            return Err(F7WalletCompositorError::Dom);
        }
        let finalized_tx_hash = *verified.tx_hash();
        let shared_output_commitment = *verified.shared_output_commitment();
        let artifact = F7VerifiedDomClaimArtifactV1 {
            verified,
            session_id,
        };
        let extraction = F7WalletDomClaimExtractionV1 {
            unsigned_transaction,
            chain_id,
            session_id,
            pre_signature,
            transcript_hash,
            claim_template_hash,
            shared_output_commitment,
            finalized_tx_hash,
        };
        Ok((artifact, extraction))
    }
}

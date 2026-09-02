//! Wallet-owned boundary for frozen Address, Slate, and fee-policy contracts.

#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dom_consensus::Transaction;
use dom_core::{
    address::{
        ADDRESS_KEY_TYPE_SECP256K1_COMPRESSED, ADDRESS_PAYLOAD_VERSION_V3, ADDRESS_TYPE_STANDARD,
        ADDRESS_V3_PAYLOAD_LEN, MAX_ADDRESS_LEN,
    },
    Address,
};
use dom_crypto::{recovery::RECOVERY_CAPSULE_SIZE, PublicKey};
use dom_serialization::DomDeserialize;
use dom_tx::slate::{
    Slate, SlateEnvelope, CURRENT_SLATE_ENVELOPE_VERSION, CURRENT_SLATE_VERSION,
    RECOVERY_SLATE_ENVELOPE_VERSION, RECOVERY_SLATE_VERSION, SLATE_FLOW_STANDARD_SEND,
    SLATE_PHASE_FINALIZED, SLATE_PHASE_RECEIVER_RESPONSE, SLATE_PHASE_SENDER_OFFER,
    SLATE_ROLE_RECEIVER, SLATE_ROLE_SENDER,
};
use dom_wallet_core_api::{
    CoreNetwork, FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeeEstimateTarget,
    FeePolicySnapshot, FeeValidation, TransactionShape, TransactionWeight, WalletCoreApi,
    WalletCoreError,
};
use dom_wallet_core_sync::CoreChainIdentity;
use std::{fmt, sync::Arc};
use thiserror::Error;

/// Canonical text framing for recovery-capable Slate envelope bytes.
pub const RECOVERY_SLATE_TEXT_PREFIX: &str = "DOMSLATE4.";

/// Frozen base Slate body version.
pub const BASE_SLATE_VERSION: u16 = CURRENT_SLATE_VERSION;
/// Frozen base Slate envelope version.
pub const BASE_SLATE_ENVELOPE_VERSION: u16 = CURRENT_SLATE_ENVELOPE_VERSION;
/// Frozen recovery Slate body version.
pub const WALLET_RECOVERY_SLATE_VERSION: u16 = RECOVERY_SLATE_VERSION;
/// Frozen recovery Slate envelope version.
pub const WALLET_RECOVERY_SLATE_ENVELOPE_VERSION: u16 = RECOVERY_SLATE_ENVELOPE_VERSION;

/// Explicit public-key purpose. No secret derivation is accepted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressIdentityPurpose {
    /// Interactive transaction identity.
    TransactionInteraction,
    /// Payment-proof identity.
    PaymentProof,
}

/// Wallet-owned Address v1 backed by the frozen DOM Address implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletAddress {
    inner: Address,
    purpose: AddressIdentityPurpose,
}

impl fmt::Debug for WalletAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletAddress")
            .field("hrp", &self.inner.hrp())
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

impl WalletAddress {
    /// Create an Address v1 from a public interaction or payment-proof key.
    pub fn from_public_key(
        public_key: [u8; 33],
        network: CoreNetwork,
        purpose: AddressIdentityPurpose,
    ) -> Result<Self, ProtocolAdapterError> {
        validate_public_key(public_key)?;
        let inner = Address::new_for_network(public_key, network.magic())
            .map_err(|_| ProtocolAdapterError::MalformedAddress)?;
        validate_address_shape(&inner, network)?;
        Ok(Self { inner, purpose })
    }

    /// Parse canonical lowercase Bech32m and bind it to an expected network.
    pub fn parse(
        text: &str,
        network: CoreNetwork,
        purpose: AddressIdentityPurpose,
    ) -> Result<Self, ProtocolAdapterError> {
        if text.is_empty()
            || text.len() > MAX_ADDRESS_LEN
            || !text.is_ascii()
            || text.bytes().any(|byte| byte.is_ascii_uppercase())
            || text.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ProtocolAdapterError::NonCanonicalAddress);
        }
        let inner = Address::decode(text).map_err(|_| ProtocolAdapterError::MalformedAddress)?;
        validate_address_shape(&inner, network)?;
        validate_public_key(inner.payload)?;
        if inner.encode() != text {
            return Err(ProtocolAdapterError::NonCanonicalAddress);
        }
        Ok(Self { inner, purpose })
    }

    /// Return canonical lowercase Bech32m text.
    pub fn encode(&self) -> String {
        self.inner.encode()
    }

    /// Return the exact frozen 40-byte payload.
    pub fn payload_bytes(&self) -> [u8; ADDRESS_V3_PAYLOAD_LEN] {
        self.inner.to_payload_bytes()
    }

    /// Return the public interaction/payment-proof key.
    pub fn public_key(&self) -> [u8; 33] {
        self.inner.payload
    }

    /// Return the explicit public-key purpose.
    pub fn purpose(&self) -> AddressIdentityPurpose {
        self.purpose
    }

    /// Return the bound network.
    pub fn network(&self) -> Result<CoreNetwork, ProtocolAdapterError> {
        CoreNetwork::from_magic(self.inner.network_magic)
            .map_err(|_| ProtocolAdapterError::MalformedAddress)
    }

    fn core(&self) -> Address {
        self.inner.clone()
    }
}

/// Participant role bound into the frozen signature digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlateParticipantRole {
    Sender,
    Receiver,
}

impl SlateParticipantRole {
    fn core(self) -> u8 {
        match self {
            Self::Sender => SLATE_ROLE_SENDER,
            Self::Receiver => SLATE_ROLE_RECEIVER,
        }
    }
}

/// Frozen standard-send phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlatePhase {
    SenderOffer,
    ReceiverResponse,
    Finalized,
}

impl SlatePhase {
    fn from_core(value: u8) -> Result<Self, ProtocolAdapterError> {
        match value {
            SLATE_PHASE_SENDER_OFFER => Ok(Self::SenderOffer),
            SLATE_PHASE_RECEIVER_RESPONSE => Ok(Self::ReceiverResponse),
            SLATE_PHASE_FINALIZED => Ok(Self::Finalized),
            _ => Err(ProtocolAdapterError::UnsupportedSlatePhase),
        }
    }
}

/// Exact fixed-size public recovery sidecars carried by Slate v4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySlateSidecars {
    /// Sender change sidecar, present exactly when change exists.
    pub sender_change: Option<[u8; RECOVERY_CAPSULE_SIZE]>,
    /// Recipient sidecar, present exactly when a recipient output exists.
    pub recipient: Option<[u8; RECOVERY_CAPSULE_SIZE]>,
}

/// Wallet-owned recovery-capable Slate body backed by canonical frozen bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverySlateBody {
    inner: Slate,
    canonical_bytes: Vec<u8>,
}

impl fmt::Debug for RecoverySlateBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverySlateBody")
            .field("version", &self.inner.version)
            .field("encoded_length", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

impl RecoverySlateBody {
    /// Decode exact canonical Slate v4 body bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolAdapterError> {
        let inner = Slate::from_canonical_bytes(bytes)
            .map_err(|_| ProtocolAdapterError::InvalidSlateEncoding)?;
        if inner.version != RECOVERY_SLATE_VERSION {
            return Err(ProtocolAdapterError::RecoverySlateRequired);
        }
        inner
            .validate()
            .map_err(|_| ProtocolAdapterError::InvalidRecoverySidecar)?;
        let canonical_bytes = inner
            .to_canonical_bytes()
            .map_err(|_| ProtocolAdapterError::InvalidSlateEncoding)?;
        if canonical_bytes != bytes {
            return Err(ProtocolAdapterError::NonCanonicalSlate);
        }
        Ok(Self {
            inner,
            canonical_bytes,
        })
    }

    /// Return exact canonical Slate body bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Return the transfer amount without exposing implementation-private types.
    pub fn amount_noms(&self) -> u64 {
        self.inner.amount
    }

    /// Return the fee without duplicating policy arithmetic.
    pub fn fee_noms(&self) -> u64 {
        self.inner.fee
    }

    /// Return the canonical input count for Core fee-policy queries.
    pub fn input_count(&self) -> u32 {
        u32::try_from(self.inner.sender_inputs.len()).unwrap_or(u32::MAX)
    }

    /// Report whether the sender Slate carries a change output.
    pub fn has_sender_change(&self) -> bool {
        self.inner.sender_change_output.is_some()
    }

    /// Return the two public interaction keys already committed by the sender.
    /// Manual Slate transport uses these as one-time Address v1 identities so
    /// users never have to invent Bitcoin-style destination fields.
    pub fn manual_interaction_public_keys(&self) -> ([u8; 33], [u8; 33]) {
        (
            self.inner.sender_public_excess.to_compressed_bytes(),
            self.inner.sender_public_nonce.to_compressed_bytes(),
        )
    }
}

/// Durable replay identity to be recorded atomically by Wallet state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlateReplayKey {
    pub slate_id: [u8; 32],
    pub replay_id: [u8; 32],
}

/// Durable Wallet replay boundary. Implementations must survive restart.
pub trait SlateReplayProtection {
    /// Atomically record a new key, returning false when it already exists.
    fn record_if_fresh(&mut self, key: SlateReplayKey) -> Result<bool, ProtocolAdapterError>;
}

/// Wallet lifecycle actions which do not change canonical Slate bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlateLifecycleAction {
    Cancelled,
    ResendUnmodified,
}

/// Wallet-owned canonical Slate envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalSlate {
    inner: SlateEnvelope,
    canonical_bytes: Vec<u8>,
}

impl fmt::Debug for CanonicalSlate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalSlate")
            .field("envelope_version", &self.inner.envelope_version)
            .field("body_version", &self.inner.body.version)
            .field("phase", &self.phase())
            .field("encoded_length", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

impl CanonicalSlate {
    /// Build a recovery-capable standard-send envelope from frozen public types.
    #[allow(clippy::too_many_arguments)]
    pub fn new_recoverable(
        identity: &CoreChainIdentity,
        slate_id: [u8; 32],
        replay_id: [u8; 32],
        phase: SlatePhase,
        expires_at_height: u64,
        sender: &WalletAddress,
        receiver: &WalletAddress,
        body: RecoverySlateBody,
    ) -> Result<Self, ProtocolAdapterError> {
        validate_address_for_identity(sender, identity)?;
        validate_address_for_identity(receiver, identity)?;
        let inner = SlateEnvelope::new(
            identity.network_magic,
            identity.chain_id,
            slate_id,
            replay_id,
            phase_to_core(phase),
            expires_at_height,
            sender.core(),
            receiver.core(),
            body.inner,
        )
        .map_err(|_| ProtocolAdapterError::InvalidSlate)?;
        Self::from_validated(inner, identity, expires_at_height)
    }

    /// Decode exact canonical bytes and require the recovery 4/4 pair.
    pub fn from_recovery_bytes(
        bytes: &[u8],
        identity: &CoreChainIdentity,
        current_height: u64,
    ) -> Result<Self, ProtocolAdapterError> {
        let inner = SlateEnvelope::from_canonical_bytes(bytes)
            .map_err(|_| ProtocolAdapterError::InvalidSlateEncoding)?;
        let value = Self::from_validated(inner, identity, current_height)?;
        if value.inner.envelope_version != RECOVERY_SLATE_ENVELOPE_VERSION
            || value.inner.body.version != RECOVERY_SLATE_VERSION
        {
            return Err(ProtocolAdapterError::RecoverySlateRequired);
        }
        if value.canonical_bytes != bytes {
            return Err(ProtocolAdapterError::NonCanonicalSlate);
        }
        Ok(value)
    }

    /// Decode canonical Base64URL text without changing signed semantics.
    pub fn from_text(
        text: &str,
        identity: &CoreChainIdentity,
        current_height: u64,
    ) -> Result<Self, ProtocolAdapterError> {
        let encoded = text
            .strip_prefix(RECOVERY_SLATE_TEXT_PREFIX)
            .ok_or(ProtocolAdapterError::InvalidSlateText)?;
        if encoded.is_empty() || encoded.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(ProtocolAdapterError::InvalidSlateText);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ProtocolAdapterError::InvalidSlateText)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(ProtocolAdapterError::InvalidSlateText);
        }
        Self::from_recovery_bytes(&bytes, identity, current_height)
    }

    /// Exact canonical bytes suitable for storage, text, and QR framing.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Canonical Base64URL text transport.
    pub fn to_text(&self) -> String {
        format!(
            "{RECOVERY_SLATE_TEXT_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(&self.canonical_bytes)
        )
    }

    /// Return the exact frozen signature-domain digest for a role.
    pub fn signature_digest(
        &self,
        role: SlateParticipantRole,
    ) -> Result<[u8; 32], ProtocolAdapterError> {
        self.inner
            .signature_digest(role.core())
            .map_err(|_| ProtocolAdapterError::InvalidSlate)
    }

    /// Validate an externally authenticated frozen signature-domain digest.
    pub fn validate_signature_digest(
        &self,
        role: SlateParticipantRole,
        expected: [u8; 32],
    ) -> Result<(), ProtocolAdapterError> {
        if self.signature_digest(role)? != expected {
            return Err(ProtocolAdapterError::SlateDomainMismatch);
        }
        Ok(())
    }

    /// Atomically register replay identity through durable Wallet storage.
    pub fn record_replay(
        &self,
        protection: &mut impl SlateReplayProtection,
    ) -> Result<(), ProtocolAdapterError> {
        if !protection.record_if_fresh(self.replay_key())? {
            return Err(ProtocolAdapterError::DuplicateReplay);
        }
        Ok(())
    }

    /// Ordered, exact recovery sidecars for Slice F.
    pub fn recovery_sidecars(&self) -> Result<RecoverySlateSidecars, ProtocolAdapterError> {
        if self.inner.envelope_version != RECOVERY_SLATE_ENVELOPE_VERSION
            || self.inner.body.version != RECOVERY_SLATE_VERSION
        {
            return Err(ProtocolAdapterError::RecoverySlateRequired);
        }
        self.inner
            .body
            .validate()
            .map_err(|_| ProtocolAdapterError::InvalidRecoverySidecar)?;
        Ok(RecoverySlateSidecars {
            sender_change: copy_sidecar(&self.inner.body.sender_change_recovery_capsule)?,
            recipient: copy_sidecar(&self.inner.body.recipient_recovery_capsule)?,
        })
    }

    /// Inclusive height-based expiration check.
    pub fn validate_height(&self, current_height: u64) -> Result<(), ProtocolAdapterError> {
        if self.inner.is_expired_at(current_height) {
            Err(ProtocolAdapterError::SlateExpired)
        } else {
            Ok(())
        }
    }

    /// Return immutable resend bytes. No rebuilding or re-signing occurs.
    pub fn resend(&self) -> (&[u8], SlateLifecycleAction) {
        (
            &self.canonical_bytes,
            SlateLifecycleAction::ResendUnmodified,
        )
    }

    /// Record a local cancellation decision without inventing a wire flow.
    pub fn cancel(&self) -> SlateLifecycleAction {
        SlateLifecycleAction::Cancelled
    }

    pub fn replay_key(&self) -> SlateReplayKey {
        SlateReplayKey {
            slate_id: self.inner.slate_id,
            replay_id: self.inner.replay_id,
        }
    }

    pub fn phase(&self) -> Result<SlatePhase, ProtocolAdapterError> {
        SlatePhase::from_core(self.inner.phase)
    }

    pub fn fee_noms(&self) -> u64 {
        self.inner.body.fee
    }

    pub fn expires_at_height(&self) -> u64 {
        self.inner.expires_at_height
    }

    /// Return a canonical recovery body for the frozen recoverable builder.
    pub fn recovery_body(&self) -> Result<RecoverySlateBody, ProtocolAdapterError> {
        RecoverySlateBody::from_canonical_bytes(
            &self
                .inner
                .body
                .to_canonical_bytes()
                .map_err(|_| ProtocolAdapterError::InvalidSlateEncoding)?,
        )
    }

    /// Replace only the canonical body and phase while preserving all signed identity fields.
    pub fn with_recovery_body(
        &self,
        phase: SlatePhase,
        body: RecoverySlateBody,
        identity: &CoreChainIdentity,
        current_height: u64,
    ) -> Result<Self, ProtocolAdapterError> {
        Self::new_recoverable(
            identity,
            self.inner.slate_id,
            self.inner.replay_id,
            phase,
            self.inner.expires_at_height,
            &WalletAddress {
                inner: self.inner.sender_address.clone(),
                purpose: AddressIdentityPurpose::TransactionInteraction,
            },
            &WalletAddress {
                inner: self.inner.receiver_address.clone(),
                purpose: AddressIdentityPurpose::TransactionInteraction,
            },
            body,
        )
        .and_then(|value| {
            value.validate_height(current_height)?;
            Ok(value)
        })
    }

    fn from_validated(
        inner: SlateEnvelope,
        identity: &CoreChainIdentity,
        current_height: u64,
    ) -> Result<Self, ProtocolAdapterError> {
        inner
            .validate()
            .map_err(|_| ProtocolAdapterError::InvalidSlate)?;
        if inner.network_magic != identity.network_magic {
            return Err(ProtocolAdapterError::SlateNetworkMismatch);
        }
        if inner.chain_id != identity.chain_id || inner.body.chain_id != identity.chain_id {
            return Err(ProtocolAdapterError::SlateChainMismatch);
        }
        if inner.flow != SLATE_FLOW_STANDARD_SEND {
            return Err(ProtocolAdapterError::UnsupportedSlateFlow);
        }
        if inner.is_expired_at(current_height) {
            return Err(ProtocolAdapterError::SlateExpired);
        }
        let canonical_bytes = inner
            .to_canonical_bytes()
            .map_err(|_| ProtocolAdapterError::InvalidSlateEncoding)?;
        Ok(Self {
            inner,
            canonical_bytes,
        })
    }
}

/// Wallet-owned transaction shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletTransactionShape {
    pub input_count: u32,
    pub output_count: u32,
    pub kernel_count: u32,
}

impl WalletTransactionShape {
    fn core(self) -> TransactionShape {
        TransactionShape {
            input_count: self.input_count,
            output_count: self.output_count,
            kernel_count: self.kernel_count,
        }
    }
}

/// Wallet-owned frozen Fee Policy v1 snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletFeePolicy {
    pub policy_version: u16,
    pub network: CoreNetwork,
    pub chain_id: [u8; 32],
    pub minimum_relay_fee_rate: u64,
    pub minimum_mempool_fee_rate: u64,
    pub recommended_fee_rate: u64,
    pub dust_threshold_noms: u64,
    pub maximum_transaction_weight: u64,
    pub validity_horizon: Option<u64>,
}

/// Wallet-owned weight projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletTransactionWeight {
    pub input_weight: u64,
    pub output_weight: u64,
    pub kernel_weight: u64,
    pub total_weight: u64,
}

/// Wallet-owned fee calculation projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletFeeEstimate {
    pub shape: WalletTransactionShape,
    pub weight: WalletTransactionWeight,
    pub minimum_fee_noms: u64,
    pub recommended_fee_noms: u64,
    pub selected_fee_noms: u64,
    pub selected_fee_rate: u64,
    pub minimum_fee_rate: u64,
    pub recommended_fee_rate: u64,
    pub policy_version: u16,
    pub network: CoreNetwork,
    pub validity_horizon: Option<u64>,
    pub dust_threshold_noms: u64,
}

/// Wallet-owned concrete fee validation projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletFeeValidation {
    pub accepted_by_policy: bool,
    pub actual_fee_noms: u64,
    pub minimum_fee_noms: u64,
    pub shortfall_noms: u64,
    pub actual_fee_rate: u64,
    pub estimate: WalletFeeEstimate,
}

/// Wallet-facing Fee Policy v1 service backed only by frozen Core methods.
pub struct CoreFeePolicyService {
    api: Arc<dyn WalletCoreApi + Send + Sync>,
    identity: CoreChainIdentity,
}

impl fmt::Debug for CoreFeePolicyService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreFeePolicyService")
            .field("network", &self.identity.network)
            .finish_non_exhaustive()
    }
}

impl CoreFeePolicyService {
    pub fn connect(
        api: Arc<dyn WalletCoreApi + Send + Sync>,
        identity: CoreChainIdentity,
    ) -> Result<Self, ProtocolAdapterError> {
        let service = Self { api, identity };
        service.require_same_chain()?;
        service.policy()?;
        Ok(service)
    }

    pub fn policy(&self) -> Result<WalletFeePolicy, ProtocolAdapterError> {
        self.require_same_chain()?;
        let snapshot = self.api.fee_policy().map_err(map_core_error)?;
        self.map_policy(snapshot)
    }

    pub fn transaction_weight(
        &self,
        shape: WalletTransactionShape,
    ) -> Result<WalletTransactionWeight, ProtocolAdapterError> {
        self.require_same_chain()?;
        let weight = self
            .api
            .transaction_weight(shape.core())
            .map_err(map_core_error)?;
        map_weight(weight)
    }

    pub fn minimum_fee(
        &self,
        shape: WalletTransactionShape,
    ) -> Result<WalletFeeEstimate, ProtocolAdapterError> {
        self.require_same_chain()?;
        let breakdown = self.api.minimum_fee(shape.core()).map_err(map_core_error)?;
        self.map_breakdown(
            breakdown,
            breakdown.minimum_fee_noms,
            breakdown.minimum_fee_rate.noms_per_weight_unit,
        )
    }

    pub fn estimate_fee(
        &self,
        shape: WalletTransactionShape,
    ) -> Result<WalletFeeEstimate, ProtocolAdapterError> {
        self.require_same_chain()?;
        let estimate = self
            .api
            .estimate_fee(FeeEstimateRequest {
                shape: shape.core(),
                target: FeeEstimateTarget::Minimum,
            })
            .map_err(map_core_error)?;
        self.map_estimate(estimate)
    }

    pub fn recommended_fee(
        &self,
        shape: WalletTransactionShape,
    ) -> Result<WalletFeeEstimate, ProtocolAdapterError> {
        self.require_same_chain()?;
        let estimate = self
            .api
            .recommended_fee(FeeEstimateRequest {
                shape: shape.core(),
                target: FeeEstimateTarget::Recommended,
            })
            .map_err(map_core_error)?;
        self.map_estimate(estimate)
    }

    pub fn validate_fee(
        &self,
        canonical_transaction_bytes: &[u8],
    ) -> Result<WalletFeeValidation, ProtocolAdapterError> {
        self.require_same_chain()?;
        let transaction = Transaction::from_bytes(canonical_transaction_bytes)
            .map_err(|_| ProtocolAdapterError::InvalidTransactionEncoding)?;
        let validation = self
            .api
            .validate_fee(&transaction)
            .map_err(map_core_error)?;
        self.map_validation(validation)
    }

    fn require_same_chain(&self) -> Result<(), ProtocolAdapterError> {
        let current = self.api.chain_identity().map_err(map_core_error)?;
        if current.network != self.identity.network
            || current.network_magic != self.identity.network_magic
            || current.chain_id != self.identity.chain_id
            || current.genesis_hash != self.identity.genesis_hash
            || current.protocol_version != self.identity.protocol_version
            || current.range_proof_serialization_version
                != self.identity.range_proof_serialization_version
            || current.coinbase_maturity != self.identity.coinbase_maturity
        {
            return Err(ProtocolAdapterError::ChainIdentityMismatch);
        }
        Ok(())
    }

    fn map_policy(
        &self,
        value: FeePolicySnapshot,
    ) -> Result<WalletFeePolicy, ProtocolAdapterError> {
        if value.policy_version != 1 {
            return Err(ProtocolAdapterError::UnsupportedFeePolicyVersion);
        }
        if value.network != self.identity.network {
            return Err(ProtocolAdapterError::FeePolicyNetworkMismatch);
        }
        if value.min_relay_fee_rate == 0
            || value.min_mempool_fee_rate < value.min_relay_fee_rate
            || value.recommended_fee_rate < value.min_mempool_fee_rate
            || value.max_tx_weight == 0
        {
            return Err(ProtocolAdapterError::InconsistentFeePolicy);
        }
        Ok(WalletFeePolicy {
            policy_version: value.policy_version,
            network: value.network,
            chain_id: self.identity.chain_id,
            minimum_relay_fee_rate: value.min_relay_fee_rate,
            minimum_mempool_fee_rate: value.min_mempool_fee_rate,
            recommended_fee_rate: value.recommended_fee_rate,
            dust_threshold_noms: value.dust_threshold_noms,
            maximum_transaction_weight: value.max_tx_weight,
            validity_horizon: value.validity_horizon,
        })
    }

    fn map_estimate(&self, value: FeeEstimate) -> Result<WalletFeeEstimate, ProtocolAdapterError> {
        self.map_breakdown(
            value.breakdown,
            value.selected_fee_noms,
            value.selected_fee_rate.noms_per_weight_unit,
        )
    }

    fn map_breakdown(
        &self,
        value: FeeBreakdown,
        selected_fee_noms: u64,
        selected_fee_rate: u64,
    ) -> Result<WalletFeeEstimate, ProtocolAdapterError> {
        let policy = self.policy()?;
        if value.policy_version != policy.policy_version
            || value.network != policy.network
            || value.minimum_fee_rate.noms_per_weight_unit != policy.minimum_relay_fee_rate
            || value.recommended_fee_rate.noms_per_weight_unit != policy.recommended_fee_rate
            || value.dust_threshold_noms != policy.dust_threshold_noms
            || value.validity_horizon != policy.validity_horizon
        {
            return Err(ProtocolAdapterError::InconsistentFeePolicy);
        }
        let weight = map_weight(TransactionWeight {
            input_weight: value.input_weight,
            output_weight: value.output_weight,
            kernel_weight: value.kernel_weight,
            total_weight: value.total_weight,
        })?;
        Ok(WalletFeeEstimate {
            shape: WalletTransactionShape {
                input_count: value.input_count,
                output_count: value.output_count,
                kernel_count: value.kernel_count,
            },
            weight,
            minimum_fee_noms: value.minimum_fee_noms,
            recommended_fee_noms: value.recommended_fee_noms,
            selected_fee_noms,
            selected_fee_rate,
            minimum_fee_rate: value.minimum_fee_rate.noms_per_weight_unit,
            recommended_fee_rate: value.recommended_fee_rate.noms_per_weight_unit,
            policy_version: value.policy_version,
            network: value.network,
            validity_horizon: value.validity_horizon,
            dust_threshold_noms: value.dust_threshold_noms,
        })
    }

    fn map_validation(
        &self,
        value: FeeValidation,
    ) -> Result<WalletFeeValidation, ProtocolAdapterError> {
        let estimate = self.map_breakdown(
            value.breakdown,
            value.minimum_fee_noms,
            value.breakdown.minimum_fee_rate.noms_per_weight_unit,
        )?;
        if value.minimum_fee_noms != estimate.minimum_fee_noms
            || (value.accepted_by_policy && value.shortfall_noms != 0)
            || (!value.accepted_by_policy && value.shortfall_noms == 0)
        {
            return Err(ProtocolAdapterError::InconsistentFeePolicy);
        }
        Ok(WalletFeeValidation {
            accepted_by_policy: value.accepted_by_policy,
            actual_fee_noms: value.actual_fee_noms,
            minimum_fee_noms: value.minimum_fee_noms,
            shortfall_noms: value.shortfall_noms,
            actual_fee_rate: value.actual_fee_rate.noms_per_weight_unit,
            estimate,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtocolAdapterError {
    #[error("address is not canonical lowercase ASCII")]
    NonCanonicalAddress,
    #[error("address is malformed")]
    MalformedAddress,
    #[error("address belongs to another network")]
    AddressNetworkMismatch,
    #[error("slate encoding is malformed")]
    InvalidSlateEncoding,
    #[error("slate encoding is not canonical")]
    NonCanonicalSlate,
    #[error("slate text transport is malformed")]
    InvalidSlateText,
    #[error("slate is invalid")]
    InvalidSlate,
    #[error("recovery-capable Slate version 4 is required")]
    RecoverySlateRequired,
    #[error("slate belongs to another network")]
    SlateNetworkMismatch,
    #[error("slate belongs to another chain")]
    SlateChainMismatch,
    #[error("slate flow is unsupported")]
    UnsupportedSlateFlow,
    #[error("slate phase is unsupported")]
    UnsupportedSlatePhase,
    #[error("slate expired")]
    SlateExpired,
    #[error("slate replay was already recorded")]
    DuplicateReplay,
    #[error("slate signature domain does not match")]
    SlateDomainMismatch,
    #[error("recovery sidecar is malformed or missing")]
    InvalidRecoverySidecar,
    #[error("Core chain identity changed")]
    ChainIdentityMismatch,
    #[error("Fee Policy version is unsupported")]
    UnsupportedFeePolicyVersion,
    #[error("Fee Policy network does not match")]
    FeePolicyNetworkMismatch,
    #[error("Fee Policy response is inconsistent")]
    InconsistentFeePolicy,
    #[error("canonical transaction encoding is invalid")]
    InvalidTransactionEncoding,
    #[error("Core is unavailable ({code})")]
    CoreUnavailable { code: &'static str },
}

fn validate_public_key(value: [u8; 33]) -> Result<(), ProtocolAdapterError> {
    PublicKey::from_compressed_bytes(&value)
        .map(|_| ())
        .map_err(|_| ProtocolAdapterError::MalformedAddress)
}

fn validate_address_shape(
    value: &Address,
    network: CoreNetwork,
) -> Result<(), ProtocolAdapterError> {
    value
        .validate_for_network(network.magic())
        .map_err(|_| ProtocolAdapterError::AddressNetworkMismatch)?;
    if value.version != ADDRESS_PAYLOAD_VERSION_V3
        || value.address_type != ADDRESS_TYPE_STANDARD
        || value.key_type != ADDRESS_KEY_TYPE_SECP256K1_COMPRESSED
        || value.to_payload_bytes().len() != ADDRESS_V3_PAYLOAD_LEN
    {
        return Err(ProtocolAdapterError::MalformedAddress);
    }
    Ok(())
}

fn validate_address_for_identity(
    address: &WalletAddress,
    identity: &CoreChainIdentity,
) -> Result<(), ProtocolAdapterError> {
    if address.network()? != identity.network {
        return Err(ProtocolAdapterError::AddressNetworkMismatch);
    }
    Ok(())
}

fn phase_to_core(value: SlatePhase) -> u8 {
    match value {
        SlatePhase::SenderOffer => SLATE_PHASE_SENDER_OFFER,
        SlatePhase::ReceiverResponse => SLATE_PHASE_RECEIVER_RESPONSE,
        SlatePhase::Finalized => SLATE_PHASE_FINALIZED,
    }
}

fn copy_sidecar(value: &[u8]) -> Result<Option<[u8; RECOVERY_CAPSULE_SIZE]>, ProtocolAdapterError> {
    if value.is_empty() {
        return Ok(None);
    }
    dom_crypto::recovery::RecoveryCapsule::from_bytes(value)
        .map_err(|_| ProtocolAdapterError::InvalidRecoverySidecar)?;
    value
        .try_into()
        .map(Some)
        .map_err(|_| ProtocolAdapterError::InvalidRecoverySidecar)
}

fn map_weight(value: TransactionWeight) -> Result<WalletTransactionWeight, ProtocolAdapterError> {
    let sum = value
        .input_weight
        .checked_add(value.output_weight)
        .and_then(|total| total.checked_add(value.kernel_weight))
        .ok_or(ProtocolAdapterError::InconsistentFeePolicy)?;
    if sum != value.total_weight {
        return Err(ProtocolAdapterError::InconsistentFeePolicy);
    }
    Ok(WalletTransactionWeight {
        input_weight: value.input_weight,
        output_weight: value.output_weight,
        kernel_weight: value.kernel_weight,
        total_weight: value.total_weight,
    })
}

fn map_core_error(value: WalletCoreError) -> ProtocolAdapterError {
    let code = match value {
        WalletCoreError::MalformedCursor(_) => "CORE_MALFORMED_CURSOR",
        WalletCoreError::CursorChainMismatch(_) => "CORE_CHAIN_MISMATCH",
        WalletCoreError::CursorReorg(_) => "CORE_CURSOR_REORG",
        WalletCoreError::InvalidScanRequest(_) => "CORE_INVALID_SCAN_REQUEST",
        WalletCoreError::CanonicalGap(_) => "CORE_CANONICAL_GAP",
        WalletCoreError::NodeNotReady(_) => "CORE_NODE_NOT_READY",
        WalletCoreError::SubmissionRejected(_) => "CORE_SUBMISSION_REJECTED",
        WalletCoreError::TemporaryFailure(_) => "CORE_TEMPORARY_FAILURE",
        WalletCoreError::InternalFailure(_) => "CORE_INTERNAL_FAILURE",
    };
    ProtocolAdapterError::CoreUnavailable { code }
}

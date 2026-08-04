//! Storage-independent contract for a durable, rollback-resistant Nonce Vault.

use core::fmt;
use dom_crypto::blake2b_256_tagged;
use std::error::Error;

macro_rules! opaque_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            #[doc = "Constructs the identifier, rejecting an empty representation."]
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, NonceVaultError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(NonceVaultError::InvalidIdentifier);
                }
                Ok(Self(bytes))
            }

            #[doc = "Returns the local opaque representation."]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

opaque_identifier!(
    VaultKeyId,
    "Opaque local identifier for a signing key budget."
);
opaque_identifier!(
    ReservationNonceId,
    "Stable identifier for one charged nonce reservation."
);
opaque_identifier!(
    ParticipantId,
    "Stable protocol participant identity bound by an exposure permit."
);
opaque_identifier!(
    TemplateHash,
    "Canonical contract-template hash bound by an exposure permit."
);
opaque_identifier!(
    SessionId,
    "Opaque local identifier for one adaptor session."
);
opaque_identifier!(
    CounterpartyBucket,
    "Opaque local bucket used for the secondary counterparty budget."
);
opaque_identifier!(
    IdempotencyKey,
    "Caller-generated key that makes one logical vault operation idempotent."
);

/// Storage-facing projection of the closed `PurposeV1` registry.
///
/// This enum deliberately has no byte codec. The canonical wire discriminants
/// belong to G1a `PurposeV1`; integration must use an exhaustive conversion.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PurposeV1 {
    /// Refund transaction construction.
    Refund = 0x01,
    /// Adaptor claim transaction construction.
    ClaimAdaptor = 0x02,
    /// Funding transaction construction.
    Funding = 0x03,
    /// Sponsor codec value, rejected by strict V1 execution policy.
    Sponsor = 0x04,
}

impl PurposeV1 {
    /// Returns whether strict V1 policy currently permits this purpose.
    pub const fn is_strict_v1_authorized(self) -> bool {
        !matches!(self, Self::Sponsor)
    }

    /// Returns the ratified V1 discriminant.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for PurposeV1 {
    type Error = NonceVaultError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Refund),
            0x02 => Ok(Self::ClaimAdaptor),
            0x03 => Ok(Self::Funding),
            0x04 => Ok(Self::Sponsor),
            _ => Err(NonceVaultError::UnsupportedPurpose),
        }
    }
}

/// Backward-compatible semantic name for the canonical V1 purpose registry.
pub type Purpose = PurposeV1;

/// Scope in which a configured budget prevented a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetScope {
    /// The per-key lifetime budget.
    GlobalKey,
    /// The per-key and per-counterparty budget.
    Counterparty,
    /// The configured concurrent-session budget.
    Concurrent,
    /// The configured rolling-window budget.
    Window,
}

/// Monotonic state of a reserved nonce slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    /// Budget and nonce slots are durably reserved.
    Reserved,
    /// Exact public bytes are durably committed and cannot change.
    CommitmentAuthorized,
    /// Exact nonce reveal is durably authorized by the witness.
    RevealAuthorized,
    /// Secret nonce material is destroyed and the partial is authorized.
    ConsumedPartialAuthorized,
    /// No public material existed when the reservation was aborted.
    AbortedBeforePublicMaterial,
    /// Public material may have existed, so abort burned the nonce.
    ConsumedOnAbort,
    /// Ambiguous restore conservatively burned the nonce.
    Burned,
}

/// Capability state after normal startup or restoration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreState {
    /// Local journal and remote anchor evidence agree.
    Operational,
    /// Adaptor operations are fail-closed pending witness reconciliation.
    RestoreQuarantined,
}

/// Why a reservation became consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeReason {
    /// The adaptor operation completed successfully.
    Completed,
    /// Material may have been exposed and the operation failed afterward.
    ExposureUncertain,
    /// Recovery conservatively consumed the slot after a crash boundary.
    CrashRecovery,
}

/// Closed NAR-002 public-exposure registry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureKindV1 {
    /// Exact 35-byte `SigNonceCommitV1`.
    NonceCommitment = 0x01,
    /// Exact 69-byte `SigNonceRevealV1`.
    NonceReveal = 0x02,
    /// Exact 67-byte `PartialSignatureV1`.
    PartialSignature = 0x03,
}

impl ExposureKindV1 {
    /// Returns the exact canonical byte length.
    pub const fn canonical_length(self) -> usize {
        match self {
            Self::NonceCommitment => 35,
            Self::NonceReveal => 69,
            Self::PartialSignature => 67,
        }
    }
}

impl TryFrom<u8> for ExposureKindV1 {
    type Error = NonceVaultError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NonceCommitment),
            2 => Ok(Self::NonceReveal),
            3 => Ok(Self::PartialSignature),
            _ => Err(NonceVaultError::UnsupportedExposureKind),
        }
    }
}

/// Public material whose exact bytes must be persisted before exposure.
///
/// The representation is deliberately opaque: this contract does not define a
/// witness wire protocol or a cryptographic transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct ExposureBytes {
    kind: ExposureKindV1,
    bytes: Box<[u8]>,
}

impl ExposureBytes {
    /// Creates an opaque byte-exact exposure value.
    pub fn from_bytes(
        kind: ExposureKindV1,
        bytes: impl Into<Box<[u8]>>,
    ) -> Result<Self, NonceVaultError> {
        let bytes = bytes.into();
        if bytes.len() != kind.canonical_length() {
            return Err(NonceVaultError::InvalidPublicMaterial);
        }
        Ok(Self { kind, bytes })
    }

    /// Returns the closed exposure kind.
    pub const fn kind(&self) -> ExposureKindV1 {
        self.kind
    }

    /// Returns the exact committed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Computes the exact stage-bound NAR-002 outbound digest.
    pub fn outbound_digest(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(5 + self.bytes.len());
        preimage.push(self.kind as u8);
        preimage.extend_from_slice(&(self.bytes.len() as u32).to_le_bytes());
        preimage.extend_from_slice(&self.bytes);
        *blake2b_256_tagged("DOM:scriptless-vault-outbound:v1", &preimage).as_bytes()
    }
}

impl fmt::Debug for ExposureBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExposureBytes([redacted])")
    }
}

/// Durable reservation metadata returned by the vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceReservation {
    /// Stable local reservation identifier.
    pub reservation_id: ReservationNonceId,
    /// Current monotonic lifecycle state.
    pub state: ReservationState,
}

/// Request to reserve nonce material and charge all applicable budgets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationRequest {
    /// Stable nonce identifier charged exactly once.
    pub reservation_id: ReservationNonceId,
    /// Signing-key budget owner.
    pub key_id: VaultKeyId,
    /// Local adaptor session.
    pub session_id: SessionId,
    /// Secondary budget bucket.
    pub counterparty: CounterpartyBucket,
    /// Closed protocol purpose.
    pub purpose: Purpose,
    /// Protocol participant bound to every exposure permit.
    pub participant_id: ParticipantId,
    /// Canonical contract template hash.
    pub template_hash: TemplateHash,
    /// Idempotency key for this logical reservation.
    pub request_id: IdempotencyKey,
}

/// Request to fix byte-exact public material before any export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPublicMaterialRequest {
    /// Reservation being advanced.
    pub reservation_id: ReservationNonceId,
    /// Idempotency key for this commit operation.
    pub request_id: IdempotencyKey,
    /// Exact bytes that every retry must return.
    pub exposure: ExposureBytes,
}

/// Request to authorize exposure after witness acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureAuthorizationRequest {
    /// Reservation being advanced.
    pub reservation_id: ReservationNonceId,
    /// Idempotency key bound by the witness receipt.
    pub request_id: IdempotencyKey,
    /// Exact public artifact already durably staged by the Wallet.
    pub exposure: ExposureBytes,
}

/// Request to retrieve already-authorized byte-exact material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryRequest {
    /// Reservation whose previously committed bytes are requested.
    pub reservation_id: ReservationNonceId,
}

/// Request to irreversibly consume a reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeRequest {
    /// Reservation being consumed.
    pub reservation_id: ReservationNonceId,
    /// Idempotency key for this terminal operation.
    pub request_id: IdempotencyKey,
    /// Conservative reason for consumption.
    pub reason: ConsumeReason,
}

/// Public bytes returned only after the nonce tombstone is durable.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsumedExposure(ExposureBytes);

impl ConsumedExposure {
    /// Returns the exact committed bytes for first send or idempotent resend.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Canonical public binding carried by an opaque Wallet-owned permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposurePermitBindingV1 {
    permit_id: IdempotencyKey,
    reservation_id: ReservationNonceId,
    session_id: SessionId,
    participant_id: ParticipantId,
    purpose: PurposeV1,
    template_hash: TemplateHash,
    outbound_digest: [u8; 32],
    exposure_kind: ExposureKindV1,
    epoch: u64,
    semantic_revision: u64,
    receipt_chain_hash: [u8; 32],
}

impl ExposurePermitBindingV1 {
    /// Validates the fields bound by a durable Wallet permit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        permit_id: IdempotencyKey,
        reservation_id: ReservationNonceId,
        session_id: SessionId,
        participant_id: ParticipantId,
        purpose: PurposeV1,
        template_hash: TemplateHash,
        outbound_digest: [u8; 32],
        exposure_kind: ExposureKindV1,
        epoch: u64,
        semantic_revision: u64,
        receipt_chain_hash: [u8; 32],
    ) -> Result<Self, NonceVaultError> {
        if outbound_digest.iter().all(|byte| *byte == 0)
            || receipt_chain_hash.iter().all(|byte| *byte == 0)
            || epoch == 0
        {
            return Err(NonceVaultError::InvalidPermit);
        }
        Ok(Self {
            permit_id,
            reservation_id,
            session_id,
            participant_id,
            purpose,
            template_hash,
            outbound_digest,
            exposure_kind,
            epoch,
            semantic_revision,
            receipt_chain_hash,
        })
    }

    /// Returns the exact 252-byte canonical binding representation.
    pub fn persistence_bytes(&self) -> [u8; 252] {
        let mut bytes = [0u8; 252];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, b"DOMEXPV1");
        append(&mut bytes, &mut cursor, &1u16.to_le_bytes());
        append(&mut bytes, &mut cursor, &[self.exposure_kind as u8]);
        append(&mut bytes, &mut cursor, self.permit_id.as_bytes());
        append(&mut bytes, &mut cursor, self.reservation_id.as_bytes());
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(&mut bytes, &mut cursor, self.participant_id.as_bytes());
        append(&mut bytes, &mut cursor, &[self.purpose as u8]);
        append(&mut bytes, &mut cursor, self.template_hash.as_bytes());
        append(&mut bytes, &mut cursor, &self.outbound_digest);
        append(&mut bytes, &mut cursor, &self.epoch.to_le_bytes());
        append(
            &mut bytes,
            &mut cursor,
            &self.semantic_revision.to_le_bytes(),
        );
        append(&mut bytes, &mut cursor, &self.receipt_chain_hash);
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }

    /// Computes the canonical permit digest.
    pub fn digest(&self) -> [u8; 32] {
        *blake2b_256_tagged(
            "DOM:scriptless-vault-exposure-permit:v1",
            &self.persistence_bytes(),
        )
        .as_bytes()
    }
}

/// Opaque one-shot permit issued only by a durable [`NonceVault`].
///
/// Production signing code accepts the associated permit type of its configured
/// vault implementation, never canonical bytes or a caller-selected parser. A
/// Wallet implementation keeps its permit constructor private and must not
/// implement Clone, Copy, Debug, Display, or generic serialization for it.
pub trait VaultExposurePermit {
    /// Returns the immutable canonical binding for exhaustive comparison.
    fn binding(&self) -> &ExposurePermitBindingV1;
}

impl fmt::Debug for ConsumedExposure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsumedExposure([redacted])")
    }
}

/// Request to abort while retaining every charged budget unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortRequest {
    /// Reservation being aborted.
    pub reservation_id: ReservationNonceId,
    /// Idempotency key for this terminal operation.
    pub request_id: IdempotencyKey,
    /// Whether any public material may have existed before abort.
    pub public_material_may_have_existed: bool,
}

/// Receipt accepted by a production witness verifier.
///
/// The byte-exact receipt protocol is intentionally outside this trait until a
/// later accepted specification freezes it.
pub trait VaultReceipt {
    /// Returns the idempotency key covered by the receipt.
    fn request_id(&self) -> &IdempotencyKey;

    /// Returns the applied receipt-chain hash.
    fn receipt_chain_hash(&self) -> &[u8; 32];

    /// Returns the opaque bytes that the wallet must persist durably.
    fn persistence_bytes(&self) -> &[u8];
}

/// Storage-independent lifecycle contract implemented by wallet software.
///
/// Implementations must make every state transition durable before returning.
/// Retrying an idempotency key must return the prior result or a typed conflict;
/// it must never allocate a new nonce or refund budget.
pub trait NonceVault {
    /// Receipt type produced by the configured witness verifier.
    type Receipt: VaultReceipt;
    /// Wallet-owned opaque one-shot permit type.
    type Permit: VaultExposurePermit;

    /// Reserves nonce slots and charges configured budgets atomically.
    fn reserve(&mut self, request: ReservationRequest)
        -> Result<NonceReservation, NonceVaultError>;

    /// Persists exact public bytes before any exposure can be authorized.
    fn stage_public_material(
        &mut self,
        request: CommitPublicMaterialRequest,
    ) -> Result<NonceReservation, NonceVaultError>;

    /// Persists a verified applied receipt and issues a one-shot permit.
    ///
    /// Commitment, reveal, and partial stages are distinct. Partial
    /// authorization additionally destroys the encrypted nonce secret and
    /// durably records its irreversible tombstone before returning.
    fn authorize_exposure(
        &mut self,
        request: ExposureAuthorizationRequest,
        receipt: Self::Receipt,
    ) -> Result<Self::Permit, NonceVaultError>;

    /// Consumes a one-shot permit and releases only its exact bound bytes.
    fn export(&mut self, permit: Self::Permit) -> Result<ConsumedExposure, NonceVaultError>;

    /// Irreversibly aborts a reservation without refunding budget.
    fn abort(
        &mut self,
        request: AbortRequest,
        receipt: Self::Receipt,
    ) -> Result<NonceReservation, NonceVaultError>;

    /// Returns whether adaptor operations are available after reconciliation.
    fn restore_state(&self) -> RestoreState;
}

/// Fail-closed errors shared by contract consumers and wallet implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceVaultError {
    /// An opaque identifier was empty.
    InvalidIdentifier,
    /// Public material was empty.
    InvalidPublicMaterial,
    /// A purpose byte is not in the ratified closed V1 registry.
    UnsupportedPurpose,
    /// An exposure byte is outside the closed NAR-002 registry.
    UnsupportedExposureKind,
    /// A one-shot permit field or durable binding is invalid.
    InvalidPermit,
    /// An idempotency key was reused for different inputs.
    IdempotencyConflict,
    /// The requested reservation does not exist.
    ReservationNotFound,
    /// The requested transition is not monotonic from the current state.
    InvalidTransition,
    /// A configured budget was exhausted.
    BudgetExhausted(BudgetScope),
    /// The witness is unavailable for an adaptor-only operation.
    WitnessUnavailable,
    /// A receipt failed witness authentication or request binding.
    InvalidWitnessReceipt,
    /// Local state is older than independently anchored state.
    RollbackDetected,
    /// Local and witnessed chains diverged.
    DivergenceDetected,
    /// Adaptor operations are disabled pending restore reconciliation.
    RestoreQuarantined,
    /// Durable state failed structural or authentication checks.
    CorruptState,
    /// Durable storage could not complete the requested operation.
    StorageUnavailable,
    /// A checked monotonic counter overflowed.
    CounterOverflow,
    /// The persisted schema or witness protocol version is unsupported.
    UnsupportedVersion,
}

impl fmt::Display for NonceVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentifier => "invalid empty vault identifier",
            Self::InvalidPublicMaterial => "invalid canonical public material",
            Self::UnsupportedPurpose => "unsupported PurposeV1 discriminant",
            Self::UnsupportedExposureKind => "unsupported ExposureKindV1 discriminant",
            Self::InvalidPermit => "invalid one-shot exposure permit",
            Self::IdempotencyConflict => "idempotency key conflicts with prior inputs",
            Self::ReservationNotFound => "nonce reservation not found",
            Self::InvalidTransition => "invalid nonce reservation transition",
            Self::BudgetExhausted(_) => "configured nonce session budget exhausted",
            Self::WitnessUnavailable => "remote witness unavailable",
            Self::InvalidWitnessReceipt => "invalid witness receipt",
            Self::RollbackDetected => "nonce vault rollback detected",
            Self::DivergenceDetected => "nonce vault divergence detected",
            Self::RestoreQuarantined => "nonce vault is restore quarantined",
            Self::CorruptState => "nonce vault durable state is corrupt",
            Self::StorageUnavailable => "nonce vault storage unavailable",
            Self::CounterOverflow => "nonce vault monotonic counter overflow",
            Self::UnsupportedVersion => "unsupported nonce vault version",
        };
        formatter.write_str(message)
    }
}

impl Error for NonceVaultError {}

fn append<const N: usize>(output: &mut [u8; N], cursor: &mut usize, bytes: &[u8]) {
    output[*cursor..*cursor + bytes.len()].copy_from_slice(bytes);
    *cursor += bytes.len();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identifier<T>(constructor: impl FnOnce([u8; 32]) -> Result<T, NonceVaultError>) -> T {
        constructor([7; 32]).expect("nonzero test identifier")
    }

    #[test]
    fn identifiers_and_exposure_are_redacted() {
        let session = identifier(SessionId::from_bytes);
        let exposure = ExposureBytes::from_bytes(ExposureKindV1::NonceCommitment, vec![1; 35])
            .expect("public bytes");
        assert_eq!(format!("{session:?}"), "SessionId([redacted])");
        assert_eq!(format!("{exposure:?}"), "ExposureBytes([redacted])");
    }

    #[test]
    fn empty_opaque_values_fail_closed() {
        assert_eq!(
            IdempotencyKey::from_bytes([0; 32]),
            Err(NonceVaultError::InvalidIdentifier)
        );
        assert_eq!(
            ExposureBytes::from_bytes(ExposureKindV1::NonceCommitment, Vec::<u8>::new()),
            Err(NonceVaultError::InvalidPublicMaterial)
        );
    }

    #[test]
    fn purpose_set_is_closed() {
        let purposes = [
            PurposeV1::Refund,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Funding,
            PurposeV1::Sponsor,
        ];
        assert_eq!(purposes.len(), 4);
        assert!(purposes[..3]
            .iter()
            .all(|purpose| purpose.is_strict_v1_authorized()));
        assert!(!PurposeV1::Sponsor.is_strict_v1_authorized());
        for (byte, purpose) in [
            (1, PurposeV1::Refund),
            (2, PurposeV1::ClaimAdaptor),
            (3, PurposeV1::Funding),
            (4, PurposeV1::Sponsor),
        ] {
            assert_eq!(PurposeV1::try_from(byte), Ok(purpose));
            assert_eq!(purpose.to_byte(), byte);
        }
        assert_eq!(
            PurposeV1::try_from(0),
            Err(NonceVaultError::UnsupportedPurpose)
        );
        assert_eq!(
            PurposeV1::try_from(5),
            Err(NonceVaultError::UnsupportedPurpose)
        );
    }
}

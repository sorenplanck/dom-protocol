//! Storage-independent contract for a durable, rollback-resistant Nonce Vault.

use core::fmt;
use std::error::Error;
use std::hash::{Hash, Hasher};

macro_rules! opaque_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq)]
        pub struct $name(Box<[u8]>);

        impl $name {
            #[doc = "Constructs the identifier, rejecting an empty representation."]
            pub fn from_bytes(bytes: impl Into<Box<[u8]>>) -> Result<Self, NonceVaultError> {
                let bytes = bytes.into();
                if bytes.is_empty() {
                    return Err(NonceVaultError::InvalidIdentifier);
                }
                Ok(Self(bytes))
            }

            #[doc = "Returns the local opaque representation."]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state);
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
    PublicCommitmentStored,
    /// A verified witness receipt is durable and exposure is permitted.
    ExportAuthorized,
    /// The nonce and budget are irreversibly consumed.
    Consumed,
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

/// Public material whose exact bytes must be persisted before exposure.
///
/// The representation is deliberately opaque: this contract does not define a
/// witness wire protocol or a cryptographic transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct ExposureBytes(Box<[u8]>);

impl ExposureBytes {
    /// Creates an opaque byte-exact exposure value.
    pub fn from_bytes(bytes: impl Into<Box<[u8]>>) -> Result<Self, NonceVaultError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(NonceVaultError::EmptyPublicMaterial);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact committed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
    pub reservation_id: IdempotencyKey,
    /// Current monotonic lifecycle state.
    pub state: ReservationState,
}

/// Request to reserve nonce material and charge all applicable budgets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationRequest {
    /// Signing-key budget owner.
    pub key_id: VaultKeyId,
    /// Local adaptor session.
    pub session_id: SessionId,
    /// Secondary budget bucket.
    pub counterparty: CounterpartyBucket,
    /// Closed protocol purpose.
    pub purpose: Purpose,
    /// Idempotency key for this logical reservation.
    pub request_id: IdempotencyKey,
}

/// Request to fix byte-exact public material before any export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPublicMaterialRequest {
    /// Reservation being advanced.
    pub reservation_id: IdempotencyKey,
    /// Idempotency key for this commit operation.
    pub request_id: IdempotencyKey,
    /// Exact bytes that every retry must return.
    pub exposure: ExposureBytes,
}

/// Request to authorize exposure after witness acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureAuthorizationRequest {
    /// Reservation being advanced.
    pub reservation_id: IdempotencyKey,
    /// Idempotency key bound by the witness receipt.
    pub request_id: IdempotencyKey,
}

/// Request to retrieve already-authorized byte-exact material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryRequest {
    /// Reservation whose previously committed bytes are requested.
    pub reservation_id: IdempotencyKey,
}

/// Request to irreversibly consume a reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeRequest {
    /// Reservation being consumed.
    pub reservation_id: IdempotencyKey,
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

impl fmt::Debug for ConsumedExposure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsumedExposure([redacted])")
    }
}

/// Request to abort while retaining every charged budget unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortRequest {
    /// Reservation being aborted.
    pub reservation_id: IdempotencyKey,
    /// Idempotency key for this terminal operation.
    pub request_id: IdempotencyKey,
}

/// Receipt accepted by a production witness verifier.
///
/// The byte-exact receipt protocol is intentionally outside this trait until a
/// later accepted specification freezes it.
pub trait VaultReceipt {
    /// Returns the idempotency key covered by the receipt.
    fn request_id(&self) -> &IdempotencyKey;

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

    /// Reserves nonce slots and charges configured budgets atomically.
    fn reserve(&mut self, request: ReservationRequest)
        -> Result<NonceReservation, NonceVaultError>;

    /// Persists exact public bytes before any exposure can be authorized.
    fn commit_public_material(
        &mut self,
        request: CommitPublicMaterialRequest,
    ) -> Result<NonceReservation, NonceVaultError>;

    /// Persists a verified witness receipt and permits exposure atomically.
    fn authorize_exposure(
        &mut self,
        request: ExposureAuthorizationRequest,
        receipt: Self::Receipt,
    ) -> Result<NonceReservation, NonceVaultError>;

    /// Returns the exact previously committed bytes only after consumption.
    ///
    /// Implementations must reject this call while the reservation is merely
    /// export-authorized. The first export is performed by [`Self::consume`].
    fn retry_public_material(
        &self,
        request: RetryRequest,
    ) -> Result<ConsumedExposure, NonceVaultError>;

    /// Irreversibly consumes secret material before returning public bytes.
    ///
    /// The implementation must durably write the tombstone and exact outbound
    /// bytes before this method succeeds. An error returns no exportable bytes.
    fn consume(&mut self, request: ConsumeRequest) -> Result<ConsumedExposure, NonceVaultError>;

    /// Irreversibly aborts a reservation without refunding budget.
    fn abort(&mut self, request: AbortRequest) -> Result<NonceReservation, NonceVaultError>;

    /// Returns whether adaptor operations are available after reconciliation.
    fn restore_state(&self) -> RestoreState;
}

/// Fail-closed errors shared by contract consumers and wallet implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceVaultError {
    /// An opaque identifier was empty.
    InvalidIdentifier,
    /// Public material was empty.
    EmptyPublicMaterial,
    /// A purpose byte is not in the ratified closed V1 registry.
    UnsupportedPurpose,
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
            Self::EmptyPublicMaterial => "empty public material",
            Self::UnsupportedPurpose => "unsupported PurposeV1 discriminant",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identifier<T>(constructor: impl FnOnce(Box<[u8]>) -> Result<T, NonceVaultError>) -> T {
        constructor(vec![7; 8].into_boxed_slice()).expect("non-empty test identifier")
    }

    #[test]
    fn identifiers_and_exposure_are_redacted() {
        let session = identifier(SessionId::from_bytes);
        let exposure = ExposureBytes::from_bytes(vec![1, 2, 3]).expect("public bytes");
        assert_eq!(format!("{session:?}"), "SessionId([redacted])");
        assert_eq!(format!("{exposure:?}"), "ExposureBytes([redacted])");
    }

    #[test]
    fn empty_opaque_values_fail_closed() {
        assert_eq!(
            IdempotencyKey::from_bytes(Vec::<u8>::new()),
            Err(NonceVaultError::InvalidIdentifier)
        );
        assert_eq!(
            ExposureBytes::from_bytes(Vec::<u8>::new()),
            Err(NonceVaultError::EmptyPublicMaterial)
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

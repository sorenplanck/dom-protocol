//! Storage-independent contract for a durable, rollback-resistant Nonce Vault.

use crate::{ExposureKindV1, PurposeV1};
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
        if bytes.len() != kind.outbound_len() {
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
        preimage.push(self.kind.to_byte());
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
    reservation_id: ReservationNonceId,
    /// Signing-key budget owner.
    key_id: VaultKeyId,
    /// Local adaptor session.
    session_id: SessionId,
    /// Secondary budget bucket.
    counterparty: CounterpartyBucket,
    /// Closed protocol purpose.
    purpose: Purpose,
    /// Protocol participant bound to every exposure permit.
    participant_id: ParticipantId,
    /// Canonical contract template hash.
    template_hash: TemplateHash,
    /// Idempotency key for this logical reservation.
    request_id: IdempotencyKey,
}

impl ReservationRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        reservation_id: ReservationNonceId,
        key_id: VaultKeyId,
        session_id: SessionId,
        counterparty: CounterpartyBucket,
        purpose: Purpose,
        participant_id: ParticipantId,
        template_hash: TemplateHash,
        request_id: IdempotencyKey,
    ) -> Self {
        Self {
            reservation_id,
            key_id,
            session_id,
            counterparty,
            purpose,
            participant_id,
            template_hash,
            request_id,
        }
    }

    /// Return the internally allocated reservation identifier.
    pub const fn reservation_id(&self) -> &ReservationNonceId {
        &self.reservation_id
    }

    /// Return the signing-key budget owner.
    pub const fn key_id(&self) -> &VaultKeyId {
        &self.key_id
    }

    /// Return the bound session identifier.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Return the secondary counterparty budget bucket.
    pub const fn counterparty(&self) -> &CounterpartyBucket {
        &self.counterparty
    }

    /// Return the canonical purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Return the bound participant identifier.
    pub const fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    /// Return the canonical template hash.
    pub const fn template_hash(&self) -> &TemplateHash {
        &self.template_hash
    }

    /// Return the internally allocated idempotency key.
    pub const fn request_id(&self) -> &IdempotencyKey {
        &self.request_id
    }
}

/// Caller intent without reservation or idempotency authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationIntentV1 {
    pub(crate) key_id: VaultKeyId,
    pub(crate) counterparty: CounterpartyBucket,
    pub(crate) purpose: PurposeV1,
    pub(crate) participant_id: ParticipantId,
    pub(crate) template_hash: TemplateHash,
}

impl ReservationIntentV1 {
    /// Construct validated public reservation intent.
    pub fn new(
        key_id: VaultKeyId,
        counterparty: CounterpartyBucket,
        purpose: PurposeV1,
        participant_id: ParticipantId,
        template_hash: TemplateHash,
    ) -> Result<Self, NonceVaultError> {
        if !purpose.is_strict_v1_authorized() {
            return Err(NonceVaultError::UnsupportedPurpose);
        }
        Ok(Self {
            key_id,
            counterparty,
            purpose,
            participant_id,
            template_hash,
        })
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
    /// Exact canonical persisted record length.
    pub const ENCODED_LEN: usize = 252;

    /// Parse the canonical durable record without creating authorization authority.
    pub fn from_persistence_bytes(bytes: &[u8]) -> Result<Self, NonceVaultError> {
        if bytes.len() != Self::ENCODED_LEN
            || &bytes[..8] != b"DOMEXPV1"
            || u16::from_le_bytes([bytes[8], bytes[9]]) != 1
        {
            return Err(NonceVaultError::InvalidPermit);
        }
        let exposure_kind = ExposureKindV1::try_from(bytes[10])
            .map_err(|_| NonceVaultError::UnsupportedExposureKind)?;
        let purpose =
            PurposeV1::try_from(bytes[139]).map_err(|_| NonceVaultError::UnsupportedPurpose)?;
        if !purpose.is_strict_v1_authorized() {
            return Err(NonceVaultError::UnsupportedPurpose);
        }
        Self::new(
            IdempotencyKey::from_bytes(bytes[11..43].try_into().expect("fixed permit ID"))?,
            ReservationNonceId::from_bytes(
                bytes[43..75].try_into().expect("fixed reservation ID"),
            )?,
            SessionId::from_bytes(bytes[75..107].try_into().expect("fixed session ID"))?,
            ParticipantId::from_bytes(bytes[107..139].try_into().expect("fixed participant ID"))?,
            purpose,
            TemplateHash::from_bytes(bytes[140..172].try_into().expect("fixed template hash"))?,
            bytes[172..204].try_into().expect("fixed outbound digest"),
            exposure_kind,
            u64::from_le_bytes(bytes[204..212].try_into().expect("fixed epoch")),
            u64::from_le_bytes(bytes[212..220].try_into().expect("fixed revision")),
            bytes[220..252]
                .try_into()
                .expect("fixed receipt-chain hash"),
        )
    }

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
    pub fn persistence_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
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

    /// Return the one-shot permit identifier.
    pub const fn permit_id(&self) -> &IdempotencyKey {
        &self.permit_id
    }

    /// Return the reservation identifier.
    pub const fn reservation_id(&self) -> &ReservationNonceId {
        &self.reservation_id
    }

    /// Return the bound session identifier.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Return the bound participant identifier.
    pub const fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    /// Return the closed purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Return the template hash.
    pub const fn template_hash(&self) -> &TemplateHash {
        &self.template_hash
    }

    /// Return the exact outbound digest.
    pub const fn outbound_digest(&self) -> &[u8; 32] {
        &self.outbound_digest
    }

    /// Return the closed exposure kind.
    pub const fn exposure_kind(&self) -> ExposureKindV1 {
        self.exposure_kind
    }

    /// Return the vault epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Return the semantic revision.
    pub const fn semantic_revision(&self) -> u64 {
        self.semantic_revision
    }

    /// Return the applied receipt-chain hash.
    pub const fn receipt_chain_hash(&self) -> &[u8; 32] {
        &self.receipt_chain_hash
    }
}

/// Canonical V1 reservation request consumed by the trusted vault.
pub type ReservationRequestV1 = ReservationRequest;

/// Canonical permit identifier used only for exact persisted resend.
pub type PermitIdV1 = IdempotencyKey;

/// A prepared public artifact that has not crossed the authorization boundary.
///
/// The type is deliberately non-cloneable and has no public raw-byte accessor.
pub struct PreparedExposureV1(ExposureBytes);

impl PreparedExposureV1 {
    pub(crate) fn new(exposure: ExposureBytes) -> Self {
        Self(exposure)
    }

    /// Borrow the exact public bytes and closed kind that the vault must persist.
    pub fn exposure(&self) -> &ExposureBytes {
        &self.0
    }
}

/// Public bytes released only after the Wallet has durably spent a permit.
pub struct AuthorizedExposureV1(ExposureBytes);

impl AuthorizedExposureV1 {
    pub(crate) fn from_vault_export(
        exported: &impl VaultExportedArtifactV1,
    ) -> Result<Self, NonceVaultError> {
        Ok(Self(ExposureBytes::from_bytes(
            exported.kind(),
            exported.as_bytes(),
        )?))
    }

    /// Return the authorized public artifact kind.
    pub const fn kind(&self) -> ExposureKindV1 {
        self.0.kind()
    }

    /// Borrow the exact persisted public bytes for first send or exact resend.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Read-only view of exact persisted output owned by a concrete Wallet vault.
///
/// The concrete production type has a private constructor and is returned only
/// after durable permit spend. `dom-adaptor` wraps its public bytes only inside
/// the integrated signer.
pub trait VaultExportedArtifactV1 {
    /// Return the closed exposure kind.
    fn kind(&self) -> ExposureKindV1;
    /// Borrow the exact byte-identical persisted artifact.
    fn as_bytes(&self) -> &[u8];
}

/// Fail-closed reason for terminally aborting a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortReasonV1 {
    /// No public material was authorized.
    BeforePublicMaterial,
    /// Public material may have existed and the complete nonce pair is burned.
    PublicMaterialMayHaveExisted,
    /// Crash ambiguity requires permanent retirement.
    CrashAmbiguity,
    /// Restore reconciliation cannot prove safe continuation.
    RestoreAmbiguity,
}

/// The only two operations allowed to reopen an encrypted nonce secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretOpenStageV1 {
    /// Read-only reopen used to derive and persist the nonce reveal.
    NonceReveal,
    /// One-shot reopen after a durable partial-attempt marker.
    PartialAttempt,
}

/// Public terminal projection returned after irreversible abort or burn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalReservationV1 {
    /// Stable reservation identifier retained for lifetime replay rejection.
    pub reservation_id: ReservationNonceId,
    /// Monotonic terminal state.
    pub state: ReservationState,
}

/// Storage-independent lifecycle authority implemented by the reviewed Wallet.
///
/// Implementations own witness exchange, receipt verification, persistence,
/// synchronization, tombstones, and budgets. No method accepts a receipt,
/// witness-success Boolean, storage-success Boolean, raw permit, or witness key
/// from its caller. Production selects one concrete implementation statically;
/// trait objects are not the production composition boundary.
pub trait NonceVaultV1 {
    /// Wallet-specific typed failure with redacted observability.
    type Error: Error + Send + Sync + 'static;
    /// Opaque reservation handle owned by the concrete vault.
    type ReservationHandle;
    /// Opaque one-shot capability with a private Wallet constructor.
    type ExposurePermit;
    /// Wallet-owned output produced only after durable permit spend.
    type ExportedArtifact: VaultExportedArtifactV1;

    /// Durably reserve, charge, seal, journal, witness, and persist a nonce slot.
    fn reserve(
        &mut self,
        request: ReservationRequestV1,
        secret: crate::NonceSecretTransferV1,
        seal_capability: crate::VaultSecretSealCapabilityV1,
        commitment: crate::NonceCommitmentV1,
    ) -> core::result::Result<Self::ReservationHandle, Self::Error>;

    /// Stage exact bytes, obtain and verify the witness receipt, and issue one capability.
    fn authorize_exposure(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        artifact: PreparedExposureV1,
    ) -> core::result::Result<Self::ExposurePermit, Self::Error>;

    /// Open the sealed record for one stage under Wallet-owned durability rules.
    ///
    /// `PartialAttempt` requires the irreversible attempt marker before
    /// decryption. Recovery after an incomplete partial attempt burns or
    /// quarantines the reservation and never calls this method again.
    fn open_secret(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        stage: SecretOpenStageV1,
        import_capability: crate::VaultSecretImportCapabilityV1,
    ) -> core::result::Result<crate::NonceSecretTransferV1, Self::Error>;

    /// Durably spend the capability before releasing the persisted artifact.
    fn export(
        &mut self,
        permit: Self::ExposurePermit,
    ) -> core::result::Result<Self::ExportedArtifact, Self::Error>;

    /// Return only the exact persisted bytes bound to an already-spent permit.
    fn resend_exported(
        &self,
        permit_id: PermitIdV1,
    ) -> core::result::Result<Self::ExportedArtifact, Self::Error>;

    /// Irreversibly abort or burn without refunding any charged budget.
    fn abort(
        &mut self,
        reservation: Self::ReservationHandle,
        reason: AbortReasonV1,
    ) -> core::result::Result<TerminalReservationV1, Self::Error>;

    /// Return whether adaptor operations are available after reconciliation.
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
    /// The session ID was already claimed by the lifetime tombstone set.
    SessionIdReused,
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
            Self::SessionIdReused => "Scriptless session identifier was already used",
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
        assert!(PurposeV1::try_from(0).is_err());
        assert!(PurposeV1::try_from(5).is_err());
    }
}

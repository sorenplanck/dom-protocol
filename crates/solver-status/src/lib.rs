//! Threshold-authenticated, durable solver operational status.
//!
//! F6 admissibility needs more than roster membership: the selected solver
//! must be current, non-suspended and not under slashing.  This crate turns
//! that economic fact into a bounded signed statement, persists its complete
//! monotonic history and returns a move-only active capability.  A caller can
//! never promote a boolean into status authority.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use kaystra_core::types::{Digest32, ParticipantId};
use std::path::Path;
use store::{ProductionStoreBindingV1, Store, StoreError};

const STATEMENT_MAGIC_V1: &[u8; 8] = b"DOMSSTV1";
const SIGNED_MAGIC_V1: &[u8; 8] = b"DOMSSGV1";
const STATEMENT_DOMAIN_V1: &[u8] = b"DOM-INTEROP/SOLVER-STATUS/STATEMENT/V1\0";
const AUTHORITY_SET_DOMAIN_V1: &[u8] = b"DOM-INTEROP/SOLVER-STATUS/AUTHORITY-SET/V1\0";
const STORE_BINDING_DOMAIN_V1: &[u8] = b"DOM-INTEROP/SOLVER-STATUS/STORE/V1\0";
const FORMAT_VERSION_V1: u16 = 1;
const STATUS_JOURNAL_KIND_V1: u16 = 1;
const TRUSTED_CLOCK_ENTITY_V1: &[u8] = b"DOM-INTEROP/SOLVER-STATUS/TRUSTED-CLOCK/V1";
const MAX_AUTHORITIES_V1: usize = 16;
const MAX_HISTORY_ROWS_V1: usize = 4_096;
const STATEMENT_BYTES_V1: usize = 203;
const SIGNATURE_BYTES_V1: usize = 66;
const MAX_SIGNED_BYTES_V1: usize =
    8 + 2 + 4 + STATEMENT_BYTES_V1 + 2 + MAX_AUTHORITIES_V1 * SIGNATURE_BYTES_V1;
const ZERO_DIGEST: Digest32 = [0; 32];

/// Hard upper bound for one signed Active/Suspended/Slashing statement.
/// Operators may configure a shorter lifetime but cannot weaken this cap.
pub const MAX_STATUS_LIFETIME_SECONDS_V1: u64 = 300;

/// Named fail-closed errors from the solver-status authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SolverStatusErrorV1 {
    /// One or more immutable scope or policy fields are invalid.
    #[error("invalid solver-status configuration")]
    InvalidConfiguration,
    /// The statement or signed wrapper is malformed or non-canonical.
    #[error("invalid solver-status encoding")]
    InvalidEncoding,
    /// The supplied statement belongs to another authority scope.
    #[error("solver-status scope mismatch")]
    ScopeMismatch,
    /// The configured threshold authority set is invalid.
    #[error("invalid solver-status authority set")]
    InvalidAuthoritySet,
    /// A signature is malformed, duplicated or invalid.
    #[error("invalid solver-status signature")]
    InvalidSignature,
    /// Too few independent authorities signed the statement.
    #[error("solver-status signature threshold not met")]
    ThresholdNotMet,
    /// The signed status is from the future or is no longer current.
    #[error("solver-status evidence is not current")]
    StaleStatus,
    /// The trusted wall clock moved below its durable high-water mark.
    #[error("solver-status trusted clock rollback detected")]
    ClockRollback,
    /// A lower epoch or observation time was presented.
    #[error("solver-status rollback detected")]
    Rollback,
    /// The same status epoch was signed over different bytes.
    #[error("solver-status equivocation detected")]
    Equivocation,
    /// The current status is suspended or under slashing.
    #[error("solver is not operationally active")]
    NotActive,
    /// A configured or durable bound was exceeded.
    #[error("solver-status bound exceeded")]
    BoundExceeded,
    /// Checked arithmetic or digest construction failed.
    #[error("solver-status arithmetic or digest failure")]
    Arithmetic,
    /// The strict durable authority could not be opened or audited.
    #[error("solver-status storage unavailable or inconsistent")]
    Storage,
}

/// Result alias for this authority.
pub type Result<T> = core::result::Result<T, SolverStatusErrorV1>;

/// Operational state asserted by the status authorities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SolverOperationalStateV1 {
    /// The solver may participate, subject to every other F6 check.
    Active = 1,
    /// The solver has been administratively suspended.
    Suspended = 2,
    /// The solver is under an unresolved slashing process.
    Slashing = 3,
}

/// Immutable network, registry, roster and solver identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverStatusScopeV1 {
    /// Authenticated deployment network.
    pub network_id: Digest32,
    /// Authenticated registry digest.
    pub registry_digest: Digest32,
    /// Monotonic registry epoch.
    pub registry_epoch: u64,
    /// Exact roster snapshot being qualified.
    pub roster_snapshot: Digest32,
    /// Solver whose operational state is asserted.
    pub solver_id: ParticipantId,
}

/// One monotonic operational observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverStatusObservationV1 {
    /// Monotonic status epoch.
    pub status_epoch: u64,
    /// Commitment to the canonical chain/slashing evidence set.
    pub source_evidence_digest: Digest32,
    /// Asserted state.
    pub state: SolverOperationalStateV1,
    /// Trusted observation second.
    pub observed_at_seconds: u64,
    /// Exclusive signed validity boundary.
    pub valid_until_seconds: u64,
}

/// Freshness policy pinned by the production store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverStatusFreshnessPolicyV1 {
    /// Maximum signed statement lifetime.
    pub max_status_lifetime_seconds: u64,
}

impl SolverOperationalStateV1 {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Suspended),
            3 => Ok(Self::Slashing),
            _ => Err(SolverStatusErrorV1::InvalidEncoding),
        }
    }
}

/// Exact threshold-signed statement about one solver at one roster snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverStatusStatementV1 {
    network_id: Digest32,
    registry_digest: Digest32,
    registry_epoch: u64,
    roster_snapshot: Digest32,
    solver_id: ParticipantId,
    status_epoch: u64,
    source_evidence_digest: Digest32,
    state: SolverOperationalStateV1,
    observed_at_seconds: u64,
    valid_until_seconds: u64,
}

impl SolverStatusStatementV1 {
    /// Constructs a complete public statement. Freshness is checked again at
    /// every installation and proof; this constructor only validates shape.
    pub fn new(scope: SolverStatusScopeV1, observation: SolverStatusObservationV1) -> Result<Self> {
        let value = Self {
            network_id: scope.network_id,
            registry_digest: scope.registry_digest,
            registry_epoch: scope.registry_epoch,
            roster_snapshot: scope.roster_snapshot,
            solver_id: scope.solver_id,
            status_epoch: observation.status_epoch,
            source_evidence_digest: observation.source_evidence_digest,
            state: observation.state,
            observed_at_seconds: observation.observed_at_seconds,
            valid_until_seconds: observation.valid_until_seconds,
        };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(self) -> Result<()> {
        if [
            self.network_id,
            self.registry_digest,
            self.roster_snapshot,
            self.solver_id.0,
            self.source_evidence_digest,
        ]
        .contains(&ZERO_DIGEST)
            || self.registry_epoch == 0
            || self.status_epoch == 0
            || self.observed_at_seconds == 0
            || self.observed_at_seconds >= self.valid_until_seconds
        {
            return Err(SolverStatusErrorV1::InvalidConfiguration);
        }
        Ok(())
    }

    /// Authenticated deployment network.
    pub const fn network_id(self) -> Digest32 {
        self.network_id
    }

    /// Authenticated deployment-registry digest.
    pub const fn registry_digest(self) -> Digest32 {
        self.registry_digest
    }

    /// Monotonic deployment-registry epoch.
    pub const fn registry_epoch(self) -> u64 {
        self.registry_epoch
    }

    /// Exact roster snapshot whose membership is being qualified.
    pub const fn roster_snapshot(self) -> Digest32 {
        self.roster_snapshot
    }

    /// Solver covered by this statement.
    pub const fn solver_id(self) -> ParticipantId {
        self.solver_id
    }

    /// Monotonic status epoch.
    pub const fn status_epoch(self) -> u64 {
        self.status_epoch
    }

    /// Commitment to the chain/slashing sources used by the authorities.
    pub const fn source_evidence_digest(self) -> Digest32 {
        self.source_evidence_digest
    }

    /// Asserted operational state.
    pub const fn state(self) -> SolverOperationalStateV1 {
        self.state
    }

    /// Trusted observation second.
    pub const fn observed_at_seconds(self) -> u64 {
        self.observed_at_seconds
    }

    /// Exclusive freshness boundary.
    pub const fn valid_until_seconds(self) -> u64 {
        self.valid_until_seconds
    }

    /// Frozen canonical bytes covered by every signature.
    pub fn canonical_bytes(self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(STATEMENT_BYTES_V1);
        out.extend_from_slice(STATEMENT_MAGIC_V1);
        out.extend_from_slice(&FORMAT_VERSION_V1.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.registry_digest);
        out.extend_from_slice(&self.registry_epoch.to_be_bytes());
        out.extend_from_slice(&self.roster_snapshot);
        out.extend_from_slice(&self.solver_id.0);
        out.extend_from_slice(&self.status_epoch.to_be_bytes());
        out.extend_from_slice(&self.source_evidence_digest);
        out.push(self.state as u8);
        out.extend_from_slice(&self.observed_at_seconds.to_be_bytes());
        out.extend_from_slice(&self.valid_until_seconds.to_be_bytes());
        if out.len() != STATEMENT_BYTES_V1 {
            return Err(SolverStatusErrorV1::Arithmetic);
        }
        Ok(out)
    }

    /// Strict canonical decoder; truncation, alternates and trailing bytes fail.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != STATEMENT_BYTES_V1
            || bytes.get(..8) != Some(STATEMENT_MAGIC_V1.as_slice())
        {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        let mut cursor = 8usize;
        if take_u16(bytes, &mut cursor)? != FORMAT_VERSION_V1 {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        let scope = SolverStatusScopeV1 {
            network_id: take_32(bytes, &mut cursor)?,
            registry_digest: take_32(bytes, &mut cursor)?,
            registry_epoch: take_u64(bytes, &mut cursor)?,
            roster_snapshot: take_32(bytes, &mut cursor)?,
            solver_id: ParticipantId(take_32(bytes, &mut cursor)?),
        };
        let observation = SolverStatusObservationV1 {
            status_epoch: take_u64(bytes, &mut cursor)?,
            source_evidence_digest: take_32(bytes, &mut cursor)?,
            state: SolverOperationalStateV1::decode(take_u8(bytes, &mut cursor)?)?,
            observed_at_seconds: take_u64(bytes, &mut cursor)?,
            valid_until_seconds: take_u64(bytes, &mut cursor)?,
        };
        let value = Self::new(scope, observation)?;
        if cursor != bytes.len() || value.canonical_bytes()?.as_slice() != bytes {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        Ok(value)
    }

    /// BLAKE2b-256 digest signed by status authorities.
    pub fn statement_digest(self) -> Result<Digest32> {
        digest_parts(STATEMENT_DOMAIN_V1, &[&self.canonical_bytes()?])
    }
}

/// One indexed BIP340 status signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverStatusSignatureV1 {
    /// Index into the externally pinned authority set.
    pub signer_index: u16,
    /// Canonical BIP340 signature over the statement digest.
    pub signature: [u8; 64],
}

/// Canonical statement plus a strictly ordered threshold signature set.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedSolverStatusV1 {
    statement_bytes: Vec<u8>,
    signatures: Vec<SolverStatusSignatureV1>,
}

impl core::fmt::Debug for SignedSolverStatusV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedSolverStatusV1")
            .field("statement_bytes", &self.statement_bytes.len())
            .field("signature_count", &self.signatures.len())
            .finish()
    }
}

impl SignedSolverStatusV1 {
    /// Wraps one canonical statement and a bounded ordered signature set.
    pub fn new(
        statement: SolverStatusStatementV1,
        signatures: Vec<SolverStatusSignatureV1>,
    ) -> Result<Self> {
        validate_signature_shape(&signatures)?;
        Ok(Self {
            statement_bytes: statement.canonical_bytes()?,
            signatures,
        })
    }

    /// Decoded statement covered by the signatures.
    pub fn statement(&self) -> Result<SolverStatusStatementV1> {
        SolverStatusStatementV1::decode(&self.statement_bytes)
    }

    /// Ordered signatures.
    pub fn signatures(&self) -> &[SolverStatusSignatureV1] {
        &self.signatures
    }

    /// Strict storage/transport encoding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        SolverStatusStatementV1::decode(&self.statement_bytes)?;
        validate_signature_shape(&self.signatures)?;
        let statement_len = u32::try_from(self.statement_bytes.len())
            .map_err(|_| SolverStatusErrorV1::BoundExceeded)?;
        let signature_count =
            u16::try_from(self.signatures.len()).map_err(|_| SolverStatusErrorV1::BoundExceeded)?;
        let mut out = Vec::with_capacity(
            8 + 2 + 4 + self.statement_bytes.len() + 2 + self.signatures.len() * SIGNATURE_BYTES_V1,
        );
        out.extend_from_slice(SIGNED_MAGIC_V1);
        out.extend_from_slice(&FORMAT_VERSION_V1.to_be_bytes());
        out.extend_from_slice(&statement_len.to_be_bytes());
        out.extend_from_slice(&self.statement_bytes);
        out.extend_from_slice(&signature_count.to_be_bytes());
        for signature in &self.signatures {
            out.extend_from_slice(&signature.signer_index.to_be_bytes());
            out.extend_from_slice(&signature.signature);
        }
        if out.len() > MAX_SIGNED_BYTES_V1 {
            return Err(SolverStatusErrorV1::BoundExceeded);
        }
        Ok(out)
    }

    /// Strict decoder for persisted and transported signed status bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_BYTES_V1
            || bytes.len() < 8 + 2 + 4 + STATEMENT_BYTES_V1 + 2 + SIGNATURE_BYTES_V1
            || bytes.get(..8) != Some(SIGNED_MAGIC_V1.as_slice())
        {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        let mut cursor = 8usize;
        if take_u16(bytes, &mut cursor)? != FORMAT_VERSION_V1 {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        let statement_len = usize::try_from(take_u32(bytes, &mut cursor)?)
            .map_err(|_| SolverStatusErrorV1::BoundExceeded)?;
        if statement_len != STATEMENT_BYTES_V1 {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        let statement_bytes = take_slice(bytes, &mut cursor, statement_len)?.to_vec();
        SolverStatusStatementV1::decode(&statement_bytes)?;
        let count = usize::from(take_u16(bytes, &mut cursor)?);
        if count == 0 || count > MAX_AUTHORITIES_V1 {
            return Err(SolverStatusErrorV1::BoundExceeded);
        }
        let remaining = count
            .checked_mul(SIGNATURE_BYTES_V1)
            .ok_or(SolverStatusErrorV1::Arithmetic)?;
        if bytes.len().checked_sub(cursor) != Some(remaining) {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(SolverStatusSignatureV1 {
                signer_index: take_u16(bytes, &mut cursor)?,
                signature: take_64(bytes, &mut cursor)?,
            });
        }
        let value = Self {
            statement_bytes,
            signatures,
        };
        validate_signature_shape(&value.signatures)?;
        if cursor != bytes.len() || value.canonical_bytes()?.as_slice() != bytes {
            return Err(SolverStatusErrorV1::InvalidEncoding);
        }
        Ok(value)
    }
}

/// Immutable pins and freshness bounds of one solver-status store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverStatusStoreConfigV1 {
    network_id: Digest32,
    registry_digest: Digest32,
    registry_epoch: u64,
    roster_snapshot: Digest32,
    solver_id: ParticipantId,
    authority_set_digest: Digest32,
    max_status_lifetime_seconds: u64,
}

impl SolverStatusStoreConfigV1 {
    /// Constructs immutable pins from the exact authority set.
    pub fn new(
        scope: SolverStatusScopeV1,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        freshness: SolverStatusFreshnessPolicyV1,
    ) -> Result<Self> {
        let value = Self {
            network_id: scope.network_id,
            registry_digest: scope.registry_digest,
            registry_epoch: scope.registry_epoch,
            roster_snapshot: scope.roster_snapshot,
            solver_id: scope.solver_id,
            authority_set_digest: authority_set_digest(authorities, secp)?,
            max_status_lifetime_seconds: freshness.max_status_lifetime_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<()> {
        if [
            self.network_id,
            self.registry_digest,
            self.roster_snapshot,
            self.solver_id.0,
            self.authority_set_digest,
        ]
        .contains(&ZERO_DIGEST)
            || self.registry_epoch == 0
            || self.max_status_lifetime_seconds == 0
            || self.max_status_lifetime_seconds > MAX_STATUS_LIFETIME_SECONDS_V1
        {
            return Err(SolverStatusErrorV1::InvalidConfiguration);
        }
        Ok(())
    }

    /// Authenticated deployment network.
    pub const fn network_id(self) -> Digest32 {
        self.network_id
    }

    /// Authenticated registry digest.
    pub const fn registry_digest(self) -> Digest32 {
        self.registry_digest
    }

    /// Registry epoch.
    pub const fn registry_epoch(self) -> u64 {
        self.registry_epoch
    }

    /// Roster snapshot qualified by this status stream.
    pub const fn roster_snapshot(self) -> Digest32 {
        self.roster_snapshot
    }

    /// Solver qualified by this status stream.
    pub const fn solver_id(self) -> ParticipantId {
        self.solver_id
    }

    /// Threshold authority-set digest.
    pub const fn authority_set_digest(self) -> Digest32 {
        self.authority_set_digest
    }

    /// Maximum accepted signed lifetime.
    pub const fn max_status_lifetime_seconds(self) -> u64 {
        self.max_status_lifetime_seconds
    }

    /// Exact binding persisted by the neutral production store.
    pub fn store_binding_digest(self) -> Result<Digest32> {
        self.validate()?;
        digest_parts(
            STORE_BINDING_DOMAIN_V1,
            &[
                &self.network_id,
                &self.registry_digest,
                &self.registry_epoch.to_be_bytes(),
                &self.roster_snapshot,
                &self.solver_id.0,
                &self.authority_set_digest,
                &self.max_status_lifetime_seconds.to_be_bytes(),
            ],
        )
    }
}

/// Result of installing one signed status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolverStatusInstallOutcomeV1 {
    /// A strictly newer status was appended durably.
    Installed,
    /// The exact signed status was already the durable head.
    AlreadyCurrent,
}

/// Move-only proof that one exact solver is currently active.
pub struct CurrentActiveSolverStatusV1 {
    scope_digest: Digest32,
    solver_id: ParticipantId,
    statement_digest: Digest32,
    source_evidence_digest: Digest32,
    status_epoch: u64,
    observed_at_seconds: u64,
    valid_until_seconds: u64,
    store_revision: u64,
}

/// Move-only proof plus the exact threshold-signed durable head that produced it.
///
/// F6 can use the capability for local authorization and transport the signed
/// evidence to a remote verifier without asking another component to recreate
/// or guess which status row was current at proof time.
pub struct CurrentActiveSignedSolverStatusV1 {
    capability: CurrentActiveSolverStatusV1,
    signed_head: SignedSolverStatusV1,
}

impl core::fmt::Debug for CurrentActiveSignedSolverStatusV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CurrentActiveSignedSolverStatusV1")
            .field("capability", &self.capability)
            .field("signed_head", &"[threshold evidence redacted]")
            .finish()
    }
}

impl CurrentActiveSignedSolverStatusV1 {
    /// Local move-only authorization derived from the exact signed head.
    pub const fn capability(&self) -> &CurrentActiveSolverStatusV1 {
        &self.capability
    }

    /// Exact canonical threshold-signed head suitable for remote verification.
    pub const fn signed_head(&self) -> &SignedSolverStatusV1 {
        &self.signed_head
    }

    /// Consumes the joint proof when the two downstream owners need separate values.
    pub fn into_parts(self) -> (CurrentActiveSolverStatusV1, SignedSolverStatusV1) {
        (self.capability, self.signed_head)
    }
}

impl core::fmt::Debug for CurrentActiveSolverStatusV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CurrentActiveSolverStatusV1")
            .field("solver_id", &self.solver_id)
            .field("status_epoch", &self.status_epoch)
            .field("valid_until_seconds", &self.valid_until_seconds)
            .finish_non_exhaustive()
    }
}

impl CurrentActiveSolverStatusV1 {
    /// Exact immutable store scope.
    pub const fn scope_digest(&self) -> Digest32 {
        self.scope_digest
    }

    /// Solver proven current and active.
    pub const fn solver_id(&self) -> ParticipantId {
        self.solver_id
    }

    /// Digest signed by the threshold authorities.
    pub const fn statement_digest(&self) -> Digest32 {
        self.statement_digest
    }

    /// Commitment to the underlying slashing/status sources.
    pub const fn source_evidence_digest(&self) -> Digest32 {
        self.source_evidence_digest
    }

    /// Monotonic status epoch.
    pub const fn status_epoch(&self) -> u64 {
        self.status_epoch
    }

    /// Trusted observation second.
    pub const fn observed_at_seconds(&self) -> u64 {
        self.observed_at_seconds
    }

    /// Exclusive freshness boundary.
    pub const fn valid_until_seconds(&self) -> u64 {
        self.valid_until_seconds
    }

    /// Durable journal revision from which this capability was issued.
    pub const fn store_revision(&self) -> u64 {
        self.store_revision
    }
}

/// Strict owner-only status history and capability issuer.
pub struct DurableSolverStatusStoreV1 {
    store: Store,
    config: SolverStatusStoreConfigV1,
    authorities: AuthoritySetV1,
}

impl core::fmt::Debug for DurableSolverStatusStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableSolverStatusStoreV1")
            .field("solver_id", &self.config.solver_id)
            .finish_non_exhaustive()
    }
}

impl DurableSolverStatusStoreV1 {
    /// Creates a new strict production status authority.
    pub fn create_production(
        path: &Path,
        config: SolverStatusStoreConfigV1,
        authorities: AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        validate_config_authorities(config, &authorities, secp)?;
        let binding = ProductionStoreBindingV1::new(config.store_binding_digest()?)
            .map_err(|_| SolverStatusErrorV1::Storage)?;
        let value = Self {
            store: Store::create_production(path, binding)
                .map_err(|_| SolverStatusErrorV1::Storage)?,
            config,
            authorities,
        };
        value.audit(secp)?;
        Ok(value)
    }

    /// Opens one existing strict production status authority.
    pub fn open_production(
        path: &Path,
        config: SolverStatusStoreConfigV1,
        authorities: AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        validate_config_authorities(config, &authorities, secp)?;
        let binding = ProductionStoreBindingV1::new(config.store_binding_digest()?)
            .map_err(|_| SolverStatusErrorV1::Storage)?;
        let value = Self {
            store: Store::open_production(path, binding)
                .map_err(|_| SolverStatusErrorV1::Storage)?,
            config,
            authorities,
        };
        value.audit(secp)?;
        Ok(value)
    }

    /// Resumes only a pristine create prefix authorized by an external
    /// provisioning journal.
    pub fn resume_create_production(
        path: &Path,
        config: SolverStatusStoreConfigV1,
        authorities: AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        validate_config_authorities(config, &authorities, secp)?;
        let binding = ProductionStoreBindingV1::new(config.store_binding_digest()?)
            .map_err(|_| SolverStatusErrorV1::Storage)?;
        let value = Self {
            store: Store::resume_create_production(path, binding)
                .map_err(|_| SolverStatusErrorV1::Storage)?,
            config,
            authorities,
        };
        value.audit(secp)?;
        Ok(value)
    }

    /// Immutable scope digest consumed by the F6 adapter.
    pub fn scope_digest(&self) -> Result<Digest32> {
        self.config.store_binding_digest()
    }

    /// Installs a fresh threshold-signed status, refusing rollback and
    /// same-epoch equivocation. Exact replay does not append another row.
    pub fn install(
        &mut self,
        signed: &SignedSolverStatusV1,
        secp: &SecpContext,
        trusted_now_seconds: u64,
    ) -> Result<SolverStatusInstallOutcomeV1> {
        self.advance_trusted_clock(trusted_now_seconds)?;
        let history = self.audit(secp)?;
        let statement = verify_signed(signed, &self.authorities, secp)?;
        self.validate_statement(statement)?;
        self.validate_current(statement, trusted_now_seconds)?;
        let signed_bytes = signed.canonical_bytes()?;
        if let Some(head) = history.last() {
            if statement.status_epoch < head.statement.status_epoch
                || statement.observed_at_seconds < head.statement.observed_at_seconds
            {
                return Err(SolverStatusErrorV1::Rollback);
            }
            if statement.status_epoch == head.statement.status_epoch {
                if signed_bytes == head.signed_bytes {
                    return Ok(SolverStatusInstallOutcomeV1::AlreadyCurrent);
                }
                return Err(SolverStatusErrorV1::Equivocation);
            }
        }
        if history.len() >= MAX_HISTORY_ROWS_V1 {
            return Err(SolverStatusErrorV1::BoundExceeded);
        }
        self.store
            .append_journal(STATUS_JOURNAL_KIND_V1, &signed_bytes)
            .map_err(|_| SolverStatusErrorV1::Storage)?;
        let installed = self.audit(secp)?;
        let head = installed.last().ok_or(SolverStatusErrorV1::Storage)?;
        if head.signed_bytes != signed_bytes || head.statement != statement {
            return Err(SolverStatusErrorV1::Storage);
        }
        Ok(SolverStatusInstallOutcomeV1::Installed)
    }

    /// Revalidates the complete retained history and issues a move-only active
    /// capability from its exact current head.
    pub fn prove_current_active(
        &mut self,
        secp: &SecpContext,
        trusted_now_seconds: u64,
    ) -> Result<CurrentActiveSolverStatusV1> {
        Ok(self
            .prove_current_active_signed(secp, trusted_now_seconds)?
            .capability)
    }

    /// Revalidates the retained history and returns both the move-only active
    /// capability and the exact threshold-signed head that produced it.
    ///
    /// The two values are issued from one audited snapshot after advancing the
    /// trusted-clock high-water mark. This prevents a caller from pairing a
    /// fresh local capability with stale or equivocated transport evidence.
    pub fn prove_current_active_signed(
        &mut self,
        secp: &SecpContext,
        trusted_now_seconds: u64,
    ) -> Result<CurrentActiveSignedSolverStatusV1> {
        self.advance_trusted_clock(trusted_now_seconds)?;
        let history = self.audit(secp)?;
        let head = history.last().ok_or(SolverStatusErrorV1::StaleStatus)?;
        self.validate_current(head.statement, trusted_now_seconds)?;
        if head.statement.state != SolverOperationalStateV1::Active {
            return Err(SolverStatusErrorV1::NotActive);
        }
        let capability = CurrentActiveSolverStatusV1 {
            scope_digest: self.config.store_binding_digest()?,
            solver_id: head.statement.solver_id,
            statement_digest: head.statement.statement_digest()?,
            source_evidence_digest: head.statement.source_evidence_digest,
            status_epoch: head.statement.status_epoch,
            observed_at_seconds: head.statement.observed_at_seconds,
            valid_until_seconds: head.statement.valid_until_seconds,
            store_revision: u64::try_from(history.len())
                .map_err(|_| SolverStatusErrorV1::BoundExceeded)?,
        };
        let signed_head = SignedSolverStatusV1::decode(&head.signed_bytes)?;
        if signed_head.statement()?.statement_digest()? != capability.statement_digest {
            return Err(SolverStatusErrorV1::Storage);
        }
        Ok(CurrentActiveSignedSolverStatusV1 {
            capability,
            signed_head,
        })
    }

    fn advance_trusted_clock(&mut self, trusted_now_seconds: u64) -> Result<()> {
        match self
            .store
            .record_monotonic_high_water(TRUSTED_CLOCK_ENTITY_V1, trusted_now_seconds)
        {
            Ok(_) => Ok(()),
            Err(StoreError::RevisionConflict) => Err(SolverStatusErrorV1::ClockRollback),
            Err(_) => Err(SolverStatusErrorV1::Storage),
        }
    }

    fn audit(&self, secp: &SecpContext) -> Result<Vec<RetainedStatusV1>> {
        validate_config_authorities(self.config, &self.authorities, secp)?;
        let rows = self
            .store
            .read_journal()
            .map_err(|_| SolverStatusErrorV1::Storage)?;
        if rows.len() > MAX_HISTORY_ROWS_V1 {
            return Err(SolverStatusErrorV1::BoundExceeded);
        }
        let mut retained: Vec<RetainedStatusV1> = Vec::with_capacity(rows.len());
        for row in rows {
            if row.kind != STATUS_JOURNAL_KIND_V1 || row.payload.len() > MAX_SIGNED_BYTES_V1 {
                return Err(SolverStatusErrorV1::Storage);
            }
            let signed = SignedSolverStatusV1::decode(&row.payload)?;
            let statement = verify_signed(&signed, &self.authorities, secp)?;
            self.validate_statement(statement)?;
            if let Some(previous) = retained.last() {
                if statement.status_epoch <= previous.statement.status_epoch
                    || statement.observed_at_seconds < previous.statement.observed_at_seconds
                {
                    return Err(SolverStatusErrorV1::Storage);
                }
            }
            retained.push(RetainedStatusV1 {
                statement,
                signed_bytes: row.payload,
            });
        }
        Ok(retained)
    }

    fn validate_statement(&self, statement: SolverStatusStatementV1) -> Result<()> {
        statement.validate_shape()?;
        if statement.network_id != self.config.network_id
            || statement.registry_digest != self.config.registry_digest
            || statement.registry_epoch != self.config.registry_epoch
            || statement.roster_snapshot != self.config.roster_snapshot
            || statement.solver_id != self.config.solver_id
        {
            return Err(SolverStatusErrorV1::ScopeMismatch);
        }
        let lifetime = statement
            .valid_until_seconds
            .checked_sub(statement.observed_at_seconds)
            .ok_or(SolverStatusErrorV1::Arithmetic)?;
        if lifetime > self.config.max_status_lifetime_seconds {
            return Err(SolverStatusErrorV1::StaleStatus);
        }
        Ok(())
    }

    fn validate_current(
        &self,
        statement: SolverStatusStatementV1,
        trusted_now_seconds: u64,
    ) -> Result<()> {
        if trusted_now_seconds == 0
            || statement.observed_at_seconds > trusted_now_seconds
            || trusted_now_seconds >= statement.valid_until_seconds
        {
            return Err(SolverStatusErrorV1::StaleStatus);
        }
        Ok(())
    }
}

struct RetainedStatusV1 {
    statement: SolverStatusStatementV1,
    signed_bytes: Vec<u8>,
}

fn validate_config_authorities(
    config: SolverStatusStoreConfigV1,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<()> {
    config.validate()?;
    if authority_set_digest(authorities, secp)? != config.authority_set_digest {
        return Err(SolverStatusErrorV1::InvalidAuthoritySet);
    }
    Ok(())
}

fn verify_signed(
    signed: &SignedSolverStatusV1,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<SolverStatusStatementV1> {
    validate_authorities(authorities, secp)?;
    validate_signature_shape(&signed.signatures)?;
    let statement = signed.statement()?;
    let digest = statement.statement_digest()?;
    for signature in &signed.signatures {
        let key = authorities
            .xonly_keys()
            .get(usize::from(signature.signer_index))
            .ok_or(SolverStatusErrorV1::InvalidSignature)?;
        secp.verify_bip340(key, &digest, &signature.signature)
            .map_err(|_| SolverStatusErrorV1::InvalidSignature)?;
    }
    if signed.signatures.len() < usize::from(authorities.threshold()) {
        return Err(SolverStatusErrorV1::ThresholdNotMet);
    }
    Ok(statement)
}

fn authority_set_digest(authorities: &AuthoritySetV1, secp: &SecpContext) -> Result<Digest32> {
    validate_authorities(authorities, secp)?;
    let bytes = authorities
        .canonical_bytes()
        .map_err(|_| SolverStatusErrorV1::InvalidAuthoritySet)?;
    digest_parts(AUTHORITY_SET_DOMAIN_V1, &[&bytes])
}

fn validate_authorities(authorities: &AuthoritySetV1, secp: &SecpContext) -> Result<()> {
    if authorities.xonly_keys().is_empty()
        || authorities.xonly_keys().len() > MAX_AUTHORITIES_V1
        || authorities.threshold() == 0
        || usize::from(authorities.threshold()) > authorities.xonly_keys().len()
    {
        return Err(SolverStatusErrorV1::InvalidAuthoritySet);
    }
    authorities
        .validate_with_context(secp)
        .map_err(|_| SolverStatusErrorV1::InvalidAuthoritySet)
}

fn validate_signature_shape(signatures: &[SolverStatusSignatureV1]) -> Result<()> {
    if signatures.is_empty() || signatures.len() > MAX_AUTHORITIES_V1 {
        return Err(SolverStatusErrorV1::BoundExceeded);
    }
    let mut previous = None;
    for signature in signatures {
        if previous.is_some_and(|index| index >= signature.signer_index) {
            return Err(SolverStatusErrorV1::InvalidSignature);
        }
        previous = Some(signature.signer_index);
    }
    Ok(())
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32> {
    let mut state = Blake2bVar::new(32).map_err(|_| SolverStatusErrorV1::Arithmetic)?;
    state.update(domain);
    for part in parts {
        state.update(part);
    }
    let mut digest = [0; 32];
    state
        .finalize_variable(&mut digest)
        .map_err(|_| SolverStatusErrorV1::Arithmetic)?;
    if digest == ZERO_DIGEST {
        return Err(SolverStatusErrorV1::Arithmetic);
    }
    Ok(digest)
}

fn take_slice<'a>(bytes: &'a [u8], cursor: &mut usize, count: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(count)
        .ok_or(SolverStatusErrorV1::Arithmetic)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(SolverStatusErrorV1::InvalidEncoding)?;
    *cursor = end;
    Ok(value)
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    let value = *bytes
        .get(*cursor)
        .ok_or(SolverStatusErrorV1::InvalidEncoding)?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(SolverStatusErrorV1::Arithmetic)?;
    Ok(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    let raw: [u8; 2] = take_slice(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| SolverStatusErrorV1::InvalidEncoding)?;
    Ok(u16::from_be_bytes(raw))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let raw: [u8; 4] = take_slice(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| SolverStatusErrorV1::InvalidEncoding)?;
    Ok(u32::from_be_bytes(raw))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let raw: [u8; 8] = take_slice(bytes, cursor, 8)?
        .try_into()
        .map_err(|_| SolverStatusErrorV1::InvalidEncoding)?;
    Ok(u64::from_be_bytes(raw))
}

fn take_32(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32]> {
    take_slice(bytes, cursor, 32)?
        .try_into()
        .map_err(|_| SolverStatusErrorV1::InvalidEncoding)
}

fn take_64(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 64]> {
    take_slice(bytes, cursor, 64)?
        .try_into()
        .map_err(|_| SolverStatusErrorV1::InvalidEncoding)
}

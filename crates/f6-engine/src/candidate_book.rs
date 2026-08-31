//! Threshold-authenticated remote bond reservations and durable F6 V2
//! candidate books.
//!
//! This module never treats a solver-signed quote as proof that collateral is
//! exclusively reserved. Remote candidates enter the book only after an
//! independent threshold authority signs the exact reservation scope.

use std::collections::BTreeMap;
use std::path::Path;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use kaystra_core::types::Digest32;
use relay::auth::{verify_roster_signature, RosterRegistryV1};
use relay::SenderRoleV1;
use rfq::selection::{CandidateFactsV1, MAX_CANDIDATES};
use rfq::v2::{QuoteV2, SettlementPositionV2};
use rfq::ParticipantId;
use solver_status::{SignedSolverStatusV1, SolverOperationalStateV1, SolverStatusStatementV1};

use crate::{BindingLog, EngineError};

const ZERO_DIGEST: Digest32 = [0; 32];
const ATTESTATION_MAGIC: &[u8; 8] = b"DOMBRAV2";
const SIGNED_MAGIC: &[u8; 8] = b"DOMBRAS2";
const DELIVERY_MAGIC: &[u8; 8] = b"DOMCQDV2";
const FRAME_MAGIC: &[u8; 8] = b"DOMCBKV2";
const VERSION: u16 = 2;
const ATTESTATION_DOMAIN: &[u8] = b"DOM-INTEROP/F6/BOND-RESERVATION-ATTESTATION/V2\0";
const AUTHORITY_SET_DOMAIN: &[u8] = b"DOM-INTEROP/F6/BOND-ATTESTATION-AUTHORITY-SET/V2\0";
const STATUS_AUTHORITY_SET_DOMAIN: &[u8] = b"DOM-INTEROP/F6/SOLVER-STATUS-AUTHORITY-SET/V2\0";
const BOOK_BINDING_DOMAIN: &[u8] = b"DOM-INTEROP/F6/CANDIDATE-BOOK/V2\0";
const CANDIDATE_AUTHORITY_DOMAIN: &[u8] = b"DOM-INTEROP/F6/CANDIDATE-AUTHORITY/V2\0";
const BOOK_JOURNAL_KIND: u16 = 0xF603;
const MAX_AUTHORITIES: usize = 16;
const MAX_BOOK_HISTORY: usize = 4_096;
const MAX_RECOVERY_HISTORY: usize = 256;
const MAX_ATTESTATION_LIFETIME_SECONDS: u64 = 300;
const ATTESTATION_BYTES: usize = 8 + 2 + 32 * 13 + 1 + 8 * 6 + 16 * 2;
const SIGNATURE_BYTES: usize = 2 + 64;
const MAX_SIGNED_BYTES: usize =
    8 + 2 + 4 + ATTESTATION_BYTES + 2 + MAX_AUTHORITIES * SIGNATURE_BYTES;
const MAX_STATUS_BYTES: usize = 2_048;
const MAX_DELIVERY_BYTES: usize = 8 + 2 + 4 + 4_096 + 4 + MAX_SIGNED_BYTES + 4 + MAX_STATUS_BYTES;
const MAX_FRAME_BYTES: usize = 8 + 2 + 8 + 4 + MAX_DELIVERY_BYTES;

/// Fail-closed remote candidate admission errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CandidateBookErrorV2 {
    /// A scope field, amount, validity interval or quote binding is invalid.
    #[error("invalid F6 V2 bond reservation attestation")]
    InvalidAttestation,
    /// Canonical bytes are malformed, alternate or have a trailing suffix.
    #[error("noncanonical F6 V2 bond reservation encoding")]
    NonCanonical,
    /// Threshold authority set or signature is invalid.
    #[error("invalid F6 V2 bond reservation authority")]
    InvalidAuthority,
    /// Too few independent authorities signed the exact attestation.
    #[error("F6 V2 bond reservation threshold not met")]
    ThresholdNotMet,
    /// Attestation is not current at the trusted production observation.
    #[error("F6 V2 bond reservation attestation stale")]
    Stale,
    /// Candidate belongs to another composition, position, RFQ or registry.
    #[error("F6 V2 candidate scope mismatch")]
    ScopeMismatch,
    /// Solver is absent from the exact roster or its quote signature is invalid.
    #[error("F6 V2 candidate solver identity invalid")]
    SolverIdentity,
    /// Same solver, quote or reservation was presented with different bytes.
    #[error("F6 V2 candidate equivocation")]
    Equivocation,
    /// Candidate or journal bound was exceeded.
    #[error("F6 V2 candidate bound exceeded")]
    BoundExceeded,
    /// Append/replay/storage authority failed closed.
    #[error("F6 V2 candidate book unavailable or inconsistent")]
    Storage,
    /// Digest or checked arithmetic failed.
    #[error("F6 V2 candidate arithmetic failure")]
    Arithmetic,
}

/// Immutable scope shared by every candidate of one RFQ position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateBookScopeV2 {
    /// Deployment network.
    pub network_id: Digest32,
    /// Linked route composition.
    pub composition_id: Digest32,
    /// Upstream/downstream position.
    pub position: SettlementPositionV2,
    /// Exact RFQ.
    pub rfq_id: Digest32,
    /// Relay roster snapshot.
    pub roster_snapshot: Digest32,
    /// Exact F4 assurance policy.
    pub bond_policy_hash: Digest32,
    /// Authenticated registry manifest.
    pub registry_digest: Digest32,
    /// Monotonic registry epoch.
    pub registry_epoch: u64,
    /// Exact collateral asset/unit binding.
    pub bond_asset_binding_digest: Digest32,
    /// Exact required collateral from the authenticated F4 policy.
    pub required_collateral: u128,
    /// Threshold attestation authority-set digest.
    pub authority_set_digest: Digest32,
    /// Independent solver-status threshold authority-set digest.
    pub status_authority_set_digest: Digest32,
}

impl CandidateBookScopeV2 {
    /// Validates every immutable pin.
    pub fn validate(self) -> Result<(), CandidateBookErrorV2> {
        if [
            self.network_id,
            self.composition_id,
            self.rfq_id,
            self.roster_snapshot,
            self.bond_policy_hash,
            self.registry_digest,
            self.bond_asset_binding_digest,
            self.authority_set_digest,
            self.status_authority_set_digest,
        ]
        .contains(&ZERO_DIGEST)
            || self.registry_epoch == 0
            || self.required_collateral == 0
        {
            return Err(CandidateBookErrorV2::ScopeMismatch);
        }
        Ok(())
    }

    /// Domain-separated store binding.
    pub fn binding_digest(self) -> Result<Digest32, CandidateBookErrorV2> {
        self.validate()?;
        digest_parts(BOOK_BINDING_DOMAIN, &[&encode_scope(self)])
    }
}

/// Computes the domain-separated pin for the independent bond authority set.
pub fn bond_reservation_authority_set_digest_v2(
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<Digest32, CandidateBookErrorV2> {
    validate_authority_set_shape(authorities, secp)?;
    digest_parts(
        AUTHORITY_SET_DOMAIN,
        &[&authorities
            .canonical_bytes()
            .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?],
    )
}

/// Computes the domain-separated pin for the independent status authority set.
pub fn candidate_status_authority_set_digest_v2(
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<Digest32, CandidateBookErrorV2> {
    validate_authority_set_shape(authorities, secp)?;
    digest_parts(
        STATUS_AUTHORITY_SET_DOMAIN,
        &[&authorities
            .canonical_bytes()
            .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?],
    )
}

/// Public facts independently attested about one remote quote reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BondReservationAttestationRequestV2 {
    /// Deployment network.
    pub network_id: Digest32,
    /// Linked composition.
    pub composition_id: Digest32,
    /// Settlement position.
    pub position: SettlementPositionV2,
    /// Exact RFQ.
    pub rfq_id: Digest32,
    /// Exact quote.
    pub quote_id: Digest32,
    /// Solver holding collateral.
    pub solver: ParticipantId,
    /// Exclusive reservation identifier.
    pub reservation_id: Digest32,
    /// F4 policy commitment.
    pub bond_policy_hash: Digest32,
    /// Registry manifest.
    pub registry_digest: Digest32,
    /// Registry epoch.
    pub registry_epoch: u64,
    /// Commitment to the exact collateral asset/unit definition.
    pub bond_asset_binding_digest: Digest32,
    /// Required collateral under the F4 policy.
    pub required_collateral: u128,
    /// Amount independently proven exclusively reserved.
    pub reserved_collateral: u128,
    /// Durable remote inventory/reservation state commitment.
    pub reservation_state_digest: Digest32,
    /// Chain/on-chain/observer source evidence commitment.
    pub source_evidence_digest: Digest32,
    /// Threshold-authenticated active solver-status statement.
    pub solver_status_statement_digest: Digest32,
    /// Monotonic solver status epoch.
    pub solver_status_epoch: u64,
    /// Exclusive solver-status validity boundary.
    pub solver_status_valid_until_seconds: u64,
    /// Observation time.
    pub observed_at_seconds: u64,
    /// Exclusive attestation validity boundary.
    pub valid_until_seconds: u64,
    /// Monotonic attestation sequence for this reservation.
    pub sequence: u64,
    /// Previous attestation digest, zero only at sequence one.
    pub previous_attestation_digest: Digest32,
}

/// Exact threshold-signed remote reservation statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BondReservationAttestationV2 {
    request: BondReservationAttestationRequestV2,
}

impl BondReservationAttestationV2 {
    /// Validates and freezes a complete attestation.
    pub fn new(request: BondReservationAttestationRequestV2) -> Result<Self, CandidateBookErrorV2> {
        let value = Self { request };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(self) -> Result<(), CandidateBookErrorV2> {
        let value = self.request;
        if [
            value.network_id,
            value.composition_id,
            value.rfq_id,
            value.quote_id,
            value.solver.0,
            value.reservation_id,
            value.bond_policy_hash,
            value.registry_digest,
            value.bond_asset_binding_digest,
            value.reservation_state_digest,
            value.source_evidence_digest,
            value.solver_status_statement_digest,
        ]
        .contains(&ZERO_DIGEST)
            || value.registry_epoch == 0
            || value.required_collateral == 0
            || value.reserved_collateral < value.required_collateral
            || value.solver_status_epoch == 0
            || value.observed_at_seconds == 0
            || value.observed_at_seconds >= value.valid_until_seconds
            || value.valid_until_seconds > value.solver_status_valid_until_seconds
            || value.sequence == 0
            || (value.sequence == 1 && value.previous_attestation_digest != ZERO_DIGEST)
            || (value.sequence > 1 && value.previous_attestation_digest == ZERO_DIGEST)
        {
            return Err(CandidateBookErrorV2::InvalidAttestation);
        }
        let lifetime = value
            .valid_until_seconds
            .checked_sub(value.observed_at_seconds)
            .ok_or(CandidateBookErrorV2::Arithmetic)?;
        if lifetime > MAX_ATTESTATION_LIFETIME_SECONDS {
            return Err(CandidateBookErrorV2::InvalidAttestation);
        }
        Ok(())
    }

    /// Canonical V2 attestation bytes.
    pub fn canonical_bytes(self) -> Result<Vec<u8>, CandidateBookErrorV2> {
        self.validate_shape()?;
        let mut output = Vec::with_capacity(ATTESTATION_BYTES);
        output.extend_from_slice(ATTESTATION_MAGIC);
        output.extend_from_slice(&VERSION.to_be_bytes());
        put_request(&mut output, self.request);
        if output.len() != ATTESTATION_BYTES {
            return Err(CandidateBookErrorV2::Arithmetic);
        }
        Ok(output)
    }

    /// Strict canonical decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, CandidateBookErrorV2> {
        if bytes.len() != ATTESTATION_BYTES || bytes.get(..8) != Some(ATTESTATION_MAGIC.as_slice())
        {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        let mut cursor = Cursor::new(bytes);
        cursor.take(8)?;
        if cursor.u16()? != VERSION {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        let value = Self::new(take_request(&mut cursor)?)?;
        cursor.finish()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        Ok(value)
    }

    /// Digest signed by independent reservation authorities.
    pub fn attestation_digest(self) -> Result<Digest32, CandidateBookErrorV2> {
        digest_parts(ATTESTATION_DOMAIN, &[&self.canonical_bytes()?])
    }

    /// Public request facts.
    pub const fn request(self) -> BondReservationAttestationRequestV2 {
        self.request
    }
}

/// One ordered threshold signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BondReservationSignatureV2 {
    /// Index in the pinned authority set.
    pub signer_index: u16,
    /// BIP340 signature over the attestation digest.
    pub signature: [u8; 64],
}

/// Canonical attestation plus threshold signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBondReservationAttestationV2 {
    attestation_bytes: Vec<u8>,
    signatures: Vec<BondReservationSignatureV2>,
}

impl SignedBondReservationAttestationV2 {
    /// Wraps canonical bytes and a strictly ordered signature set.
    pub fn new(
        attestation: BondReservationAttestationV2,
        signatures: Vec<BondReservationSignatureV2>,
    ) -> Result<Self, CandidateBookErrorV2> {
        validate_signature_shape(&signatures)?;
        Ok(Self {
            attestation_bytes: attestation.canonical_bytes()?,
            signatures,
        })
    }

    /// Decoded public statement covered by the signatures.
    pub fn attestation(&self) -> Result<BondReservationAttestationV2, CandidateBookErrorV2> {
        BondReservationAttestationV2::decode(&self.attestation_bytes)
    }

    /// Canonical signed wire bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CandidateBookErrorV2> {
        validate_signature_shape(&self.signatures)?;
        let count = u16::try_from(self.signatures.len())
            .map_err(|_| CandidateBookErrorV2::BoundExceeded)?;
        let mut output = Vec::with_capacity(MAX_SIGNED_BYTES.min(
            8 + 2 + 4 + self.attestation_bytes.len() + 2 + self.signatures.len() * SIGNATURE_BYTES,
        ));
        output.extend_from_slice(SIGNED_MAGIC);
        output.extend_from_slice(&VERSION.to_be_bytes());
        output.extend_from_slice(
            &u32::try_from(self.attestation_bytes.len())
                .map_err(|_| CandidateBookErrorV2::BoundExceeded)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&self.attestation_bytes);
        output.extend_from_slice(&count.to_be_bytes());
        for signature in &self.signatures {
            output.extend_from_slice(&signature.signer_index.to_be_bytes());
            output.extend_from_slice(&signature.signature);
        }
        if output.len() > MAX_SIGNED_BYTES {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        Ok(output)
    }

    /// Strict signed decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, CandidateBookErrorV2> {
        if bytes.len() > MAX_SIGNED_BYTES || bytes.get(..8) != Some(SIGNED_MAGIC.as_slice()) {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        let mut cursor = Cursor::new(bytes);
        cursor.take(8)?;
        if cursor.u16()? != VERSION
            || usize::try_from(cursor.u32()?).map_err(|_| CandidateBookErrorV2::BoundExceeded)?
                != ATTESTATION_BYTES
        {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        let attestation_bytes = cursor.take(ATTESTATION_BYTES)?.to_vec();
        BondReservationAttestationV2::decode(&attestation_bytes)?;
        let count = usize::from(cursor.u16()?);
        if count == 0 || count > MAX_AUTHORITIES {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(BondReservationSignatureV2 {
                signer_index: cursor.u16()?,
                signature: cursor.array()?,
            });
        }
        cursor.finish()?;
        let value = Self {
            attestation_bytes,
            signatures,
        };
        validate_signature_shape(&value.signatures)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        Ok(value)
    }
}

/// Move-only result of threshold verification.
pub struct VerifiedBondReservationAttestationV2 {
    attestation: BondReservationAttestationV2,
    digest: Digest32,
}

/// Move-only proof that both independent threshold authorities authenticated
/// the exact quote candidate.
pub struct VerifiedCandidateDeliveryV2 {
    bond: VerifiedBondReservationAttestationV2,
    status: SolverStatusStatementV1,
}

impl core::fmt::Debug for VerifiedBondReservationAttestationV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedBondReservationAttestationV2([authority redacted])")
    }
}

impl VerifiedBondReservationAttestationV2 {
    /// Exact threshold-authenticated public facts.
    pub const fn attestation(&self) -> BondReservationAttestationV2 {
        self.attestation
    }

    /// Exact signed attestation digest.
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }
}

/// Verifies independent threshold authority, exact quote scope and freshness.
pub fn verify_bond_reservation_attestation_v2(
    signed: &SignedBondReservationAttestationV2,
    quote: &QuoteV2,
    scope: CandidateBookScopeV2,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
    trusted_now_seconds: u64,
) -> Result<VerifiedBondReservationAttestationV2, CandidateBookErrorV2> {
    validate_authorities(scope, authorities, secp)?;
    let bytes = signed.canonical_bytes()?;
    let reparsed = SignedBondReservationAttestationV2::decode(&bytes)?;
    let attestation = BondReservationAttestationV2::decode(&reparsed.attestation_bytes)?;
    let digest = attestation.attestation_digest()?;
    for signature in &reparsed.signatures {
        let key = authorities
            .xonly_keys()
            .get(usize::from(signature.signer_index))
            .ok_or(CandidateBookErrorV2::InvalidAuthority)?;
        secp.verify_bip340(key, &digest, &signature.signature)
            .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?;
    }
    if reparsed.signatures.len() < usize::from(authorities.threshold()) {
        return Err(CandidateBookErrorV2::ThresholdNotMet);
    }
    let request = attestation.request;
    quote
        .validate()
        .map_err(|_| CandidateBookErrorV2::InvalidAttestation)?;
    if request.network_id != scope.network_id
        || request.composition_id != scope.composition_id
        || request.position != scope.position
        || request.rfq_id != scope.rfq_id
        || request.quote_id != quote.quote_id
        || request.solver != quote.solver
        || request.reservation_id != quote.bond_reservation_id
        || request.bond_policy_hash != scope.bond_policy_hash
        || request.registry_digest != scope.registry_digest
        || request.registry_epoch != scope.registry_epoch
        || request.bond_asset_binding_digest != scope.bond_asset_binding_digest
        || request.required_collateral != scope.required_collateral
    {
        return Err(CandidateBookErrorV2::ScopeMismatch);
    }
    if trusted_now_seconds == 0
        || request.observed_at_seconds > trusted_now_seconds
        || trusted_now_seconds >= request.valid_until_seconds
    {
        return Err(CandidateBookErrorV2::Stale);
    }
    Ok(VerifiedBondReservationAttestationV2 {
        attestation,
        digest,
    })
}

/// Result of one append-before-selection admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateAdmissionOutcomeV2 {
    /// New candidate was durably appended.
    Admitted,
    /// Exact canonical candidate was already present.
    AlreadyAdmitted,
}

/// Borrowed verifier bundle for one candidate-book operation. It contains no
/// evidence and cannot mint an admission capability.
pub struct CandidateVerificationAuthoritiesV2<'authority> {
    bond: &'authority AuthoritySetV1,
    status: &'authority AuthoritySetV1,
    secp: &'authority SecpContext,
    rosters: &'authority RosterRegistryV1,
}

impl<'authority> CandidateVerificationAuthoritiesV2<'authority> {
    /// Bundles the four independently pinned verification authorities.
    pub fn new(
        bond: &'authority AuthoritySetV1,
        status: &'authority AuthoritySetV1,
        secp: &'authority SecpContext,
        rosters: &'authority RosterRegistryV1,
    ) -> Self {
        Self {
            bond,
            status,
            secp,
            rosters,
        }
    }
}

impl core::fmt::Debug for CandidateVerificationAuthoritiesV2<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CandidateVerificationAuthoritiesV2([authorities redacted])")
    }
}

/// Canonical remote quote delivery. A quote without an independently signed
/// reservation attestation is never a production candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateQuoteDeliveryV2 {
    quote: QuoteV2,
    attestation: SignedBondReservationAttestationV2,
    status: SignedSolverStatusV1,
}

impl CandidateQuoteDeliveryV2 {
    /// Freezes one exact quote and its threshold reservation proof.
    pub fn new(
        quote: QuoteV2,
        attestation: SignedBondReservationAttestationV2,
        status: SignedSolverStatusV1,
    ) -> Result<Self, CandidateBookErrorV2> {
        quote
            .validate()
            .map_err(|_| CandidateBookErrorV2::InvalidAttestation)?;
        let value = Self {
            quote,
            attestation,
            status,
        };
        value.canonical_bytes()?;
        Ok(value)
    }

    /// Exact quote.
    pub const fn quote(&self) -> QuoteV2 {
        self.quote
    }

    /// Independent threshold-signed reservation proof.
    pub const fn attestation(&self) -> &SignedBondReservationAttestationV2 {
        &self.attestation
    }

    /// Independent threshold-signed operational status.
    pub const fn status(&self) -> &SignedSolverStatusV1 {
        &self.status
    }

    /// Canonical V2 delivery bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CandidateBookErrorV2> {
        let quote = self
            .quote
            .canonical_bytes()
            .map_err(|_| CandidateBookErrorV2::InvalidAttestation)?;
        let attestation = self.attestation.canonical_bytes()?;
        let status = self
            .status
            .canonical_bytes()
            .map_err(|_| CandidateBookErrorV2::SolverIdentity)?;
        let mut output =
            Vec::with_capacity(8 + 2 + 4 + quote.len() + 4 + attestation.len() + 4 + status.len());
        output.extend_from_slice(DELIVERY_MAGIC);
        output.extend_from_slice(&VERSION.to_be_bytes());
        output.extend_from_slice(
            &u32::try_from(quote.len())
                .map_err(|_| CandidateBookErrorV2::BoundExceeded)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&quote);
        output.extend_from_slice(
            &u32::try_from(attestation.len())
                .map_err(|_| CandidateBookErrorV2::BoundExceeded)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&attestation);
        output.extend_from_slice(
            &u32::try_from(status.len())
                .map_err(|_| CandidateBookErrorV2::BoundExceeded)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&status);
        if output.len() > MAX_DELIVERY_BYTES {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        Ok(output)
    }

    /// Strict decoder rejects alternate or trailing encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, CandidateBookErrorV2> {
        if bytes.len() > MAX_DELIVERY_BYTES || bytes.get(..8) != Some(DELIVERY_MAGIC.as_slice()) {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        let mut cursor = Cursor::new(bytes);
        cursor.take(8)?;
        if cursor.u16()? != VERSION {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        let quote_len =
            usize::try_from(cursor.u32()?).map_err(|_| CandidateBookErrorV2::BoundExceeded)?;
        let quote = QuoteV2::decode(cursor.take(quote_len)?)
            .map_err(|_| CandidateBookErrorV2::NonCanonical)?;
        let attestation_len =
            usize::try_from(cursor.u32()?).map_err(|_| CandidateBookErrorV2::BoundExceeded)?;
        let attestation =
            SignedBondReservationAttestationV2::decode(cursor.take(attestation_len)?)?;
        let status_len =
            usize::try_from(cursor.u32()?).map_err(|_| CandidateBookErrorV2::BoundExceeded)?;
        if status_len > MAX_STATUS_BYTES {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        let status = SignedSolverStatusV1::decode(cursor.take(status_len)?)
            .map_err(|_| CandidateBookErrorV2::NonCanonical)?;
        cursor.finish()?;
        let value = Self::new(quote, attestation, status)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(CandidateBookErrorV2::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Clone)]
struct CandidateRecordV2 {
    quote: QuoteV2,
    attestation: BondReservationAttestationV2,
    attestation_digest: Digest32,
    status: SolverStatusStatementV1,
    delivery_bytes: Vec<u8>,
}

/// Move-only, arrival-independent candidate set issued from durable replay.
pub struct CandidateBookCapabilityV2 {
    scope: CandidateBookScopeV2,
    candidates: Vec<(QuoteV2, CandidateFactsV1)>,
    inputs_digest: Digest32,
    revision: u64,
}

impl core::fmt::Debug for CandidateBookCapabilityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CandidateBookCapabilityV2")
            .field("candidate_count", &self.candidates.len())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl CandidateBookCapabilityV2 {
    /// Exact RFQ scope.
    pub const fn scope(&self) -> CandidateBookScopeV2 {
        self.scope
    }

    /// Canonically quote-id-sorted admissible candidates.
    pub fn candidates(&self) -> &[(QuoteV2, CandidateFactsV1)] {
        &self.candidates
    }

    /// Arrival-independent candidate-set digest.
    pub const fn inputs_digest(&self) -> Digest32 {
        self.inputs_digest
    }

    /// Durable book revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Durable remote candidate book. Every frame contains the complete signed
/// attestation, so restart re-verifies signatures rather than trusting rows.
pub struct DurableCandidateBookV2<L: BindingLog> {
    log: L,
    scope: CandidateBookScopeV2,
    records: BTreeMap<Digest32, CandidateRecordV2>,
    by_solver: BTreeMap<ParticipantId, Digest32>,
    by_reservation: BTreeMap<Digest32, Digest32>,
    revision: u64,
}

impl<L: BindingLog> DurableCandidateBookV2<L> {
    /// Replays a complete book, threshold-verifying every historical frame.
    pub fn open(
        log: L,
        scope: CandidateBookScopeV2,
        authorities: &CandidateVerificationAuthoritiesV2<'_>,
    ) -> Result<Self, CandidateBookErrorV2> {
        validate_authorities(scope, authorities.bond, authorities.secp)?;
        validate_status_authorities(scope, authorities.status, authorities.secp)?;
        let frames = log.frames().map_err(|_| CandidateBookErrorV2::Storage)?;
        if frames.len() > MAX_BOOK_HISTORY {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        let mut value = Self {
            log,
            scope,
            records: BTreeMap::new(),
            by_solver: BTreeMap::new(),
            by_reservation: BTreeMap::new(),
            revision: 0,
        };
        for frame in frames {
            let (revision, delivery) = decode_frame(&frame)?;
            if revision != value.revision {
                return Err(CandidateBookErrorV2::Storage);
            }
            let verified = verify_without_freshness(
                &delivery,
                scope,
                authorities.bond,
                authorities.status,
                authorities.secp,
            )?;
            validate_roster_quote(scope, &delivery.quote, authorities.rosters)?;
            value.apply_replayed(delivery, verified)?;
            value.revision = value
                .revision
                .checked_add(1)
                .ok_or(CandidateBookErrorV2::Arithmetic)?;
        }
        Ok(value)
    }

    /// Verifies then appends a remote candidate before exposing it.
    pub fn admit_remote(
        &mut self,
        delivery: &CandidateQuoteDeliveryV2,
        authorities: &CandidateVerificationAuthoritiesV2<'_>,
        trusted_now_seconds: u64,
    ) -> Result<CandidateAdmissionOutcomeV2, CandidateBookErrorV2> {
        let quote = delivery.quote;
        validate_roster_quote(self.scope, &quote, authorities.rosters)?;
        let verified = verify_candidate_quote_delivery_v2(
            delivery,
            self.scope,
            authorities.bond,
            authorities.status,
            authorities.secp,
            trusted_now_seconds,
        )?;
        let delivery_bytes = delivery.canonical_bytes()?;
        let frame = encode_frame(self.revision, delivery)?;
        if let Some(existing) = self.records.get(&quote.quote_id) {
            if existing.delivery_bytes == delivery_bytes {
                return Ok(CandidateAdmissionOutcomeV2::AlreadyAdmitted);
            }
            validate_refresh(existing, &verified)?;
        } else {
            if verified.bond.attestation.request.sequence != 1
                || verified
                    .bond
                    .attestation
                    .request
                    .previous_attestation_digest
                    != ZERO_DIGEST
            {
                return Err(CandidateBookErrorV2::Equivocation);
            }
            self.ensure_unique(&quote)?;
            if self.records.len() >= MAX_CANDIDATES {
                return Err(CandidateBookErrorV2::BoundExceeded);
            }
        }
        if usize::try_from(self.revision).map_err(|_| CandidateBookErrorV2::BoundExceeded)?
            >= MAX_BOOK_HISTORY
        {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        self.log
            .append_frame(&frame)
            .map_err(|_| CandidateBookErrorV2::Storage)?;
        self.insert_or_refresh(delivery.clone(), verified)?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(CandidateBookErrorV2::Arithmetic)?;
        Ok(CandidateAdmissionOutcomeV2::Admitted)
    }

    /// Recovers a complete signed revision chain after a caller-side crash.
    ///
    /// Historical predecessors are threshold/roster verified at their own
    /// observation time, but are never resurrected as current. The final
    /// supplied head alone must pass freshness at `trusted_now_seconds` before
    /// any missing frame is appended. Existing exact prefixes replay
    /// idempotently; gaps, forks and truncated predecessors fail closed.
    pub fn recover_signed_history(
        &mut self,
        history: &[CandidateQuoteDeliveryV2],
        authorities: &CandidateVerificationAuthoritiesV2<'_>,
        trusted_now_seconds: u64,
    ) -> Result<(), CandidateBookErrorV2> {
        if history.is_empty() || history.len() > MAX_RECOVERY_HISTORY {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        let quote = history[0].quote;
        let mut verified = Vec::with_capacity(history.len());
        let mut delivery_bytes = Vec::with_capacity(history.len());
        for delivery in history {
            if delivery.quote != quote {
                return Err(CandidateBookErrorV2::Equivocation);
            }
            validate_roster_quote(self.scope, &delivery.quote, authorities.rosters)?;
            verified.push(verify_without_freshness(
                delivery,
                self.scope,
                authorities.bond,
                authorities.status,
                authorities.secp,
            )?);
            delivery_bytes.push(delivery.canonical_bytes()?);
        }
        let first_request = verified[0].bond.attestation.request;
        if first_request.sequence != 1 || first_request.previous_attestation_digest != ZERO_DIGEST {
            return Err(CandidateBookErrorV2::Equivocation);
        }
        let mut previous = recovery_record(&history[0], &verified[0])?;
        for (delivery, next) in history.iter().zip(verified.iter()).skip(1) {
            validate_refresh(&previous, next)?;
            previous = recovery_record(delivery, next)?;
        }
        verify_candidate_quote_delivery_v2(
            history.last().ok_or(CandidateBookErrorV2::BoundExceeded)?,
            self.scope,
            authorities.bond,
            authorities.status,
            authorities.secp,
            trusted_now_seconds,
        )?;

        let missing_from = match self.records.get(&quote.quote_id) {
            Some(existing) => delivery_bytes
                .iter()
                .position(|bytes| bytes == &existing.delivery_bytes)
                .ok_or(CandidateBookErrorV2::Equivocation)?
                .checked_add(1)
                .ok_or(CandidateBookErrorV2::Arithmetic)?,
            None => {
                self.ensure_unique(&quote)?;
                if self.records.len() >= MAX_CANDIDATES {
                    return Err(CandidateBookErrorV2::BoundExceeded);
                }
                0
            }
        };
        let missing = history
            .len()
            .checked_sub(missing_from)
            .ok_or(CandidateBookErrorV2::Equivocation)?;
        if usize::try_from(self.revision)
            .map_err(|_| CandidateBookErrorV2::BoundExceeded)?
            .checked_add(missing)
            .ok_or(CandidateBookErrorV2::BoundExceeded)?
            > MAX_BOOK_HISTORY
        {
            return Err(CandidateBookErrorV2::BoundExceeded);
        }
        for delivery in history.iter().skip(missing_from) {
            let frame = encode_frame(self.revision, delivery)?;
            let recovered = verify_without_freshness(
                delivery,
                self.scope,
                authorities.bond,
                authorities.status,
                authorities.secp,
            )?;
            self.log
                .append_frame(&frame)
                .map_err(|_| CandidateBookErrorV2::Storage)?;
            self.insert_or_refresh(delivery.clone(), recovered)?;
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or(CandidateBookErrorV2::Arithmetic)?;
        }
        Ok(())
    }

    /// Revalidates freshness and issues an arrival-independent selection set.
    pub fn prove_current_candidates(
        &self,
        trusted_now_seconds: u64,
    ) -> Result<CandidateBookCapabilityV2, CandidateBookErrorV2> {
        if trusted_now_seconds == 0 {
            return Err(CandidateBookErrorV2::Stale);
        }
        let mut candidates = Vec::with_capacity(self.records.len());
        for record in self.records.values() {
            let request = record.attestation.request;
            if request.observed_at_seconds > trusted_now_seconds
                || trusted_now_seconds >= request.valid_until_seconds
                || record.status.observed_at_seconds() > trusted_now_seconds
                || trusted_now_seconds >= record.status.valid_until_seconds()
                || record.status.state() != SolverOperationalStateV1::Active
                || record.attestation_digest == ZERO_DIGEST
            {
                return Err(CandidateBookErrorV2::Stale);
            }
            candidates.push((
                record.quote,
                CandidateFactsV1 {
                    solver_registered: true,
                    signature_valid: true,
                    bond_reserved_exclusive: true,
                    exposure_covered: true,
                    coverage_excess: request
                        .reserved_collateral
                        .checked_sub(request.required_collateral)
                        .ok_or(CandidateBookErrorV2::Arithmetic)?,
                    solver_active: true,
                    policy_version_accepted: true,
                },
            ));
        }
        let inputs_digest = self.snapshot_digest(&candidates)?;
        Ok(CandidateBookCapabilityV2 {
            scope: self.scope,
            candidates,
            inputs_digest,
            revision: self.revision,
        })
    }

    fn ensure_unique(&self, quote: &QuoteV2) -> Result<(), CandidateBookErrorV2> {
        if self.by_solver.contains_key(&quote.solver)
            || self.by_reservation.contains_key(&quote.bond_reservation_id)
        {
            return Err(CandidateBookErrorV2::Equivocation);
        }
        Ok(())
    }

    fn snapshot_digest(
        &self,
        candidates: &[(QuoteV2, CandidateFactsV1)],
    ) -> Result<Digest32, CandidateBookErrorV2> {
        let mut bytes = encode_scope(self.scope);
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        for (quote, facts) in candidates {
            let record = self
                .records
                .get(&quote.quote_id)
                .ok_or(CandidateBookErrorV2::Storage)?;
            let quote_bytes = quote
                .canonical_bytes()
                .map_err(|_| CandidateBookErrorV2::InvalidAttestation)?;
            bytes.extend_from_slice(
                &u32::try_from(quote_bytes.len())
                    .map_err(|_| CandidateBookErrorV2::BoundExceeded)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&quote_bytes);
            bytes.extend_from_slice(&record.attestation_digest);
            bytes.extend_from_slice(&record.attestation.request.sequence.to_be_bytes());
            bytes.extend_from_slice(
                &record
                    .status
                    .statement_digest()
                    .map_err(|_| CandidateBookErrorV2::SolverIdentity)?,
            );
            bytes.extend_from_slice(&record.status.status_epoch().to_be_bytes());
            bytes.extend_from_slice(&record.status.valid_until_seconds().to_be_bytes());
            bytes.extend_from_slice(&encode_facts(*facts));
        }
        digest_parts(CANDIDATE_AUTHORITY_DOMAIN, &[&bytes])
    }

    fn insert_or_refresh(
        &mut self,
        delivery: CandidateQuoteDeliveryV2,
        verified: VerifiedCandidateDeliveryV2,
    ) -> Result<(), CandidateBookErrorV2> {
        let quote = delivery.quote;
        if !self.records.contains_key(&quote.quote_id) {
            self.ensure_unique(&quote)?;
        }
        self.by_solver.insert(quote.solver, quote.quote_id);
        self.by_reservation
            .insert(quote.bond_reservation_id, quote.quote_id);
        self.records.insert(
            quote.quote_id,
            CandidateRecordV2 {
                quote,
                attestation: verified.bond.attestation,
                attestation_digest: verified.bond.digest,
                status: verified.status,
                delivery_bytes: delivery.canonical_bytes()?,
            },
        );
        Ok(())
    }

    fn apply_replayed(
        &mut self,
        delivery: CandidateQuoteDeliveryV2,
        verified: VerifiedCandidateDeliveryV2,
    ) -> Result<(), CandidateBookErrorV2> {
        if let Some(existing) = self.records.get(&delivery.quote.quote_id) {
            validate_refresh(existing, &verified)?;
        } else if verified.bond.attestation.request.sequence != 1
            || verified
                .bond
                .attestation
                .request
                .previous_attestation_digest
                != ZERO_DIGEST
        {
            return Err(CandidateBookErrorV2::Equivocation);
        }
        self.insert_or_refresh(delivery, verified)
    }
}

/// Strict Store-backed candidate-book journal.
pub struct CandidateBookStoreLogV2 {
    store: store::Store,
}

impl CandidateBookStoreLogV2 {
    /// Creates an empty production candidate book.
    pub fn create_production(
        path: &Path,
        scope: CandidateBookScopeV2,
    ) -> Result<Self, CandidateBookErrorV2> {
        let binding = store::ProductionStoreBindingV1::new(scope.binding_digest()?)
            .map_err(|_| CandidateBookErrorV2::Storage)?;
        Ok(Self {
            store: store::Store::create_production(path, binding)
                .map_err(|_| CandidateBookErrorV2::Storage)?,
        })
    }

    /// Opens an exact existing production candidate book.
    pub fn open_production(
        path: &Path,
        scope: CandidateBookScopeV2,
    ) -> Result<Self, CandidateBookErrorV2> {
        let binding = store::ProductionStoreBindingV1::new(scope.binding_digest()?)
            .map_err(|_| CandidateBookErrorV2::Storage)?;
        Ok(Self {
            store: store::Store::open_production(path, binding)
                .map_err(|_| CandidateBookErrorV2::Storage)?,
        })
    }

    /// Resumes only a globally journaled pristine create prefix.
    pub fn resume_create_production(
        path: &Path,
        scope: CandidateBookScopeV2,
    ) -> Result<Self, CandidateBookErrorV2> {
        let binding = store::ProductionStoreBindingV1::new(scope.binding_digest()?)
            .map_err(|_| CandidateBookErrorV2::Storage)?;
        Ok(Self {
            store: store::Store::resume_create_production(path, binding)
                .map_err(|_| CandidateBookErrorV2::Storage)?,
        })
    }
}

impl BindingLog for CandidateBookStoreLogV2 {
    fn append_frame(&mut self, frame: &[u8]) -> Result<(), EngineError> {
        self.store
            .append_journal(BOOK_JOURNAL_KIND, frame)
            .map(|_| ())
            .map_err(|error| EngineError::Log(error.to_string()))
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>, EngineError> {
        let rows = self
            .store
            .read_journal()
            .map_err(|error| EngineError::Log(error.to_string()))?;
        rows.into_iter()
            .map(|row| {
                if row.kind != BOOK_JOURNAL_KIND {
                    Err(EngineError::ForeignRecord)
                } else {
                    Ok(row.payload)
                }
            })
            .collect()
    }
}

fn validate_authority_set_shape(
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<(), CandidateBookErrorV2> {
    if authorities.xonly_keys().is_empty()
        || authorities.xonly_keys().len() > MAX_AUTHORITIES
        || authorities.threshold() == 0
        || usize::from(authorities.threshold()) > authorities.xonly_keys().len()
    {
        return Err(CandidateBookErrorV2::InvalidAuthority);
    }
    authorities
        .validate_with_context(secp)
        .map_err(|_| CandidateBookErrorV2::InvalidAuthority)
}

fn validate_authorities(
    scope: CandidateBookScopeV2,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<(), CandidateBookErrorV2> {
    scope.validate()?;
    if authorities.xonly_keys().is_empty()
        || authorities.xonly_keys().len() > MAX_AUTHORITIES
        || authorities.threshold() == 0
        || usize::from(authorities.threshold()) > authorities.xonly_keys().len()
    {
        return Err(CandidateBookErrorV2::InvalidAuthority);
    }
    authorities
        .validate_with_context(secp)
        .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?;
    let bytes = authorities
        .canonical_bytes()
        .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?;
    if digest_parts(AUTHORITY_SET_DOMAIN, &[&bytes])? != scope.authority_set_digest {
        return Err(CandidateBookErrorV2::InvalidAuthority);
    }
    Ok(())
}

fn validate_status_authorities(
    scope: CandidateBookScopeV2,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<(), CandidateBookErrorV2> {
    if authorities.xonly_keys().is_empty()
        || authorities.xonly_keys().len() > MAX_AUTHORITIES
        || authorities.threshold() == 0
        || usize::from(authorities.threshold()) > authorities.xonly_keys().len()
    {
        return Err(CandidateBookErrorV2::InvalidAuthority);
    }
    authorities
        .validate_with_context(secp)
        .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?;
    let bytes = authorities
        .canonical_bytes()
        .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?;
    if digest_parts(STATUS_AUTHORITY_SET_DOMAIN, &[&bytes])? != scope.status_authority_set_digest {
        return Err(CandidateBookErrorV2::InvalidAuthority);
    }
    Ok(())
}

/// Verifies the complete remote quote delivery against independent bond and
/// solver-status authority sets.
pub fn verify_candidate_quote_delivery_v2(
    delivery: &CandidateQuoteDeliveryV2,
    scope: CandidateBookScopeV2,
    authorities: &AuthoritySetV1,
    status_authorities: &AuthoritySetV1,
    secp: &SecpContext,
    trusted_now_seconds: u64,
) -> Result<VerifiedCandidateDeliveryV2, CandidateBookErrorV2> {
    let bond = verify_bond_reservation_attestation_v2(
        &delivery.attestation,
        &delivery.quote,
        scope,
        authorities,
        secp,
        trusted_now_seconds,
    )?;
    validate_status_authorities(scope, status_authorities, secp)?;
    let status = delivery
        .status
        .statement()
        .map_err(|_| CandidateBookErrorV2::SolverIdentity)?;
    let status_digest = status
        .statement_digest()
        .map_err(|_| CandidateBookErrorV2::SolverIdentity)?;
    for signature in delivery.status.signatures() {
        let key = status_authorities
            .xonly_keys()
            .get(usize::from(signature.signer_index))
            .ok_or(CandidateBookErrorV2::InvalidAuthority)?;
        secp.verify_bip340(key, &status_digest, &signature.signature)
            .map_err(|_| CandidateBookErrorV2::InvalidAuthority)?;
    }
    if delivery.status.signatures().len() < usize::from(status_authorities.threshold()) {
        return Err(CandidateBookErrorV2::ThresholdNotMet);
    }
    let request = bond.attestation.request;
    if status.network_id() != scope.network_id
        || status.registry_digest() != scope.registry_digest
        || status.registry_epoch() != scope.registry_epoch
        || status.roster_snapshot() != scope.roster_snapshot
        || status.solver_id() != delivery.quote.solver
        || status.state() != SolverOperationalStateV1::Active
        || status_digest != request.solver_status_statement_digest
        || status.status_epoch() != request.solver_status_epoch
        || status.valid_until_seconds() != request.solver_status_valid_until_seconds
    {
        return Err(CandidateBookErrorV2::SolverIdentity);
    }
    if trusted_now_seconds == 0
        || status.observed_at_seconds() > trusted_now_seconds
        || trusted_now_seconds >= status.valid_until_seconds()
    {
        return Err(CandidateBookErrorV2::Stale);
    }
    Ok(VerifiedCandidateDeliveryV2 { bond, status })
}

fn validate_refresh(
    previous: &CandidateRecordV2,
    next: &VerifiedCandidateDeliveryV2,
) -> Result<(), CandidateBookErrorV2> {
    let old = previous.attestation.request;
    let new = next.bond.attestation.request;
    let previous_status_digest = previous
        .status
        .statement_digest()
        .map_err(|_| CandidateBookErrorV2::SolverIdentity)?;
    let next_status_digest = next
        .status
        .statement_digest()
        .map_err(|_| CandidateBookErrorV2::SolverIdentity)?;
    if new.sequence
        != old
            .sequence
            .checked_add(1)
            .ok_or(CandidateBookErrorV2::Arithmetic)?
        || new.previous_attestation_digest != previous.attestation_digest
        || new.required_collateral != old.required_collateral
        || new.reserved_collateral < old.reserved_collateral
        || new.observed_at_seconds < old.observed_at_seconds
        || new.solver_status_epoch < old.solver_status_epoch
        || (new.solver_status_epoch == old.solver_status_epoch
            && next_status_digest != previous_status_digest)
        || next.status.observed_at_seconds() < previous.status.observed_at_seconds()
    {
        return Err(CandidateBookErrorV2::Equivocation);
    }
    Ok(())
}

fn recovery_record(
    delivery: &CandidateQuoteDeliveryV2,
    verified: &VerifiedCandidateDeliveryV2,
) -> Result<CandidateRecordV2, CandidateBookErrorV2> {
    Ok(CandidateRecordV2 {
        quote: delivery.quote,
        attestation: verified.bond.attestation,
        attestation_digest: verified.bond.digest,
        status: verified.status,
        delivery_bytes: delivery.canonical_bytes()?,
    })
}

fn validate_signature_shape(
    signatures: &[BondReservationSignatureV2],
) -> Result<(), CandidateBookErrorV2> {
    if signatures.is_empty() || signatures.len() > MAX_AUTHORITIES {
        return Err(CandidateBookErrorV2::BoundExceeded);
    }
    let mut previous = None;
    for signature in signatures {
        if previous.is_some_and(|index| index >= signature.signer_index) {
            return Err(CandidateBookErrorV2::InvalidAuthority);
        }
        previous = Some(signature.signer_index);
    }
    Ok(())
}

fn validate_roster_quote(
    scope: CandidateBookScopeV2,
    quote: &QuoteV2,
    rosters: &RosterRegistryV1,
) -> Result<(), CandidateBookErrorV2> {
    if quote.route.composition_id != scope.composition_id
        || quote.route.position != scope.position
        || quote.rfq_id != scope.rfq_id
    {
        return Err(CandidateBookErrorV2::ScopeMismatch);
    }
    let member = rosters
        .snapshot(&scope.roster_snapshot)
        .and_then(|snapshot| snapshot.member(&quote.solver))
        .ok_or(CandidateBookErrorV2::SolverIdentity)?;
    if member.role != SenderRoleV1::Solver
        || verify_roster_signature(&member.xonly_key, &quote.quote_id, &quote.solver_signature)
            .is_err()
    {
        return Err(CandidateBookErrorV2::SolverIdentity);
    }
    Ok(())
}

fn verify_without_freshness(
    delivery: &CandidateQuoteDeliveryV2,
    scope: CandidateBookScopeV2,
    authorities: &AuthoritySetV1,
    status_authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<VerifiedCandidateDeliveryV2, CandidateBookErrorV2> {
    let attestation =
        BondReservationAttestationV2::decode(&delivery.attestation.attestation_bytes)?;
    let status = delivery
        .status
        .statement()
        .map_err(|_| CandidateBookErrorV2::SolverIdentity)?;
    verify_candidate_quote_delivery_v2(
        delivery,
        scope,
        authorities,
        status_authorities,
        secp,
        attestation
            .request
            .observed_at_seconds
            .max(status.observed_at_seconds()),
    )
}

fn encode_frame(
    revision: u64,
    delivery: &CandidateQuoteDeliveryV2,
) -> Result<Vec<u8>, CandidateBookErrorV2> {
    let delivery_bytes = delivery.canonical_bytes()?;
    let mut output = Vec::with_capacity(8 + 2 + 8 + 4 + delivery_bytes.len());
    output.extend_from_slice(FRAME_MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&revision.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(delivery_bytes.len())
            .map_err(|_| CandidateBookErrorV2::BoundExceeded)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&delivery_bytes);
    if output.len() > MAX_FRAME_BYTES {
        return Err(CandidateBookErrorV2::BoundExceeded);
    }
    Ok(output)
}

fn decode_frame(bytes: &[u8]) -> Result<(u64, CandidateQuoteDeliveryV2), CandidateBookErrorV2> {
    if bytes.len() > MAX_FRAME_BYTES || bytes.get(..8) != Some(FRAME_MAGIC.as_slice()) {
        return Err(CandidateBookErrorV2::NonCanonical);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.take(8)?;
    if cursor.u16()? != VERSION {
        return Err(CandidateBookErrorV2::NonCanonical);
    }
    let revision = cursor.u64()?;
    let delivery_len =
        usize::try_from(cursor.u32()?).map_err(|_| CandidateBookErrorV2::BoundExceeded)?;
    let delivery = CandidateQuoteDeliveryV2::decode(cursor.take(delivery_len)?)?;
    cursor.finish()?;
    if encode_frame(revision, &delivery)?.as_slice() != bytes {
        return Err(CandidateBookErrorV2::NonCanonical);
    }
    Ok((revision, delivery))
}

fn encode_scope(scope: CandidateBookScopeV2) -> Vec<u8> {
    let mut output = Vec::with_capacity(32 * 9 + 1 + 8 + 16);
    output.extend_from_slice(&scope.network_id);
    output.extend_from_slice(&scope.composition_id);
    output.push(scope.position as u8);
    output.extend_from_slice(&scope.rfq_id);
    output.extend_from_slice(&scope.roster_snapshot);
    output.extend_from_slice(&scope.bond_policy_hash);
    output.extend_from_slice(&scope.registry_digest);
    output.extend_from_slice(&scope.registry_epoch.to_be_bytes());
    output.extend_from_slice(&scope.bond_asset_binding_digest);
    output.extend_from_slice(&scope.required_collateral.to_be_bytes());
    output.extend_from_slice(&scope.authority_set_digest);
    output.extend_from_slice(&scope.status_authority_set_digest);
    output
}

fn encode_facts(facts: CandidateFactsV1) -> [u8; 23] {
    let mut output = [0u8; 23];
    output[0] = u8::from(facts.solver_registered);
    output[1] = u8::from(facts.signature_valid);
    output[2] = u8::from(facts.bond_reserved_exclusive);
    output[3] = u8::from(facts.exposure_covered);
    output[4..20].copy_from_slice(&facts.coverage_excess.to_be_bytes());
    output[20] = u8::from(facts.solver_active);
    output[21] = u8::from(facts.policy_version_accepted);
    output[22] = 2;
    output
}

fn put_request(output: &mut Vec<u8>, request: BondReservationAttestationRequestV2) {
    output.extend_from_slice(&request.network_id);
    output.extend_from_slice(&request.composition_id);
    output.push(request.position as u8);
    output.extend_from_slice(&request.rfq_id);
    output.extend_from_slice(&request.quote_id);
    output.extend_from_slice(&request.solver.0);
    output.extend_from_slice(&request.reservation_id);
    output.extend_from_slice(&request.bond_policy_hash);
    output.extend_from_slice(&request.registry_digest);
    output.extend_from_slice(&request.registry_epoch.to_be_bytes());
    output.extend_from_slice(&request.bond_asset_binding_digest);
    output.extend_from_slice(&request.required_collateral.to_be_bytes());
    output.extend_from_slice(&request.reserved_collateral.to_be_bytes());
    output.extend_from_slice(&request.reservation_state_digest);
    output.extend_from_slice(&request.source_evidence_digest);
    output.extend_from_slice(&request.solver_status_statement_digest);
    output.extend_from_slice(&request.solver_status_epoch.to_be_bytes());
    output.extend_from_slice(&request.solver_status_valid_until_seconds.to_be_bytes());
    output.extend_from_slice(&request.observed_at_seconds.to_be_bytes());
    output.extend_from_slice(&request.valid_until_seconds.to_be_bytes());
    output.extend_from_slice(&request.sequence.to_be_bytes());
    output.extend_from_slice(&request.previous_attestation_digest);
}

fn take_request(
    cursor: &mut Cursor<'_>,
) -> Result<BondReservationAttestationRequestV2, CandidateBookErrorV2> {
    Ok(BondReservationAttestationRequestV2 {
        network_id: cursor.array()?,
        composition_id: cursor.array()?,
        position: match cursor.u8()? {
            1 => SettlementPositionV2::Upstream,
            2 => SettlementPositionV2::Downstream,
            _ => return Err(CandidateBookErrorV2::NonCanonical),
        },
        rfq_id: cursor.array()?,
        quote_id: cursor.array()?,
        solver: ParticipantId(cursor.array()?),
        reservation_id: cursor.array()?,
        bond_policy_hash: cursor.array()?,
        registry_digest: cursor.array()?,
        registry_epoch: cursor.u64()?,
        bond_asset_binding_digest: cursor.array()?,
        required_collateral: cursor.u128()?,
        reserved_collateral: cursor.u128()?,
        reservation_state_digest: cursor.array()?,
        source_evidence_digest: cursor.array()?,
        solver_status_statement_digest: cursor.array()?,
        solver_status_epoch: cursor.u64()?,
        solver_status_valid_until_seconds: cursor.u64()?,
        observed_at_seconds: cursor.u64()?,
        valid_until_seconds: cursor.u64()?,
        sequence: cursor.u64()?,
        previous_attestation_digest: cursor.array()?,
    })
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, CandidateBookErrorV2> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| CandidateBookErrorV2::Arithmetic)?;
    hasher.update(&(domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| CandidateBookErrorV2::Arithmetic)?;
    Ok(output)
}

struct Cursor<'bytes> {
    bytes: &'bytes [u8],
    position: usize,
}

impl<'bytes> Cursor<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'bytes [u8], CandidateBookErrorV2> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CandidateBookErrorV2::Arithmetic)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CandidateBookErrorV2::NonCanonical)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CandidateBookErrorV2> {
        self.take(N)?
            .try_into()
            .map_err(|_| CandidateBookErrorV2::NonCanonical)
    }

    fn u8(&mut self) -> Result<u8, CandidateBookErrorV2> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CandidateBookErrorV2> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CandidateBookErrorV2> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CandidateBookErrorV2> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u128(&mut self) -> Result<u128, CandidateBookErrorV2> {
        Ok(u128::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), CandidateBookErrorV2> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(CandidateBookErrorV2::NonCanonical)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use relay::auth::{RosterMemberV1, RosterSnapshotV1};
    use rfq::v2::{
        select_winner_with_authority_digest_v2, NativeClockKindV2, NegotiationClockV2,
        NegotiationInstantV2, NegotiationObservationV2, QuoteProposalV2, RfqRequestV2, RouteV2,
    };
    use rfq::{AssetId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1};
    use solver_status::{SolverStatusObservationV1, SolverStatusScopeV1, SolverStatusSignatureV1};
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(VerifiedBondReservationAttestationV2: Clone, Copy);
    assert_not_impl_any!(CandidateBookCapabilityV2: Clone, Copy);

    #[derive(Clone, Default)]
    struct MemoryLog(Rc<RefCell<Vec<Vec<u8>>>>);

    impl BindingLog for MemoryLog {
        fn append_frame(&mut self, frame: &[u8]) -> Result<(), EngineError> {
            self.0.borrow_mut().push(frame.to_vec());
            Ok(())
        }

        fn frames(&self) -> Result<Vec<Vec<u8>>, EngineError> {
            Ok(self.0.borrow().clone())
        }
    }

    struct Fixture {
        secp: SecpContext,
        scope: CandidateBookScopeV2,
        bond_authorities: AuthoritySetV1,
        status_authorities: AuthoritySetV1,
        rosters: RosterRegistryV1,
        solver_secrets: [[u8; 32]; 2],
        rfq: rfq::v2::RfqV2,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let secp = SecpContext::new(&[0x91; 32]);
            let bond_secrets = [[0x11; 32], [0x12; 32], [0x13; 32]];
            let status_secrets = [[0x21; 32], [0x22; 32], [0x23; 32]];
            let bond_authorities = authority_set(&secp, &bond_secrets)?;
            let status_authorities = authority_set(&secp, &status_secrets)?;
            let clock = NegotiationClockV2 {
                chain_id: rfq::ChainId([0xd0; 32]),
                profile_digest: [0x31; 32],
                authority_scope: [0x32; 32],
                kind: NativeClockKindV2::BlockHeight,
            };
            let route = RouteV2 {
                composition_id: [0x41; 32],
                position: SettlementPositionV2::Upstream,
                legs: [
                    RouteLegV1 {
                        chain_id: rfq::ChainId([0xe1; 32]),
                        asset: AssetId([0xe2; 32]),
                        direction: LegDirectionV1::UserGives,
                    },
                    RouteLegV1 {
                        chain_id: clock.chain_id,
                        asset: AssetId([0xd2; 32]),
                        direction: LegDirectionV1::UserReceives,
                    },
                ],
            };
            let rfq = rfq::v2::RfqV2::create(RfqRequestV2 {
                initiator: ParticipantId([0x42; 32]),
                route,
                mode: RfqModeV1::ExactIn {
                    input_amount: 100,
                    minimum_output: 90,
                },
                fee_limit: FeeLimitV1 {
                    dom_max: 4,
                    counterparty_max: 6,
                },
                negotiation_clock: clock,
                quote_deadline: NegotiationInstantV2 {
                    clock,
                    value: 1_100,
                },
                assurance_policy_ref: PolicyId([0x43; 32]),
                policy_version: 3,
                session_id: [0x44; 32],
            })?;
            let solver_secrets = [[0x51; 32], [0x52; 32]];
            let mut snapshot = RosterSnapshotV1::new();
            for secret in &solver_secrets {
                let key = secp.xonly_public_key(secret)?;
                snapshot = snapshot.with_member(
                    ParticipantId(key),
                    RosterMemberV1 {
                        xonly_key: key,
                        role: SenderRoleV1::Solver,
                    },
                );
            }
            let roster_snapshot = [0x45; 32];
            let rosters = RosterRegistryV1::new().with_snapshot(roster_snapshot, snapshot);
            let scope = CandidateBookScopeV2 {
                network_id: [0x46; 32],
                composition_id: route.composition_id,
                position: route.position,
                rfq_id: rfq.rfq_id,
                roster_snapshot,
                bond_policy_hash: [0x47; 32],
                registry_digest: [0x48; 32],
                registry_epoch: 7,
                bond_asset_binding_digest: [0x49; 32],
                required_collateral: 10,
                authority_set_digest: authority_digest(
                    &bond_authorities,
                    &secp,
                    AUTHORITY_SET_DOMAIN,
                )?,
                status_authority_set_digest: authority_digest(
                    &status_authorities,
                    &secp,
                    STATUS_AUTHORITY_SET_DOMAIN,
                )?,
            };
            Ok(Self {
                secp,
                scope,
                bond_authorities,
                status_authorities,
                rosters,
                solver_secrets,
                rfq,
            })
        }

        fn delivery(
            &self,
            solver_index: usize,
            sequence: u64,
            previous: Digest32,
            observed_at: u64,
            reserved: u128,
        ) -> Result<CandidateQuoteDeliveryV2, Box<dyn std::error::Error>> {
            self.delivery_with_status_epoch(
                solver_index,
                sequence,
                previous,
                observed_at,
                reserved,
                sequence,
            )
        }

        fn delivery_with_status_epoch(
            &self,
            solver_index: usize,
            sequence: u64,
            previous: Digest32,
            observed_at: u64,
            reserved: u128,
            status_epoch: u64,
        ) -> Result<CandidateQuoteDeliveryV2, Box<dyn std::error::Error>> {
            let secret = self.solver_secrets[solver_index];
            let solver = ParticipantId(self.secp.xonly_public_key(&secret)?);
            let unsigned = QuoteV2::create(QuoteProposalV2 {
                rfq_id: self.rfq.rfq_id,
                solver,
                route: self.rfq.route,
                net_output: 95 + solver_index as u128,
                total_input: 100,
                total_fee: 7,
                execution_deadline: NegotiationInstantV2 {
                    clock: self.rfq.negotiation_clock,
                    value: 1_080,
                },
                bond_reservation_id: [0x61 + solver_index as u8; 32],
                bond_policy_version: self.rfq.policy_version,
                expiry: NegotiationInstantV2 {
                    clock: self.rfq.negotiation_clock,
                    value: 1_050,
                },
                solver_signature: [0; 64],
            })?;
            let signature = self
                .secp
                .sign_bip340(&secret, &unsigned.quote_id, &[0x71; 32])?
                .0;
            let quote = QuoteV2::create(QuoteProposalV2 {
                solver_signature: signature,
                ..QuoteProposalV2 {
                    rfq_id: unsigned.rfq_id,
                    solver: unsigned.solver,
                    route: unsigned.route,
                    net_output: unsigned.net_output,
                    total_input: unsigned.total_input,
                    total_fee: unsigned.total_fee,
                    execution_deadline: unsigned.execution_deadline,
                    bond_reservation_id: unsigned.bond_reservation_id,
                    bond_policy_version: unsigned.bond_policy_version,
                    expiry: unsigned.expiry,
                    solver_signature: [0; 64],
                }
            })?;
            let status = SolverStatusStatementV1::new(
                SolverStatusScopeV1 {
                    network_id: self.scope.network_id,
                    registry_digest: self.scope.registry_digest,
                    registry_epoch: self.scope.registry_epoch,
                    roster_snapshot: self.scope.roster_snapshot,
                    solver_id: solver,
                },
                SolverStatusObservationV1 {
                    status_epoch,
                    source_evidence_digest: [0x81; 32],
                    state: SolverOperationalStateV1::Active,
                    observed_at_seconds: observed_at,
                    valid_until_seconds: observed_at + 100,
                },
            )?;
            let signed_status = sign_status(&self.secp, status, &[[0x21; 32], [0x22; 32]])?;
            let attestation =
                BondReservationAttestationV2::new(BondReservationAttestationRequestV2 {
                    network_id: self.scope.network_id,
                    composition_id: self.scope.composition_id,
                    position: self.scope.position,
                    rfq_id: self.scope.rfq_id,
                    quote_id: quote.quote_id,
                    solver,
                    reservation_id: quote.bond_reservation_id,
                    bond_policy_hash: self.scope.bond_policy_hash,
                    registry_digest: self.scope.registry_digest,
                    registry_epoch: self.scope.registry_epoch,
                    bond_asset_binding_digest: self.scope.bond_asset_binding_digest,
                    required_collateral: 10,
                    reserved_collateral: reserved,
                    reservation_state_digest: [0x82 + sequence as u8; 32],
                    source_evidence_digest: [0x83; 32],
                    solver_status_statement_digest: status.statement_digest()?,
                    solver_status_epoch: status.status_epoch(),
                    solver_status_valid_until_seconds: status.valid_until_seconds(),
                    observed_at_seconds: observed_at,
                    valid_until_seconds: observed_at + 90,
                    sequence,
                    previous_attestation_digest: previous,
                })?;
            let signed_bond = sign_bond(&self.secp, attestation, &[[0x11; 32], [0x12; 32]])?;
            Ok(CandidateQuoteDeliveryV2::new(
                quote,
                signed_bond,
                signed_status,
            )?)
        }

        fn verifiers(&self) -> CandidateVerificationAuthoritiesV2<'_> {
            CandidateVerificationAuthoritiesV2::new(
                &self.bond_authorities,
                &self.status_authorities,
                &self.secp,
                &self.rosters,
            )
        }
    }

    fn authority_set(
        secp: &SecpContext,
        secrets: &[[u8; 32]],
    ) -> Result<AuthoritySetV1, Box<dyn std::error::Error>> {
        let keys = secrets
            .iter()
            .map(|secret| secp.xonly_public_key(secret))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AuthoritySetV1::new(2, keys)?)
    }

    fn authority_digest(
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        domain: &[u8],
    ) -> Result<Digest32, Box<dyn std::error::Error>> {
        authorities.validate_with_context(secp)?;
        Ok(digest_parts(domain, &[&authorities.canonical_bytes()?])?)
    }

    fn sign_bond(
        secp: &SecpContext,
        attestation: BondReservationAttestationV2,
        secrets: &[[u8; 32]],
    ) -> Result<SignedBondReservationAttestationV2, Box<dyn std::error::Error>> {
        let digest = attestation.attestation_digest()?;
        let signatures = secrets
            .iter()
            .enumerate()
            .map(|(index, secret)| {
                Ok(BondReservationSignatureV2 {
                    signer_index: u16::try_from(index)?,
                    signature: secp
                        .sign_bip340(secret, &digest, &[0x91 + index as u8; 32])?
                        .0,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        Ok(SignedBondReservationAttestationV2::new(
            attestation,
            signatures,
        )?)
    }

    fn sign_status(
        secp: &SecpContext,
        statement: SolverStatusStatementV1,
        secrets: &[[u8; 32]],
    ) -> Result<SignedSolverStatusV1, Box<dyn std::error::Error>> {
        let digest = statement.statement_digest()?;
        let signatures = secrets
            .iter()
            .enumerate()
            .map(|(index, secret)| {
                Ok(SolverStatusSignatureV1 {
                    signer_index: u16::try_from(index)?,
                    signature: secp
                        .sign_bip340(secret, &digest, &[0xa1 + index as u8; 32])?
                        .0,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        Ok(SignedSolverStatusV1::new(statement, signatures)?)
    }

    #[test]
    fn attestation_codec_is_strict_and_transplant_sensitive() -> Result<(), CandidateBookErrorV2> {
        let request = BondReservationAttestationRequestV2 {
            network_id: [1; 32],
            composition_id: [2; 32],
            position: SettlementPositionV2::Upstream,
            rfq_id: [3; 32],
            quote_id: [4; 32],
            solver: ParticipantId([5; 32]),
            reservation_id: [6; 32],
            bond_policy_hash: [7; 32],
            registry_digest: [8; 32],
            registry_epoch: 9,
            bond_asset_binding_digest: [10; 32],
            required_collateral: 11,
            reserved_collateral: 12,
            reservation_state_digest: [13; 32],
            source_evidence_digest: [14; 32],
            solver_status_statement_digest: [15; 32],
            solver_status_epoch: 16,
            solver_status_valid_until_seconds: 200,
            observed_at_seconds: 100,
            valid_until_seconds: 150,
            sequence: 1,
            previous_attestation_digest: ZERO_DIGEST,
        };
        let exact = BondReservationAttestationV2::new(request)?;
        let bytes = exact.canonical_bytes()?;
        assert_eq!(BondReservationAttestationV2::decode(&bytes)?, exact);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            BondReservationAttestationV2::decode(&trailing),
            Err(CandidateBookErrorV2::NonCanonical)
        );
        let transplanted =
            BondReservationAttestationV2::new(BondReservationAttestationRequestV2 {
                composition_id: [0x44; 32],
                ..request
            })?;
        assert_ne!(
            exact.attestation_digest()?,
            transplanted.attestation_digest()?
        );
        Ok(())
    }

    #[test]
    fn refresh_is_monotonic_replayable_and_changes_authority_snapshot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let log = MemoryLog::default();
        let mut book =
            DurableCandidateBookV2::open(log.clone(), fixture.scope, &fixture.verifiers())?;
        let first = fixture.delivery(0, 1, ZERO_DIGEST, 100, 12)?;
        assert_eq!(
            book.admit_remote(&first, &fixture.verifiers(), 110,)?,
            CandidateAdmissionOutcomeV2::Admitted
        );
        let first_capability = book.prove_current_candidates(110)?;
        let first_attestation = first.attestation().attestation_bytes.as_slice();
        let first_digest =
            BondReservationAttestationV2::decode(first_attestation)?.attestation_digest()?;
        let equivocated_status =
            fixture.delivery_with_status_epoch(0, 2, first_digest, 120, 15, 1)?;
        assert_eq!(
            book.admit_remote(&equivocated_status, &fixture.verifiers(), 125),
            Err(CandidateBookErrorV2::Equivocation)
        );
        let refresh = fixture.delivery(0, 2, first_digest, 120, 15)?;
        assert_eq!(
            book.admit_remote(&refresh, &fixture.verifiers(), 125,)?,
            CandidateAdmissionOutcomeV2::Admitted
        );
        let refreshed = book.prove_current_candidates(125)?;
        assert_ne!(first_capability.inputs_digest(), refreshed.inputs_digest());
        assert_eq!(refreshed.revision(), 2);
        assert_eq!(
            book.admit_remote(&first, &fixture.verifiers(), 125,),
            Err(CandidateBookErrorV2::Equivocation)
        );
        drop(book);
        let reopened = DurableCandidateBookV2::open(log, fixture.scope, &fixture.verifiers())?;
        assert_eq!(
            reopened.prove_current_candidates(125)?.inputs_digest(),
            refreshed.inputs_digest()
        );
        Ok(())
    }

    #[test]
    fn signed_history_recovers_expired_prefix_but_requires_fresh_exact_head(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let first = fixture.delivery(0, 1, ZERO_DIGEST, 100, 12)?;
        let first_digest = first.attestation().attestation()?.attestation_digest()?;
        let second = fixture.delivery(0, 2, first_digest, 220, 15)?;

        let log = MemoryLog::default();
        let mut recovered =
            DurableCandidateBookV2::open(log.clone(), fixture.scope, &fixture.verifiers())?;
        recovered.recover_signed_history(
            &[first.clone(), second.clone()],
            &fixture.verifiers(),
            225,
        )?;
        assert_eq!(recovered.prove_current_candidates(225)?.revision(), 2);
        recovered.recover_signed_history(
            &[first.clone(), second.clone()],
            &fixture.verifiers(),
            225,
        )?;
        assert_eq!(log.0.borrow().len(), 2);

        let empty = MemoryLog::default();
        let mut missing =
            DurableCandidateBookV2::open(empty.clone(), fixture.scope, &fixture.verifiers())?;
        assert_eq!(
            missing.recover_signed_history(
                core::slice::from_ref(&second),
                &fixture.verifiers(),
                225,
            ),
            Err(CandidateBookErrorV2::Equivocation)
        );
        assert!(empty.0.borrow().is_empty());

        let mut tampered = second.clone();
        let signature = tampered
            .attestation
            .signatures
            .get_mut(0)
            .ok_or("missing test signature")?;
        signature.signature[0] ^= 1;
        assert_eq!(
            missing.recover_signed_history(&[first.clone(), tampered], &fixture.verifiers(), 225,),
            Err(CandidateBookErrorV2::InvalidAuthority)
        );
        assert!(empty.0.borrow().is_empty());

        let wrong_previous = fixture.delivery(0, 2, [0xee; 32], 220, 15)?;
        assert_eq!(
            missing.recover_signed_history(
                &[first.clone(), wrong_previous],
                &fixture.verifiers(),
                225,
            ),
            Err(CandidateBookErrorV2::Equivocation)
        );
        assert!(empty.0.borrow().is_empty());

        let stale_log = MemoryLog::default();
        let mut stale =
            DurableCandidateBookV2::open(stale_log.clone(), fixture.scope, &fixture.verifiers())?;
        assert_eq!(
            stale.recover_signed_history(core::slice::from_ref(&first), &fixture.verifiers(), 225,),
            Err(CandidateBookErrorV2::Stale)
        );
        assert!(stale_log.0.borrow().is_empty());

        let oversized_log = MemoryLog::default();
        let mut oversized = DurableCandidateBookV2::open(
            oversized_log.clone(),
            fixture.scope,
            &fixture.verifiers(),
        )?;
        let oversized_history = vec![first.clone(); MAX_RECOVERY_HISTORY + 1];
        assert_eq!(
            oversized.recover_signed_history(&oversized_history, &fixture.verifiers(), 225,),
            Err(CandidateBookErrorV2::BoundExceeded)
        );
        assert!(oversized_log.0.borrow().is_empty());

        let prefix_log = MemoryLog::default();
        let mut prefix =
            DurableCandidateBookV2::open(prefix_log.clone(), fixture.scope, &fixture.verifiers())?;
        prefix.admit_remote(&first, &fixture.verifiers(), 110)?;
        drop(prefix);
        let mut restarted =
            DurableCandidateBookV2::open(prefix_log.clone(), fixture.scope, &fixture.verifiers())?;
        restarted.recover_signed_history(&[first, second], &fixture.verifiers(), 225)?;
        assert_eq!(prefix_log.0.borrow().len(), 2);
        assert_eq!(restarted.prove_current_candidates(225)?.revision(), 2);
        Ok(())
    }

    #[test]
    fn arrival_order_is_irrelevant_but_asset_status_and_facts_are_bound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let first = fixture.delivery(0, 1, ZERO_DIGEST, 100, 12)?;
        let second = fixture.delivery(1, 1, ZERO_DIGEST, 100, 14)?;
        let mut books = Vec::new();
        let mut selections = Vec::new();
        // These are two solver nodes: each appends its own local delivery
        // first and receives the other solver through Relay second. Locality
        // must not change the global authority snapshot or Selection wire.
        for order in [[&first, &second], [&second, &first]] {
            let mut book = DurableCandidateBookV2::open(
                MemoryLog::default(),
                fixture.scope,
                &fixture.verifiers(),
            )?;
            for delivery in order {
                book.admit_remote(delivery, &fixture.verifiers(), 110)?;
            }
            let capability = book.prove_current_candidates(110)?;
            let selection = select_winner_with_authority_digest_v2(
                &fixture.rfq,
                capability.candidates(),
                fixture.rfq.negotiation_clock.chain_id,
                NegotiationObservationV2 {
                    clock: fixture.rfq.negotiation_clock,
                    value: 101,
                },
                capability.inputs_digest(),
            )?;
            books.push(capability.inputs_digest());
            selections.push(selection.selection);
        }
        assert_eq!(books[0], books[1]);
        assert_eq!(selections[0], selections[1]);

        let changed_asset = CandidateBookScopeV2 {
            bond_asset_binding_digest: [0xf1; 32],
            ..fixture.scope
        };
        assert_ne!(
            fixture.scope.binding_digest()?,
            changed_asset.binding_digest()?
        );
        let changed_requirement = CandidateBookScopeV2 {
            required_collateral: fixture.scope.required_collateral + 1,
            ..fixture.scope
        };
        assert_ne!(
            fixture.scope.binding_digest()?,
            changed_requirement.binding_digest()?
        );
        assert!(matches!(
            verify_candidate_quote_delivery_v2(
                &first,
                changed_asset,
                &fixture.bond_authorities,
                &fixture.status_authorities,
                &fixture.secp,
                110,
            ),
            Err(CandidateBookErrorV2::ScopeMismatch)
        ));
        assert!(matches!(
            verify_candidate_quote_delivery_v2(
                &first,
                changed_requirement,
                &fixture.bond_authorities,
                &fixture.status_authorities,
                &fixture.secp,
                110,
            ),
            Err(CandidateBookErrorV2::ScopeMismatch)
        ));

        let mut wrong_status = first.status().canonical_bytes()?;
        let last = wrong_status
            .len()
            .checked_sub(1)
            .ok_or(CandidateBookErrorV2::Arithmetic)?;
        wrong_status[last] ^= 1;
        let canonical_but_unauthentic = SignedSolverStatusV1::decode(&wrong_status)?;
        let unauthentic_delivery = CandidateQuoteDeliveryV2::new(
            first.quote(),
            first.attestation().clone(),
            canonical_but_unauthentic,
        )?;
        assert!(matches!(
            verify_candidate_quote_delivery_v2(
                &unauthentic_delivery,
                fixture.scope,
                &fixture.bond_authorities,
                &fixture.status_authorities,
                &fixture.secp,
                110,
            ),
            Err(CandidateBookErrorV2::InvalidAuthority)
        ));
        Ok(())
    }

    #[test]
    fn threshold_trailing_and_stale_evidence_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        let delivery = fixture.delivery(0, 1, ZERO_DIGEST, 100, 12)?;
        assert!(matches!(
            verify_candidate_quote_delivery_v2(
                &delivery,
                fixture.scope,
                &fixture.bond_authorities,
                &fixture.status_authorities,
                &fixture.secp,
                200,
            ),
            Err(CandidateBookErrorV2::Stale)
        ));
        let mut trailing = delivery.canonical_bytes()?;
        trailing.push(0);
        assert_eq!(
            CandidateQuoteDeliveryV2::decode(&trailing),
            Err(CandidateBookErrorV2::NonCanonical)
        );
        let one_signature = SignedBondReservationAttestationV2::new(
            BondReservationAttestationV2::decode(&delivery.attestation().attestation_bytes)?,
            vec![delivery.attestation().signatures[0]],
        )?;
        let below_threshold = CandidateQuoteDeliveryV2::new(
            delivery.quote(),
            one_signature,
            delivery.status().clone(),
        )?;
        assert!(matches!(
            verify_candidate_quote_delivery_v2(
                &below_threshold,
                fixture.scope,
                &fixture.bond_authorities,
                &fixture.status_authorities,
                &fixture.secp,
                110,
            ),
            Err(CandidateBookErrorV2::ThresholdNotMet)
        ));
        Ok(())
    }
}

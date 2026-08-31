//! Participant-to-EVM-account authority for DOM interoperability.
//!
//! Settlement terms identify participants with 32-byte protocol identities,
//! while an EVM lock names 20-byte accounts.  Those namespaces are not
//! interchangeable.  This crate requires the same bounded EIP-712 statement
//! to be signed both by the EVM account and by the participant's roster
//! BIP340 key before it can produce [`EvmSessionBindingsV1`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use adapter_evm::Direction;
use btc_crypto::SecpContext;
use deployment_registry::EvmSessionBindingsV1;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{Digest32, ParticipantId},
};
use sha3::{Digest, Keccak256};

const DOMAIN_NAME: &[u8] = b"DOM Interop";
const DOMAIN_VERSION: &[u8] = b"1";
const DOMAIN_TYPE: &[u8] = b"EIP712Domain(string name,string version,uint256 chainId,bytes32 salt)";
const BINDING_TYPE: &[u8] = b"DomEvmAccountBinding(bytes32 networkId,bytes32 registryDigest,bytes32 routeId,bytes32 settlementId,bytes32 sessionId,bytes32 termsDigest,bytes32 rosterSnapshot,bytes32 participantId,bytes32 participantKey,address account,uint8 position,uint8 role,uint64 issuedAt,uint64 validUntil,uint256 evmChainId)";
const ROSTER_DOMAIN: &[u8] = b"DOM-INTEROP/EVM-ORDERED-ROSTER/V1\0";
const VERIFICATION_CONTEXT_SEED: [u8; 32] = [0xA7; 32];

/// EVM signature length (`r || s || v`).
pub const EVM_ACCOUNT_SIGNATURE_BYTES_V1: usize = 65;
/// BIP340 participant signature length.
pub const PARTICIPANT_SIGNATURE_BYTES_V1: usize = 64;
/// Exact size of one canonical dual-signed account-binding proof.
pub const EVM_ACCOUNT_BINDING_PROOF_BYTES_V1: usize = 475;

const PROOF_MAGIC_V1: &[u8; 8] = b"DOMEVMP1";
const PROOF_VERSION_V1: u16 = 1;

/// The economic EVM role whose account ownership is being authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmBindingRoleV1 {
    /// Account that calls `open` and receives a timeout refund.
    Funder,
    /// Only account authorized by the contract to claim with the route scalar.
    Beneficiary,
}

impl EvmBindingRoleV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Funder => 1,
            Self::Beneficiary => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ParticipantBindingErrorV1> {
        match tag {
            1 => Ok(Self::Funder),
            2 => Ok(Self::Beneficiary),
            _ => Err(ParticipantBindingErrorV1::NonCanonicalEncoding),
        }
    }
}

/// Position of the settlement inside the composed `X -> DOM -> Y` route.
///
/// This is signed instead of accepting an independent direction flag: the
/// upstream counterparty must fund before DOM, while the downstream
/// counterparty is funded after DOM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmSettlementPositionV1 {
    /// Counterparty funding enters the DOM hub.
    Upstream,
    /// Counterparty claim exits the DOM hub.
    Downstream,
}

impl EvmSettlementPositionV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Upstream => 1,
            Self::Downstream => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ParticipantBindingErrorV1> {
        match tag {
            1 => Ok(Self::Upstream),
            2 => Ok(Self::Downstream),
            _ => Err(ParticipantBindingErrorV1::NonCanonicalEncoding),
        }
    }

    /// Contract direction implied by this composed settlement position.
    pub const fn direction(self) -> Direction {
        match self {
            Self::Upstream => Direction::EvmToDom,
            Self::Downstream => Direction::DomToEvm,
        }
    }
}

/// One bounded EIP-712 account-link statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmAccountBindingStatementV1 {
    /// DOM interoperability network identity.
    pub network_id: Digest32,
    /// Threshold-authenticated deployment registry digest.
    pub registry_digest: Digest32,
    /// Composed route identity.
    pub route_id: Digest32,
    /// Exact settlement whose EVM leg uses the account.
    pub settlement_id: Digest32,
    /// Exact scriptless session identity.
    pub session_id: Digest32,
    /// Frozen route terms digest carried by the EVM lock.
    pub terms_digest: Digest32,
    /// Frozen Relay roster snapshot that authenticates the participant key.
    pub roster_snapshot: Digest32,
    /// Protocol participant identity from the ordered settlement roster.
    pub participant_id: ParticipantId,
    /// BIP340 transport key registered for the participant at that snapshot.
    pub participant_xonly_key: [u8; 32],
    /// EVM account being linked to that participant and role.
    pub account: [u8; 20],
    /// Signed position from which the EVM direction is derived.
    pub position: EvmSettlementPositionV1,
    /// Economic role authorized for the account.
    pub role: EvmBindingRoleV1,
    /// First Unix second at which this statement may be accepted.
    pub issued_at: u64,
    /// Last Unix second at which a new session authority may accept it.
    pub valid_until: u64,
    /// EIP-155 chain id for the account and EIP-712 domain.
    pub evm_chain_id: u64,
}

/// The exact dual proof over an account-link statement.
#[derive(Clone, Eq, PartialEq)]
pub struct EvmAccountBindingProofV1 {
    statement: EvmAccountBindingStatementV1,
    evm_signature: [u8; EVM_ACCOUNT_SIGNATURE_BYTES_V1],
    participant_signature: [u8; PARTICIPANT_SIGNATURE_BYTES_V1],
}

impl core::fmt::Debug for EvmAccountBindingProofV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EvmAccountBindingProofV1")
            .field("statement", &self.statement)
            .finish_non_exhaustive()
    }
}

impl EvmAccountBindingProofV1 {
    /// Constructs an unverified proof for boundary ingestion.
    pub const fn new(
        statement: EvmAccountBindingStatementV1,
        evm_signature: [u8; EVM_ACCOUNT_SIGNATURE_BYTES_V1],
        participant_signature: [u8; PARTICIPANT_SIGNATURE_BYTES_V1],
    ) -> Self {
        Self {
            statement,
            evm_signature,
            participant_signature,
        }
    }

    /// Statement signed by both authorities.
    pub const fn statement(&self) -> EvmAccountBindingStatementV1 {
        self.statement
    }

    /// Exact bounded binary representation used by production input bundles.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ParticipantBindingErrorV1> {
        // Statement validation is shared with EIP-712 hashing. Signatures are
        // intentionally only authenticated by the verification boundary.
        evm_account_binding_digest_v1(&self.statement)?;
        let statement = self.statement;
        let mut bytes = Vec::with_capacity(EVM_ACCOUNT_BINDING_PROOF_BYTES_V1);
        bytes.extend_from_slice(PROOF_MAGIC_V1);
        bytes.extend_from_slice(&PROOF_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&statement.network_id);
        bytes.extend_from_slice(&statement.registry_digest);
        bytes.extend_from_slice(&statement.route_id);
        bytes.extend_from_slice(&statement.settlement_id);
        bytes.extend_from_slice(&statement.session_id);
        bytes.extend_from_slice(&statement.terms_digest);
        bytes.extend_from_slice(&statement.roster_snapshot);
        bytes.extend_from_slice(&statement.participant_id.0);
        bytes.extend_from_slice(&statement.participant_xonly_key);
        bytes.extend_from_slice(&statement.account);
        bytes.push(statement.position.tag());
        bytes.push(statement.role.tag());
        bytes.extend_from_slice(&statement.issued_at.to_be_bytes());
        bytes.extend_from_slice(&statement.valid_until.to_be_bytes());
        bytes.extend_from_slice(&statement.evm_chain_id.to_be_bytes());
        bytes.extend_from_slice(&self.evm_signature);
        bytes.extend_from_slice(&self.participant_signature);
        if bytes.len() != EVM_ACCOUNT_BINDING_PROOF_BYTES_V1 {
            return Err(ParticipantBindingErrorV1::NonCanonicalEncoding);
        }
        Ok(bytes)
    }

    /// Strictly decodes one proof and rejects alternate or trailing bytes.
    /// Cryptographic authentication still requires
    /// [`verify_evm_account_binding_v1`].
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ParticipantBindingErrorV1> {
        if bytes.len() != EVM_ACCOUNT_BINDING_PROOF_BYTES_V1 {
            return Err(ParticipantBindingErrorV1::NonCanonicalEncoding);
        }
        let mut cursor = ProofCursorV1::new(bytes);
        if cursor.take::<8>()? != *PROOF_MAGIC_V1
            || cursor.u16()? != PROOF_VERSION_V1
            || cursor.u16()? != 0
        {
            return Err(ParticipantBindingErrorV1::NonCanonicalEncoding);
        }
        let statement = EvmAccountBindingStatementV1 {
            network_id: cursor.take::<32>()?,
            registry_digest: cursor.take::<32>()?,
            route_id: cursor.take::<32>()?,
            settlement_id: cursor.take::<32>()?,
            session_id: cursor.take::<32>()?,
            terms_digest: cursor.take::<32>()?,
            roster_snapshot: cursor.take::<32>()?,
            participant_id: ParticipantId(cursor.take::<32>()?),
            participant_xonly_key: cursor.take::<32>()?,
            account: cursor.take::<20>()?,
            position: EvmSettlementPositionV1::from_tag(cursor.u8()?)?,
            role: EvmBindingRoleV1::from_tag(cursor.u8()?)?,
            issued_at: cursor.u64()?,
            valid_until: cursor.u64()?,
            evm_chain_id: cursor.u64()?,
        };
        let value = Self::new(
            statement,
            cursor.take::<EVM_ACCOUNT_SIGNATURE_BYTES_V1>()?,
            cursor.take::<PARTICIPANT_SIGNATURE_BYTES_V1>()?,
        );
        cursor.finish()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ParticipantBindingErrorV1::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

/// Verified, route-scoped link between one participant and one EVM account.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedEvmAccountBindingV1 {
    statement: EvmAccountBindingStatementV1,
    participant_xonly_key: [u8; 32],
    binding_digest: Digest32,
}

impl AuthenticatedEvmAccountBindingV1 {
    /// Verified statement.
    pub const fn statement(&self) -> EvmAccountBindingStatementV1 {
        self.statement
    }

    /// Roster key that authenticated the participant side of the link.
    pub const fn participant_xonly_key(&self) -> [u8; 32] {
        self.participant_xonly_key
    }

    /// EIP-712 digest signed by both identities.
    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }
}

/// Complete session bindings constructed only from two verified account links.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedEvmSessionBindingsV1 {
    bindings: EvmSessionBindingsV1,
    network_id: Digest32,
    registry_digest: Digest32,
    route_id: Digest32,
    settlement_id: Digest32,
    settlement_terms_digest: Digest32,
    evm_chain_id: u64,
    position: EvmSettlementPositionV1,
    roster_snapshot: Digest32,
    funder_binding_digest: Digest32,
    beneficiary_binding_digest: Digest32,
}

impl AuthenticatedEvmSessionBindingsV1 {
    /// Session facts accepted by the authenticated deployment resolver.
    pub const fn bindings(&self) -> EvmSessionBindingsV1 {
        self.bindings
    }

    /// DOM interoperability network authenticated by both proofs.
    pub const fn network_id(&self) -> Digest32 {
        self.network_id
    }

    /// Deployment registry digest authenticated by both proofs.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }

    /// Composed route authenticated by both proofs.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Settlement authenticated by both proofs.
    pub const fn settlement_id(&self) -> Digest32 {
        self.settlement_id
    }

    /// Canonical digest of the complete settlement terms used during bind.
    pub const fn settlement_terms_digest(&self) -> Digest32 {
        self.settlement_terms_digest
    }

    /// EIP-155 chain id authenticated by both proofs and the EIP-712 domain.
    pub const fn evm_chain_id(&self) -> u64 {
        self.evm_chain_id
    }

    /// Signed settlement position from which `direction` was derived.
    pub const fn position(&self) -> EvmSettlementPositionV1 {
        self.position
    }

    /// Relay roster snapshot shared by both participant proofs.
    pub const fn roster_snapshot(&self) -> Digest32 {
        self.roster_snapshot
    }

    /// Dual-signed proof digest for the funding account.
    pub const fn funder_binding_digest(&self) -> Digest32 {
        self.funder_binding_digest
    }

    /// Dual-signed proof digest for the beneficiary account.
    pub const fn beneficiary_binding_digest(&self) -> Digest32 {
        self.beneficiary_binding_digest
    }
}

/// Fail-closed account/session binding refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParticipantBindingErrorV1 {
    /// A proof artifact was truncated, alternate or had trailing bytes.
    #[error("non-canonical participant binding encoding")]
    NonCanonicalEncoding,
    /// A required identity, account, chain or time field is invalid.
    #[error("invalid participant account binding statement")]
    InvalidStatement,
    /// The ECDSA signature is malformed or uses a non-canonical recovery id.
    #[error("invalid EVM account signature")]
    InvalidEvmSignature,
    /// The ECDSA signature uses the malleable high-s form.
    #[error("malleable EVM account signature")]
    HighEvmSignatureS,
    /// The recovered EVM signer differs from the account in the statement.
    #[error("EVM account signature recovered a different account")]
    WrongEvmSigner,
    /// The BIP340 signature does not verify under the roster key.
    #[error("invalid participant roster signature")]
    InvalidParticipantSignature,
    /// A verified proof does not match the requested route/session authority.
    #[error("participant binding scope mismatch")]
    ScopeMismatch,
    /// Roster entries are zero, duplicated or not in canonical order.
    #[error("invalid ordered participant roster")]
    InvalidRoster,
    /// Funder and beneficiary proofs do not match the settlement roles.
    #[error("participant account roles do not match settlement terms")]
    RoleMismatch,
}

struct ProofCursorV1<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ProofCursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ParticipantBindingErrorV1> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(ParticipantBindingErrorV1::NonCanonicalEncoding)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ParticipantBindingErrorV1::NonCanonicalEncoding)?;
        self.position = end;
        value
            .try_into()
            .map_err(|_| ParticipantBindingErrorV1::NonCanonicalEncoding)
    }

    fn u8(&mut self) -> Result<u8, ParticipantBindingErrorV1> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ParticipantBindingErrorV1> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u64(&mut self) -> Result<u64, ParticipantBindingErrorV1> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn finish(self) -> Result<(), ParticipantBindingErrorV1> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ParticipantBindingErrorV1::NonCanonicalEncoding)
        }
    }
}

/// Computes the canonical EIP-712 digest for one account-link statement.
pub fn evm_account_binding_digest_v1(
    statement: &EvmAccountBindingStatementV1,
) -> Result<Digest32, ParticipantBindingErrorV1> {
    validate_statement(statement)?;
    let domain_separator = domain_separator(statement.evm_chain_id, statement.network_id);
    let struct_hash = statement_hash(statement);
    let mut encoded = [0u8; 66];
    encoded[0] = 0x19;
    encoded[1] = 0x01;
    encoded[2..34].copy_from_slice(&domain_separator);
    encoded[34..].copy_from_slice(&struct_hash);
    Ok(keccak(&encoded))
}

/// Verifies both the EVM account and participant-roster signatures.
pub fn verify_evm_account_binding_v1(
    proof: &EvmAccountBindingProofV1,
    expected_participant_xonly_key: [u8; 32],
    expected_roster_snapshot: Digest32,
    expected_network_id: Digest32,
    expected_registry_digest: Digest32,
    now_seconds: u64,
) -> Result<AuthenticatedEvmAccountBindingV1, ParticipantBindingErrorV1> {
    let statement = proof.statement;
    validate_statement(&statement)?;
    if expected_participant_xonly_key == [0; 32]
        || expected_roster_snapshot == [0; 32]
        || expected_network_id == [0; 32]
        || expected_registry_digest == [0; 32]
        || statement.network_id != expected_network_id
        || statement.registry_digest != expected_registry_digest
        || statement.roster_snapshot != expected_roster_snapshot
        || statement.participant_xonly_key != expected_participant_xonly_key
        || now_seconds < statement.issued_at
        || now_seconds > statement.valid_until
    {
        return Err(ParticipantBindingErrorV1::ScopeMismatch);
    }
    let digest = evm_account_binding_digest_v1(&statement)?;
    verify_evm_signature(statement.account, digest, &proof.evm_signature)?;
    let secp = SecpContext::new(&VERIFICATION_CONTEXT_SEED);
    secp.verify_bip340(
        &expected_participant_xonly_key,
        &digest,
        &proof.participant_signature,
    )
    .map_err(|_| ParticipantBindingErrorV1::InvalidParticipantSignature)?;
    Ok(AuthenticatedEvmAccountBindingV1 {
        statement,
        participant_xonly_key: expected_participant_xonly_key,
        binding_digest: digest,
    })
}

/// Derives `participantsHash` from the exact ordered two-party roster.
pub fn evm_participants_hash_v1(
    roster: [ParticipantId; 2],
) -> Result<Digest32, ParticipantBindingErrorV1> {
    validate_roster(roster)?;
    let mut bytes = Vec::with_capacity(ROSTER_DOMAIN.len() + 64);
    bytes.extend_from_slice(ROSTER_DOMAIN);
    bytes.extend_from_slice(&roster[0].0);
    bytes.extend_from_slice(&roster[1].0);
    Ok(keccak(&bytes))
}

/// Produces complete EVM session facts after matching both verified account
/// links to the canonical settlement roster and economic roles.
#[allow(clippy::too_many_arguments)]
pub fn bind_evm_session_v1(
    terms: &SettlementTermsV1,
    route_id: Digest32,
    frozen_terms_digest: Digest32,
    expected_position: EvmSettlementPositionV1,
    evm_chain_id: u64,
    network_id: Digest32,
    registry_digest: Digest32,
    now_seconds: u64,
    funder: &AuthenticatedEvmAccountBindingV1,
    beneficiary: &AuthenticatedEvmAccountBindingV1,
) -> Result<AuthenticatedEvmSessionBindingsV1, ParticipantBindingErrorV1> {
    terms
        .validate()
        .map_err(|_| ParticipantBindingErrorV1::ScopeMismatch)?;
    let settlement_terms_digest = terms
        .terms_hash()
        .map_err(|_| ParticipantBindingErrorV1::ScopeMismatch)?;
    validate_roster(terms.roster)?;
    if route_id == [0; 32]
        || frozen_terms_digest == [0; 32]
        || evm_chain_id == 0
        || network_id == [0; 32]
        || registry_digest == [0; 32]
    {
        return Err(ParticipantBindingErrorV1::ScopeMismatch);
    }
    let expected_common = |binding: &AuthenticatedEvmAccountBindingV1| {
        let statement = binding.statement;
        statement.network_id == network_id
            && statement.registry_digest == registry_digest
            && statement.route_id == route_id
            && statement.settlement_id == terms.settlement_id.0
            && statement.session_id == terms.session_id.0
            && statement.terms_digest == frozen_terms_digest
            && statement.position == expected_position
            && statement.evm_chain_id == evm_chain_id
            && now_seconds >= statement.issued_at
            && now_seconds <= statement.valid_until
            && terms.roster.contains(&statement.participant_id)
    };
    if !expected_common(funder) || !expected_common(beneficiary) {
        return Err(ParticipantBindingErrorV1::ScopeMismatch);
    }
    if funder.statement.role != EvmBindingRoleV1::Funder
        || beneficiary.statement.role != EvmBindingRoleV1::Beneficiary
        || funder.statement.roster_snapshot != beneficiary.statement.roster_snapshot
        || funder.statement.participant_id != terms.counterparty_leg.refund_to
        || beneficiary.statement.participant_id != terms.counterparty_leg.beneficiary
        || funder.statement.participant_id == beneficiary.statement.participant_id
        || funder.statement.participant_xonly_key == beneficiary.statement.participant_xonly_key
        || funder.statement.account == beneficiary.statement.account
    {
        return Err(ParticipantBindingErrorV1::RoleMismatch);
    }
    let participants_hash = evm_participants_hash_v1(terms.roster)?;
    Ok(AuthenticatedEvmSessionBindingsV1 {
        bindings: EvmSessionBindingsV1 {
            direction: expected_position.direction(),
            session_id: terms.session_id.0,
            terms_hash: frozen_terms_digest,
            participants_hash,
            beneficiary: beneficiary.statement.account,
            funder: funder.statement.account,
        },
        network_id,
        registry_digest,
        route_id,
        settlement_id: terms.settlement_id.0,
        settlement_terms_digest,
        evm_chain_id,
        position: expected_position,
        roster_snapshot: funder.statement.roster_snapshot,
        funder_binding_digest: funder.binding_digest,
        beneficiary_binding_digest: beneficiary.binding_digest,
    })
}

fn validate_statement(
    statement: &EvmAccountBindingStatementV1,
) -> Result<(), ParticipantBindingErrorV1> {
    if statement.network_id == [0; 32]
        || statement.registry_digest == [0; 32]
        || statement.route_id == [0; 32]
        || statement.settlement_id == [0; 32]
        || statement.session_id == [0; 32]
        || statement.terms_digest == [0; 32]
        || statement.roster_snapshot == [0; 32]
        || statement.participant_id.0 == [0; 32]
        || statement.participant_xonly_key == [0; 32]
        || statement.account == [0; 20]
        || statement.issued_at == 0
        || statement.issued_at > statement.valid_until
        || statement.evm_chain_id == 0
    {
        return Err(ParticipantBindingErrorV1::InvalidStatement);
    }
    Ok(())
}

fn validate_roster(roster: [ParticipantId; 2]) -> Result<(), ParticipantBindingErrorV1> {
    if roster[0].0 == [0; 32] || roster[0] >= roster[1] {
        return Err(ParticipantBindingErrorV1::InvalidRoster);
    }
    Ok(())
}

fn domain_separator(chain_id: u64, network_id: Digest32) -> Digest32 {
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&keccak(DOMAIN_TYPE));
    encoded.extend_from_slice(&keccak(DOMAIN_NAME));
    encoded.extend_from_slice(&keccak(DOMAIN_VERSION));
    push_u64_word(&mut encoded, chain_id);
    encoded.extend_from_slice(&network_id);
    keccak(&encoded)
}

fn statement_hash(statement: &EvmAccountBindingStatementV1) -> Digest32 {
    let mut encoded = Vec::with_capacity(32 * 17);
    encoded.extend_from_slice(&keccak(BINDING_TYPE));
    encoded.extend_from_slice(&statement.network_id);
    encoded.extend_from_slice(&statement.registry_digest);
    encoded.extend_from_slice(&statement.route_id);
    encoded.extend_from_slice(&statement.settlement_id);
    encoded.extend_from_slice(&statement.session_id);
    encoded.extend_from_slice(&statement.terms_digest);
    encoded.extend_from_slice(&statement.roster_snapshot);
    encoded.extend_from_slice(&statement.participant_id.0);
    encoded.extend_from_slice(&statement.participant_xonly_key);
    push_address_word(&mut encoded, statement.account);
    push_u8_word(&mut encoded, statement.position.tag());
    push_u8_word(&mut encoded, statement.role.tag());
    push_u64_word(&mut encoded, statement.issued_at);
    push_u64_word(&mut encoded, statement.valid_until);
    push_u64_word(&mut encoded, statement.evm_chain_id);
    keccak(&encoded)
}

fn verify_evm_signature(
    expected_account: [u8; 20],
    digest: Digest32,
    signature: &[u8; EVM_ACCOUNT_SIGNATURE_BYTES_V1],
) -> Result<(), ParticipantBindingErrorV1> {
    let parsed = Signature::from_slice(&signature[..64])
        .map_err(|_| ParticipantBindingErrorV1::InvalidEvmSignature)?;
    if parsed.normalize_s().is_some() {
        return Err(ParticipantBindingErrorV1::HighEvmSignatureS);
    }
    let recovery_byte = match signature[64] {
        27 | 28 => signature[64] - 27,
        _ => return Err(ParticipantBindingErrorV1::InvalidEvmSignature),
    };
    let recovery = RecoveryId::from_byte(recovery_byte)
        .ok_or(ParticipantBindingErrorV1::InvalidEvmSignature)?;
    let key = VerifyingKey::recover_from_prehash(&digest, &parsed, recovery)
        .map_err(|_| ParticipantBindingErrorV1::InvalidEvmSignature)?;
    let encoded = key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ParticipantBindingErrorV1::InvalidEvmSignature);
    }
    let hash = keccak(&bytes[1..]);
    let mut recovered = [0u8; 20];
    recovered.copy_from_slice(&hash[12..]);
    if recovered == [0; 20] || recovered != expected_account {
        return Err(ParticipantBindingErrorV1::WrongEvmSigner);
    }
    Ok(())
}

fn push_address_word(output: &mut Vec<u8>, value: [u8; 20]) {
    output.extend_from_slice(&[0; 12]);
    output.extend_from_slice(&value);
}

fn push_u8_word(output: &mut Vec<u8>, value: u8) {
    output.extend_from_slice(&[0; 31]);
    output.push(value);
}

fn push_u64_word(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&[0; 24]);
    output.extend_from_slice(&value.to_be_bytes());
}

fn keccak(bytes: &[u8]) -> Digest32 {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use kaystra_core::types::{
        AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
        LockMechanism, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
    };

    const NETWORK: Digest32 = [0x11; 32];
    const REGISTRY: Digest32 = [0x12; 32];
    const ROUTE: Digest32 = [0x13; 32];
    const FROZEN_TERMS: Digest32 = [0x14; 32];
    const ROSTER_SNAPSHOT: Digest32 = [0x15; 32];
    const NOW: u64 = 1_900_000_000;
    const SECP256K1_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    struct SignedFixture {
        proof: EvmAccountBindingProofV1,
        xonly: [u8; 32],
    }

    fn participant(value: u8) -> ParticipantId {
        ParticipantId([value; 32])
    }

    fn subtract_be(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut output = [0; 32];
        let mut borrow = 0u16;
        for index in (0..32).rev() {
            let minuend = u16::from(left[index]);
            let subtrahend = u16::from(right[index]) + borrow;
            if minuend >= subtrahend {
                output[index] = (minuend - subtrahend) as u8;
                borrow = 0;
            } else {
                output[index] = (minuend + 256 - subtrahend) as u8;
                borrow = 1;
            }
        }
        assert_eq!(borrow, 0);
        output
    }

    fn terms() -> SettlementTermsV1 {
        let funder = participant(0x21);
        let beneficiary = participant(0x31);
        SettlementTermsV1 {
            settlement_id: SettlementId([0x41; 32]),
            session_id: SessionId([0x42; 32]),
            intent_hash: IntentHash([0x43; 32]),
            solver_id: SolverId([0x44; 32]),
            roster: [funder, beneficiary],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId([0x45; 32]),
                asset_id: AssetId([0x46; 32]),
                amount: 100,
                beneficiary,
                refund_to: funder,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 1_000 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 6,
                    max_reorg_depth: 12,
                },
                adapter_profile_hash: [0x47; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId([0x48; 32]),
                asset_id: AssetId([0x49; 32]),
                amount: 200,
                beneficiary,
                refund_to: funder,
                mechanism: LockMechanism::ConditionLock,
                deadline: TimelockSpec::TimestampSeconds {
                    value: NOW + 10_000,
                },
                finality: FinalityPolicyV1 {
                    min_confirmations: 1,
                    max_reorg_depth: 2,
                },
                adapter_profile_hash: [0x4A; 32],
            },
            adaptor_point_sec1: {
                let mut point = [0x4B; 33];
                point[0] = 0x02;
                point
            },
            fee_limit: FeeLimitV1 {
                dom_max: 10,
                counterparty_max: 10,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 20,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: Vec::new(),
        }
    }

    fn evm_account(secret: [u8; 32]) -> [u8; 20] {
        let key = SigningKey::from_slice(&secret).expect("valid EVM test key");
        let encoded = key.verifying_key().to_encoded_point(false);
        let hash = keccak(&encoded.as_bytes()[1..]);
        let mut account = [0; 20];
        account.copy_from_slice(&hash[12..]);
        account
    }

    fn signed(
        participant_id: ParticipantId,
        role: EvmBindingRoleV1,
        position: EvmSettlementPositionV1,
        evm_secret: [u8; 32],
        participant_secret: [u8; 32],
    ) -> SignedFixture {
        let settlement = terms();
        let secp = SecpContext::new(&[0x51; 32]);
        let (_, xonly) = secp
            .sign_bip340(&participant_secret, &[0x53; 32], &[0x54; 32])
            .expect("participant public key");
        let statement = EvmAccountBindingStatementV1 {
            network_id: NETWORK,
            registry_digest: REGISTRY,
            route_id: ROUTE,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_digest: FROZEN_TERMS,
            roster_snapshot: ROSTER_SNAPSHOT,
            participant_id,
            participant_xonly_key: xonly,
            account: evm_account(evm_secret),
            position,
            role,
            issued_at: NOW - 100,
            valid_until: NOW + 100,
            evm_chain_id: 31_337,
        };
        let digest = evm_account_binding_digest_v1(&statement).expect("binding digest");
        let signing = SigningKey::from_slice(&evm_secret).expect("valid EVM test key");
        let (signature, recovery) = signing
            .sign_prehash_recoverable(&digest)
            .expect("EVM signature");
        let mut evm_signature = [0; EVM_ACCOUNT_SIGNATURE_BYTES_V1];
        evm_signature[..64].copy_from_slice(&signature.to_bytes());
        evm_signature[64] = 27 + recovery.to_byte();
        let (participant_signature, signed_xonly) = secp
            .sign_bip340(&participant_secret, &digest, &[0x52; 32])
            .expect("participant signature");
        assert_eq!(signed_xonly, xonly);
        SignedFixture {
            proof: EvmAccountBindingProofV1::new(statement, evm_signature, participant_signature),
            xonly,
        }
    }

    fn authenticate(fixture: &SignedFixture) -> AuthenticatedEvmAccountBindingV1 {
        verify_evm_account_binding_v1(
            &fixture.proof,
            fixture.xonly,
            ROSTER_SNAPSHOT,
            NETWORK,
            REGISTRY,
            NOW,
        )
        .expect("dual proof")
    }

    #[test]
    fn eip712_digest_matches_independent_cast_vector() {
        // Generated independently with `cast abi-encode` + `cast keccak` over
        // the declared EIP-712 domain and struct types. This catches a
        // self-consistent field-order or ABI-word bug that sign/verify tests
        // implemented by this crate alone would not detect.
        let statement = EvmAccountBindingStatementV1 {
            network_id: [0x11; 32],
            registry_digest: [0x12; 32],
            route_id: [0x13; 32],
            settlement_id: [0x41; 32],
            session_id: [0x42; 32],
            terms_digest: [0x14; 32],
            roster_snapshot: [0x15; 32],
            participant_id: ParticipantId([0x21; 32]),
            participant_xonly_key: [0x22; 32],
            account: [0x33; 20],
            position: EvmSettlementPositionV1::Upstream,
            role: EvmBindingRoleV1::Beneficiary,
            issued_at: 1_899_999_900,
            valid_until: 1_900_000_100,
            evm_chain_id: 31_337,
        };
        assert_eq!(
            evm_account_binding_digest_v1(&statement).expect("valid vector"),
            [
                0x47, 0xfa, 0x4c, 0xbf, 0xb7, 0x9e, 0x83, 0xfb, 0xb1, 0x04, 0x82, 0x8f, 0xb6, 0x3c,
                0xab, 0xb2, 0x8a, 0xdd, 0x73, 0x1e, 0x60, 0x50, 0xba, 0xb0, 0xae, 0x00, 0x57, 0x24,
                0xe6, 0xbc, 0x4e, 0xd1,
            ]
        );
    }

    #[test]
    fn dual_signed_accounts_produce_the_only_complete_session_binding() {
        let settlement = terms();
        let funder = signed(
            settlement.counterparty_leg.refund_to,
            EvmBindingRoleV1::Funder,
            EvmSettlementPositionV1::Upstream,
            [0x61; 32],
            [0x62; 32],
        );
        let beneficiary = signed(
            settlement.counterparty_leg.beneficiary,
            EvmBindingRoleV1::Beneficiary,
            EvmSettlementPositionV1::Upstream,
            [0x71; 32],
            [0x72; 32],
        );
        let funder_authority = authenticate(&funder);
        let beneficiary_authority = authenticate(&beneficiary);
        let session = bind_evm_session_v1(
            &settlement,
            ROUTE,
            FROZEN_TERMS,
            EvmSettlementPositionV1::Upstream,
            31_337,
            NETWORK,
            REGISTRY,
            NOW,
            &funder_authority,
            &beneficiary_authority,
        )
        .expect("complete session binding");
        let bindings = session.bindings();
        assert_eq!(bindings.session_id, settlement.session_id.0);
        assert_eq!(bindings.terms_hash, FROZEN_TERMS);
        assert_eq!(bindings.direction, Direction::EvmToDom);
        assert_eq!(session.position(), EvmSettlementPositionV1::Upstream);
        assert_eq!(session.roster_snapshot(), ROSTER_SNAPSHOT);
        assert_eq!(bindings.funder, funder.proof.statement.account);
        assert_eq!(bindings.beneficiary, beneficiary.proof.statement.account);
        assert_eq!(
            bindings.participants_hash,
            evm_participants_hash_v1(settlement.roster).expect("roster hash")
        );
        assert_eq!(
            session.funder_binding_digest(),
            funder_authority.binding_digest()
        );
        assert_eq!(
            session.beneficiary_binding_digest(),
            beneficiary_authority.binding_digest()
        );
    }

    #[test]
    fn either_signature_or_any_scope_tamper_is_refused() {
        let base = signed(
            participant(0x21),
            EvmBindingRoleV1::Funder,
            EvmSettlementPositionV1::Upstream,
            [0x61; 32],
            [0x62; 32],
        );
        assert!(verify_evm_account_binding_v1(
            &base.proof,
            base.xonly,
            ROSTER_SNAPSHOT,
            NETWORK,
            REGISTRY,
            NOW
        )
        .is_ok());

        let mut wrong_evm = base.proof.clone();
        wrong_evm.evm_signature[0] ^= 1;
        assert!(matches!(
            verify_evm_account_binding_v1(
                &wrong_evm,
                base.xonly,
                ROSTER_SNAPSHOT,
                NETWORK,
                REGISTRY,
                NOW
            ),
            Err(ParticipantBindingErrorV1::InvalidEvmSignature)
                | Err(ParticipantBindingErrorV1::WrongEvmSigner)
        ));

        let mut wrong_participant = base.proof.clone();
        wrong_participant.participant_signature[0] ^= 1;
        assert_eq!(
            verify_evm_account_binding_v1(
                &wrong_participant,
                base.xonly,
                ROSTER_SNAPSHOT,
                NETWORK,
                REGISTRY,
                NOW
            ),
            Err(ParticipantBindingErrorV1::InvalidParticipantSignature)
        );

        let mut changed_statement = base.proof.clone();
        changed_statement.statement.route_id[0] ^= 1;
        assert!(verify_evm_account_binding_v1(
            &changed_statement,
            base.xonly,
            ROSTER_SNAPSHOT,
            NETWORK,
            REGISTRY,
            NOW
        )
        .is_err());
        assert_eq!(
            verify_evm_account_binding_v1(
                &base.proof,
                base.xonly,
                ROSTER_SNAPSHOT,
                NETWORK,
                REGISTRY,
                NOW + 101
            ),
            Err(ParticipantBindingErrorV1::ScopeMismatch)
        );
        assert_eq!(
            verify_evm_account_binding_v1(
                &base.proof,
                base.xonly,
                [0x16; 32],
                NETWORK,
                REGISTRY,
                NOW
            ),
            Err(ParticipantBindingErrorV1::ScopeMismatch)
        );
        let mut wrong_roster_key = base.xonly;
        wrong_roster_key[0] ^= 1;
        assert_eq!(
            verify_evm_account_binding_v1(
                &base.proof,
                wrong_roster_key,
                ROSTER_SNAPSHOT,
                NETWORK,
                REGISTRY,
                NOW
            ),
            Err(ParticipantBindingErrorV1::ScopeMismatch)
        );
        let mut invalid_v = base.proof.clone();
        invalid_v.evm_signature[64] = 1;
        assert_eq!(
            verify_evm_account_binding_v1(
                &invalid_v,
                base.xonly,
                ROSTER_SNAPSHOT,
                NETWORK,
                REGISTRY,
                NOW
            ),
            Err(ParticipantBindingErrorV1::InvalidEvmSignature)
        );
        let mut high_s = base.proof.clone();
        let mut low_s = [0; 32];
        low_s.copy_from_slice(&high_s.evm_signature[32..64]);
        high_s.evm_signature[32..64].copy_from_slice(&subtract_be(SECP256K1_ORDER, low_s));
        high_s.evm_signature[64] = if high_s.evm_signature[64] == 27 {
            28
        } else {
            27
        };
        assert_eq!(
            verify_evm_account_binding_v1(
                &high_s,
                base.xonly,
                ROSTER_SNAPSHOT,
                NETWORK,
                REGISTRY,
                NOW
            ),
            Err(ParticipantBindingErrorV1::HighEvmSignatureS)
        );
    }

    #[test]
    fn wrong_roles_roster_and_cross_session_reuse_are_refused() {
        let settlement = terms();
        let funder = authenticate(&signed(
            settlement.counterparty_leg.refund_to,
            EvmBindingRoleV1::Funder,
            EvmSettlementPositionV1::Upstream,
            [0x61; 32],
            [0x62; 32],
        ));
        let beneficiary = authenticate(&signed(
            settlement.counterparty_leg.beneficiary,
            EvmBindingRoleV1::Beneficiary,
            EvmSettlementPositionV1::Upstream,
            [0x71; 32],
            [0x72; 32],
        ));
        assert_eq!(
            bind_evm_session_v1(
                &settlement,
                ROUTE,
                FROZEN_TERMS,
                EvmSettlementPositionV1::Upstream,
                31_337,
                NETWORK,
                REGISTRY,
                NOW,
                &beneficiary,
                &funder,
            ),
            Err(ParticipantBindingErrorV1::RoleMismatch)
        );

        let mut other_session = settlement.clone();
        other_session.session_id.0[0] ^= 1;
        assert_eq!(
            bind_evm_session_v1(
                &other_session,
                ROUTE,
                FROZEN_TERMS,
                EvmSettlementPositionV1::Upstream,
                31_337,
                NETWORK,
                REGISTRY,
                NOW,
                &funder,
                &beneficiary,
            ),
            Err(ParticipantBindingErrorV1::ScopeMismatch)
        );
        assert_eq!(
            bind_evm_session_v1(
                &settlement,
                ROUTE,
                FROZEN_TERMS,
                EvmSettlementPositionV1::Downstream,
                31_337,
                NETWORK,
                REGISTRY,
                NOW,
                &funder,
                &beneficiary,
            ),
            Err(ParticipantBindingErrorV1::ScopeMismatch)
        );
        assert_eq!(
            bind_evm_session_v1(
                &settlement,
                ROUTE,
                FROZEN_TERMS,
                EvmSettlementPositionV1::Upstream,
                31_337,
                NETWORK,
                REGISTRY,
                NOW + 101,
                &funder,
                &beneficiary,
            ),
            Err(ParticipantBindingErrorV1::ScopeMismatch)
        );
        assert_eq!(
            evm_participants_hash_v1([participant(0x31), participant(0x21)]),
            Err(ParticipantBindingErrorV1::InvalidRoster)
        );
    }

    #[test]
    fn proof_codec_roundtrips_and_rejects_trailing_or_unknown_tags() {
        let settlement = terms();
        let fixture = signed(
            settlement.counterparty_leg.refund_to,
            EvmBindingRoleV1::Funder,
            EvmSettlementPositionV1::Upstream,
            [0x61; 32],
            [0x62; 32],
        );
        let bytes = fixture.proof.canonical_bytes().expect("canonical proof");
        assert_eq!(bytes.len(), EVM_ACCOUNT_BINDING_PROOF_BYTES_V1);
        assert_eq!(
            EvmAccountBindingProofV1::decode_canonical(&bytes),
            Ok(fixture.proof.clone())
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            EvmAccountBindingProofV1::decode_canonical(&trailing),
            Err(ParticipantBindingErrorV1::NonCanonicalEncoding)
        );

        let mut unknown_role = bytes;
        // Header + nine bytes32 fields + address + position.
        unknown_role[12 + 9 * 32 + 20 + 1] = 3;
        assert_eq!(
            EvmAccountBindingProofV1::decode_canonical(&unknown_role),
            Err(ParticipantBindingErrorV1::NonCanonicalEncoding)
        );
    }
}

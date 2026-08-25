//! PROVISIONAL/NON-NORMATIVE Relay V2 Scriptless wire candidate.
//!
//! Status: **D-030 PROPOSED — AWAITS EXPLICIT OPERATOR RATIFICATION**.
//!
//! This default-off, Store-free leaf is deliberately not a normative
//! protocol. It does not supersede D-018/D-019, does not modify Relay V1, and
//! does not authorize any caller to remove a transport blocker. Its only
//! purpose is to make the candidate envelope, frame, roster, recipient, ACK,
//! digest, and fail-closed validation choices concrete enough to review.
//! It does not claim conformance with a separately drafted LAB proposal;
//! conflicting provisional profiles require an explicit operator selection.
//!
//! The crate signs nothing and holds no secret key. When the explicit
//! `provisional-non-normative-v2` feature is enabled it verifies public
//! signatures through the already pinned `btc-crypto` BIP340 API. With the
//! feature disabled, cryptographic validation refuses every envelope and ACK.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

/// PROVISIONAL/NON-NORMATIVE candidate status; this is not ratification.
pub const PROVISIONAL_NON_NORMATIVE_STATUS_V2: &str =
    "PROVISIONAL/NON-NORMATIVE — D-030 PROPOSED — AWAITS EXPLICIT OPERATOR RATIFICATION";

/// PROVISIONAL/NON-NORMATIVE candidate envelope magic; Relay V1 is unchanged.
pub const PROVISIONAL_NON_NORMATIVE_ENVELOPE_MAGIC_V2: &[u8; 8] = b"DOMIRLY2";
/// PROVISIONAL/NON-NORMATIVE candidate frame magic.
pub const PROVISIONAL_NON_NORMATIVE_FRAME_MAGIC_V2: &[u8; 8] = b"DOMIRF2!";
/// PROVISIONAL/NON-NORMATIVE candidate ACK magic.
pub const PROVISIONAL_NON_NORMATIVE_ACK_MAGIC_V2: &[u8; 8] = b"DOMIRA2!";
/// PROVISIONAL/NON-NORMATIVE candidate roster magic.
pub const PROVISIONAL_NON_NORMATIVE_ROSTER_MAGIC_V2: &[u8; 8] = b"DOMIRR2!";
/// PROVISIONAL/NON-NORMATIVE candidate wire version.
pub const PROVISIONAL_NON_NORMATIVE_WIRE_VERSION_V2: u16 = 2;
/// PROVISIONAL/NON-NORMATIVE candidate flags; every other bit fails closed.
pub const PROVISIONAL_NON_NORMATIVE_FLAGS_V2: u16 = 0;

/// PROVISIONAL/NON-NORMATIVE domain for ciphertext hashes.
pub const PROVISIONAL_NON_NORMATIVE_CIPHERTEXT_DOMAIN_V2: &[u8] =
    b"PROVISIONAL/NON-NORMATIVE/DOM-INTEROP/RELAY-V2/CIPHERTEXT\0";
/// PROVISIONAL/NON-NORMATIVE domain for frame digests.
pub const PROVISIONAL_NON_NORMATIVE_FRAME_DOMAIN_V2: &[u8] =
    b"PROVISIONAL/NON-NORMATIVE/DOM-INTEROP/RELAY-V2/FRAME\0";
/// PROVISIONAL/NON-NORMATIVE domain for signed envelope digests.
pub const PROVISIONAL_NON_NORMATIVE_ENVELOPE_DOMAIN_V2: &[u8] =
    b"PROVISIONAL/NON-NORMATIVE/DOM-INTEROP/RELAY-V2/ENVELOPE\0";
/// PROVISIONAL/NON-NORMATIVE domain for signed ACK digests.
pub const PROVISIONAL_NON_NORMATIVE_ACK_DOMAIN_V2: &[u8] =
    b"PROVISIONAL/NON-NORMATIVE/DOM-INTEROP/RELAY-V2/ACK\0";
/// PROVISIONAL/NON-NORMATIVE domain for roster snapshot digests.
pub const PROVISIONAL_NON_NORMATIVE_ROSTER_DOMAIN_V2: &[u8] =
    b"PROVISIONAL/NON-NORMATIVE/DOM-INTEROP/RELAY-V2/ROSTER\0";

/// PROVISIONAL/NON-NORMATIVE maximum Noise ciphertext bytes in one frame.
pub const PROVISIONAL_NON_NORMATIVE_MAX_CIPHERTEXT_BYTES_V2: usize = 16_384;
/// PROVISIONAL/NON-NORMATIVE fixed bytes in a standalone frame.
pub const PROVISIONAL_NON_NORMATIVE_FRAME_OVERHEAD_BYTES_V2: usize = 8 + 2 + 2 + 2 + 4 + 32;
/// PROVISIONAL/NON-NORMATIVE maximum standalone frame bytes.
pub const PROVISIONAL_NON_NORMATIVE_MAX_FRAME_BYTES_V2: usize =
    PROVISIONAL_NON_NORMATIVE_FRAME_OVERHEAD_BYTES_V2
        + PROVISIONAL_NON_NORMATIVE_MAX_CIPHERTEXT_BYTES_V2;
/// PROVISIONAL/NON-NORMATIVE fixed envelope bytes outside the frame.
pub const PROVISIONAL_NON_NORMATIVE_ENVELOPE_OVERHEAD_BYTES_V2: usize =
    8 + 2 + 2 + 32 + 32 + 32 + 32 + 32 + 32 + 1 + 8 + 8 + 32 + 8 + 4 + 64;
/// PROVISIONAL/NON-NORMATIVE maximum complete envelope bytes.
pub const PROVISIONAL_NON_NORMATIVE_MAX_ENVELOPE_BYTES_V2: usize =
    PROVISIONAL_NON_NORMATIVE_ENVELOPE_OVERHEAD_BYTES_V2
        + PROVISIONAL_NON_NORMATIVE_MAX_FRAME_BYTES_V2;
/// PROVISIONAL/NON-NORMATIVE exact ACK wire length.
pub const PROVISIONAL_NON_NORMATIVE_ACK_BYTES_V2: usize =
    8 + 2 + 2 + 32 + 32 + 32 + 32 + 32 + 32 + 1 + 8 + 8 + 32 + 1 + 64;
/// PROVISIONAL/NON-NORMATIVE exact two-member roster wire length.
pub const PROVISIONAL_NON_NORMATIVE_ROSTER_BYTES_V2: usize =
    8 + 2 + 2 + 32 + 32 + 32 + 2 + (2 * (32 + 1 + 32));
/// PROVISIONAL/NON-NORMATIVE roster size candidate: exactly two participants.
pub const PROVISIONAL_NON_NORMATIVE_ROSTER_MEMBER_COUNT_V2: usize = 2;

const PROVISIONAL_NON_NORMATIVE_ROLE_INITIATOR_TAG_V2: u8 = 0x01;
const PROVISIONAL_NON_NORMATIVE_ROLE_RESPONDER_TAG_V2: u8 = 0x02;
const PROVISIONAL_NON_NORMATIVE_KIND_INITIATOR_HANDSHAKE_TAG_V2: u16 = 0x1001;
const PROVISIONAL_NON_NORMATIVE_KIND_RESPONDER_HANDSHAKE_TAG_V2: u16 = 0x1002;
const PROVISIONAL_NON_NORMATIVE_KIND_TRANSPORT_TAG_V2: u16 = 0x1003;
const PROVISIONAL_NON_NORMATIVE_KIND_EPOCH_CLOSE_TAG_V2: u16 = 0x1004;
const PROVISIONAL_NON_NORMATIVE_ACK_PERSISTED_TAG_V2: u8 = 0x01;
const PROVISIONAL_NON_NORMATIVE_ACK_DUPLICATE_TAG_V2: u8 = 0x02;

/// Returns the explicit PROVISIONAL/NON-NORMATIVE status string.
pub const fn provisional_non_normative_candidate_status_v2() -> &'static str {
    PROVISIONAL_NON_NORMATIVE_STATUS_V2
}

/// Fail-closed errors of the PROVISIONAL/NON-NORMATIVE candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ProvisionalNonNormativeWireErrorV2 {
    /// A complete object exceeds its PROVISIONAL/NON-NORMATIVE bound.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 object exceeds its bound")]
    ObjectTooLarge,
    /// A ciphertext is empty or exceeds its PROVISIONAL/NON-NORMATIVE bound.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 ciphertext has invalid length")]
    InvalidCiphertextLength,
    /// The input does not begin with the expected candidate magic.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 magic is invalid")]
    InvalidMagic,
    /// The candidate version is not exactly V2.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 version is invalid")]
    InvalidVersion,
    /// A flag bit is outside the closed candidate set.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 flags are unknown")]
    UnknownFlags,
    /// A role tag is outside the closed candidate set.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 role is unknown")]
    UnknownRole,
    /// A frame-kind tag is outside the closed candidate set.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 frame kind is unknown")]
    UnknownFrameKind,
    /// An ACK status tag is outside the closed candidate set.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 ACK status is unknown")]
    UnknownAckStatus,
    /// The object ends before every candidate field is present.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 encoding is truncated")]
    Truncated,
    /// The object has bytes after the exact candidate encoding.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 encoding has trailing bytes")]
    TrailingBytes,
    /// A declared embedded length differs from the strict candidate length.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 declared length is invalid")]
    LengthMismatch,
    /// A ciphertext or embedded frame digest does not match the bytes.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 digest does not match")]
    DigestMismatch,
    /// A scope identifier is all zeroes.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 route scope is invalid")]
    InvalidScope,
    /// A participant identifier or x-only key is all zeroes.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 participant is invalid")]
    InvalidParticipant,
    /// The candidate roster is not exactly one initiator and one responder.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 roster is invalid")]
    InvalidRoster,
    /// Sender and recipient are not distinct.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 sender equals recipient")]
    SenderIsRecipient,
    /// The role is not permitted to emit this closed candidate frame kind.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 role cannot emit this frame kind")]
    RoleNotPermitted,
    /// Epoch, sequence, predecessor, or expiry fields are internally invalid.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 flow position is invalid")]
    InvalidFlow,
    /// A required signature was not attached.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 signature is absent")]
    MissingSignature,
    /// The envelope does not match the expected route scope.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 route scope does not match")]
    WrongScope,
    /// The envelope does not match the authenticated roster snapshot.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 roster does not match")]
    WrongRoster,
    /// The envelope is addressed to another recipient.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 recipient does not match")]
    WrongRecipient,
    /// The sender is absent from the authenticated roster.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 sender is not in the roster")]
    UnknownSender,
    /// The sender's envelope role differs from its authenticated roster role.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 sender role does not match")]
    WrongSenderRole,
    /// The epoch does not match the recipient's expected epoch.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 epoch does not match")]
    WrongEpoch,
    /// The sequence is not the recipient's exact next sequence.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 sequence does not match")]
    WrongSequence,
    /// The predecessor digest is not the recipient's exact transcript tip.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 predecessor does not match")]
    WrongPredecessor,
    /// The candidate envelope expired before validation.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 envelope is expired")]
    Expired,
    /// BLAKE2b-256 initialization failed.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 hash initialization failed")]
    HashInitialization,
    /// The default-off build cannot perform the required BIP340 check.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 cryptography is default-off")]
    CryptographyUnavailable,
    /// The pinned BIP340 backend rejected the signature or x-only key.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 BIP340 signature is invalid")]
    InvalidSignature,
    /// The ACK does not refer to the exact envelope and opposite participant.
    #[error("PROVISIONAL/NON-NORMATIVE Relay V2 ACK reference does not match")]
    WrongAckReference,
}

/// PROVISIONAL/NON-NORMATIVE participant identifier with private bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProvisionalNonNormativeParticipantIdV2([u8; 32]);

impl ProvisionalNonNormativeParticipantIdV2 {
    /// Constructs a nonzero PROVISIONAL/NON-NORMATIVE participant identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if !nonzero_32(&bytes) {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidParticipant);
        }
        Ok(Self(bytes))
    }

    /// Returns the public participant identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ProvisionalNonNormativeParticipantIdV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeParticipantIdV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("identifier", &"<redacted:32>")
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE closed sender-role candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProvisionalNonNormativeRoleV2 {
    /// PROVISIONAL/NON-NORMATIVE F6-selected route initiator.
    Initiator,
    /// PROVISIONAL/NON-NORMATIVE F6-selected route responder.
    Responder,
}

impl ProvisionalNonNormativeRoleV2 {
    fn tag(self) -> u8 {
        match self {
            Self::Initiator => PROVISIONAL_NON_NORMATIVE_ROLE_INITIATOR_TAG_V2,
            Self::Responder => PROVISIONAL_NON_NORMATIVE_ROLE_RESPONDER_TAG_V2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        match tag {
            PROVISIONAL_NON_NORMATIVE_ROLE_INITIATOR_TAG_V2 => Ok(Self::Initiator),
            PROVISIONAL_NON_NORMATIVE_ROLE_RESPONDER_TAG_V2 => Ok(Self::Responder),
            _ => Err(ProvisionalNonNormativeWireErrorV2::UnknownRole),
        }
    }
}

/// PROVISIONAL/NON-NORMATIVE closed Noise-frame kind candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProvisionalNonNormativeFrameKindV2 {
    /// PROVISIONAL/NON-NORMATIVE initiator Noise handshake bytes.
    InitiatorHandshake,
    /// PROVISIONAL/NON-NORMATIVE responder Noise handshake bytes.
    ResponderHandshake,
    /// PROVISIONAL/NON-NORMATIVE established Noise transport ciphertext.
    Transport,
    /// PROVISIONAL/NON-NORMATIVE authenticated epoch-close ciphertext.
    EpochClose,
}

impl ProvisionalNonNormativeFrameKindV2 {
    fn tag(self) -> u16 {
        match self {
            Self::InitiatorHandshake => PROVISIONAL_NON_NORMATIVE_KIND_INITIATOR_HANDSHAKE_TAG_V2,
            Self::ResponderHandshake => PROVISIONAL_NON_NORMATIVE_KIND_RESPONDER_HANDSHAKE_TAG_V2,
            Self::Transport => PROVISIONAL_NON_NORMATIVE_KIND_TRANSPORT_TAG_V2,
            Self::EpochClose => PROVISIONAL_NON_NORMATIVE_KIND_EPOCH_CLOSE_TAG_V2,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        match tag {
            PROVISIONAL_NON_NORMATIVE_KIND_INITIATOR_HANDSHAKE_TAG_V2 => {
                Ok(Self::InitiatorHandshake)
            }
            PROVISIONAL_NON_NORMATIVE_KIND_RESPONDER_HANDSHAKE_TAG_V2 => {
                Ok(Self::ResponderHandshake)
            }
            PROVISIONAL_NON_NORMATIVE_KIND_TRANSPORT_TAG_V2 => Ok(Self::Transport),
            PROVISIONAL_NON_NORMATIVE_KIND_EPOCH_CLOSE_TAG_V2 => Ok(Self::EpochClose),
            _ => Err(ProvisionalNonNormativeWireErrorV2::UnknownFrameKind),
        }
    }

    fn permitted_for(self, role: ProvisionalNonNormativeRoleV2) -> bool {
        matches!(
            (role, self),
            (
                ProvisionalNonNormativeRoleV2::Initiator,
                ProvisionalNonNormativeFrameKindV2::InitiatorHandshake,
            ) | (
                ProvisionalNonNormativeRoleV2::Responder,
                ProvisionalNonNormativeFrameKindV2::ResponderHandshake,
            ) | (
                ProvisionalNonNormativeRoleV2::Initiator | ProvisionalNonNormativeRoleV2::Responder,
                ProvisionalNonNormativeFrameKindV2::Transport
                    | ProvisionalNonNormativeFrameKindV2::EpochClose,
            )
        )
    }
}

/// PROVISIONAL/NON-NORMATIVE closed ACK-status candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProvisionalNonNormativeAckStatusV2 {
    /// PROVISIONAL/NON-NORMATIVE first durable persistence acknowledgement.
    Persisted,
    /// PROVISIONAL/NON-NORMATIVE byte-identical duplicate acknowledgement.
    ByteIdenticalDuplicate,
}

impl ProvisionalNonNormativeAckStatusV2 {
    fn tag(self) -> u8 {
        match self {
            Self::Persisted => PROVISIONAL_NON_NORMATIVE_ACK_PERSISTED_TAG_V2,
            Self::ByteIdenticalDuplicate => PROVISIONAL_NON_NORMATIVE_ACK_DUPLICATE_TAG_V2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        match tag {
            PROVISIONAL_NON_NORMATIVE_ACK_PERSISTED_TAG_V2 => Ok(Self::Persisted),
            PROVISIONAL_NON_NORMATIVE_ACK_DUPLICATE_TAG_V2 => Ok(Self::ByteIdenticalDuplicate),
            _ => Err(ProvisionalNonNormativeWireErrorV2::UnknownAckStatus),
        }
    }
}

/// PROVISIONAL/NON-NORMATIVE network/session/route scope with private fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalNonNormativeRouteScopeV2 {
    network_id: [u8; 32],
    relay_session_id: [u8; 32],
    route_id: [u8; 32],
}

impl ProvisionalNonNormativeRouteScopeV2 {
    /// Constructs a PROVISIONAL/NON-NORMATIVE nonzero route scope.
    pub fn new(
        network_id: [u8; 32],
        relay_session_id: [u8; 32],
        route_id: [u8; 32],
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if !nonzero_32(&network_id) || !nonzero_32(&relay_session_id) || !nonzero_32(&route_id) {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidScope);
        }
        Ok(Self {
            network_id,
            relay_session_id,
            route_id,
        })
    }

    /// Returns the public network identifier.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Returns the public Relay-session identifier.
    pub const fn relay_session_id(&self) -> [u8; 32] {
        self.relay_session_id
    }

    /// Returns the public route identifier.
    pub const fn route_id(&self) -> [u8; 32] {
        self.route_id
    }
}

impl fmt::Debug for ProvisionalNonNormativeRouteScopeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeRouteScopeV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("network_id", &"<redacted:32>")
            .field("relay_session_id", &"<redacted:32>")
            .field("route_id", &"<redacted:32>")
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE roster member with private identity/key fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalNonNormativeRosterMemberV2 {
    participant_id: ProvisionalNonNormativeParticipantIdV2,
    role: ProvisionalNonNormativeRoleV2,
    xonly_key: [u8; 32],
}

impl ProvisionalNonNormativeRosterMemberV2 {
    /// Constructs one PROVISIONAL/NON-NORMATIVE nonzero roster member.
    pub fn new(
        participant_id: ProvisionalNonNormativeParticipantIdV2,
        role: ProvisionalNonNormativeRoleV2,
        xonly_key: [u8; 32],
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if !nonzero_32(&xonly_key) {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidParticipant);
        }
        Ok(Self {
            participant_id,
            role,
            xonly_key,
        })
    }

    /// Returns the public participant identifier.
    pub const fn participant_id(&self) -> ProvisionalNonNormativeParticipantIdV2 {
        self.participant_id
    }

    /// Returns the public candidate role.
    pub const fn role(&self) -> ProvisionalNonNormativeRoleV2 {
        self.role
    }
}

impl fmt::Debug for ProvisionalNonNormativeRosterMemberV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeRosterMemberV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("participant_id", &self.participant_id)
            .field("role", &self.role)
            .field("xonly_key", &"<redacted:32>")
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE exact two-member roster with private fields.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvisionalNonNormativeRosterV2 {
    scope: ProvisionalNonNormativeRouteScopeV2,
    members:
        [ProvisionalNonNormativeRosterMemberV2; PROVISIONAL_NON_NORMATIVE_ROSTER_MEMBER_COUNT_V2],
}

impl ProvisionalNonNormativeRosterV2 {
    /// Constructs, validates, and canonically orders the candidate roster.
    pub fn new(
        scope: ProvisionalNonNormativeRouteScopeV2,
        mut members: [ProvisionalNonNormativeRosterMemberV2;
            PROVISIONAL_NON_NORMATIVE_ROSTER_MEMBER_COUNT_V2],
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if members[0].participant_id == members[1].participant_id
            || members[0].role == members[1].role
        {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidRoster);
        }
        members.sort_by_key(|member| member.participant_id);
        Ok(Self { scope, members })
    }

    /// Returns the public route scope bound by this roster.
    pub const fn scope(&self) -> ProvisionalNonNormativeRouteScopeV2 {
        self.scope
    }

    /// Returns the PROVISIONAL/NON-NORMATIVE canonical roster bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProvisionalNonNormativeWireErrorV2> {
        let mut out = Vec::with_capacity(PROVISIONAL_NON_NORMATIVE_ROSTER_BYTES_V2);
        out.extend_from_slice(PROVISIONAL_NON_NORMATIVE_ROSTER_MAGIC_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_WIRE_VERSION_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_FLAGS_V2);
        put_scope(&mut out, self.scope);
        put_u16(
            &mut out,
            PROVISIONAL_NON_NORMATIVE_ROSTER_MEMBER_COUNT_V2 as u16,
        );
        for member in self.members {
            out.extend_from_slice(member.participant_id.as_bytes());
            out.push(member.role.tag());
            out.extend_from_slice(&member.xonly_key);
        }
        Ok(out)
    }

    /// Returns the PROVISIONAL/NON-NORMATIVE roster snapshot digest.
    pub fn digest(&self) -> Result<[u8; 32], ProvisionalNonNormativeWireErrorV2> {
        digest32(
            PROVISIONAL_NON_NORMATIVE_ROSTER_DOMAIN_V2,
            &self.canonical_bytes()?,
        )
    }

    /// Strictly decodes one PROVISIONAL/NON-NORMATIVE roster with exact EOF.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if bytes.len() > PROVISIONAL_NON_NORMATIVE_ROSTER_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::ObjectTooLarge);
        }
        if bytes.len() != PROVISIONAL_NON_NORMATIVE_ROSTER_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::LengthMismatch);
        }
        let mut cursor = Cursor::new(bytes);
        require_prefix(&mut cursor, PROVISIONAL_NON_NORMATIVE_ROSTER_MAGIC_V2)?;
        require_version_and_flags(&mut cursor)?;
        let scope = take_scope(&mut cursor)?;
        if cursor.take_u16()? as usize != PROVISIONAL_NON_NORMATIVE_ROSTER_MEMBER_COUNT_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidRoster);
        }
        let first = take_roster_member(&mut cursor)?;
        let second = take_roster_member(&mut cursor)?;
        require_eof(&cursor)?;
        let roster = Self::new(scope, [first, second])?;
        if roster.canonical_bytes()?.as_slice() != bytes {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidRoster);
        }
        Ok(roster)
    }

    fn member(
        &self,
        participant: ProvisionalNonNormativeParticipantIdV2,
    ) -> Option<&ProvisionalNonNormativeRosterMemberV2> {
        self.members
            .iter()
            .find(|member| member.participant_id == participant)
    }
}

impl fmt::Debug for ProvisionalNonNormativeRosterV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeRosterV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field(
                "member_count",
                &PROVISIONAL_NON_NORMATIVE_ROSTER_MEMBER_COUNT_V2,
            )
            .field("members", &"<redacted:participant-and-key-material>")
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE standalone Noise ciphertext frame.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvisionalNonNormativeFrameV2 {
    kind: ProvisionalNonNormativeFrameKindV2,
    ciphertext: Vec<u8>,
}

impl ProvisionalNonNormativeFrameV2 {
    /// Constructs a bounded nonempty PROVISIONAL/NON-NORMATIVE frame.
    pub fn new(
        kind: ProvisionalNonNormativeFrameKindV2,
        ciphertext: Vec<u8>,
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if ciphertext.is_empty()
            || ciphertext.len() > PROVISIONAL_NON_NORMATIVE_MAX_CIPHERTEXT_BYTES_V2
        {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidCiphertextLength);
        }
        Ok(Self { kind, ciphertext })
    }

    /// Returns the closed PROVISIONAL/NON-NORMATIVE frame kind.
    pub const fn kind(&self) -> ProvisionalNonNormativeFrameKindV2 {
        self.kind
    }

    /// Returns authenticated Noise ciphertext after envelope validation.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the PROVISIONAL/NON-NORMATIVE ciphertext digest.
    pub fn ciphertext_digest(&self) -> Result<[u8; 32], ProvisionalNonNormativeWireErrorV2> {
        digest32(
            PROVISIONAL_NON_NORMATIVE_CIPHERTEXT_DOMAIN_V2,
            &self.ciphertext,
        )
    }

    /// Returns exact PROVISIONAL/NON-NORMATIVE standalone frame bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProvisionalNonNormativeWireErrorV2> {
        let mut out = Vec::with_capacity(
            PROVISIONAL_NON_NORMATIVE_FRAME_OVERHEAD_BYTES_V2 + self.ciphertext.len(),
        );
        out.extend_from_slice(PROVISIONAL_NON_NORMATIVE_FRAME_MAGIC_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_WIRE_VERSION_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_FLAGS_V2);
        put_u16(&mut out, self.kind.tag());
        put_u32(&mut out, self.ciphertext.len() as u32);
        out.extend_from_slice(&self.ciphertext_digest()?);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Returns the PROVISIONAL/NON-NORMATIVE domain-separated frame digest.
    pub fn digest(&self) -> Result<[u8; 32], ProvisionalNonNormativeWireErrorV2> {
        digest32(
            PROVISIONAL_NON_NORMATIVE_FRAME_DOMAIN_V2,
            &self.canonical_bytes()?,
        )
    }

    /// Strictly decodes a bounded candidate frame and requires exact EOF.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if bytes.len() > PROVISIONAL_NON_NORMATIVE_MAX_FRAME_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::ObjectTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        require_prefix(&mut cursor, PROVISIONAL_NON_NORMATIVE_FRAME_MAGIC_V2)?;
        require_version_and_flags(&mut cursor)?;
        let kind = ProvisionalNonNormativeFrameKindV2::from_tag(cursor.take_u16()?)?;
        let length = cursor.take_u32()? as usize;
        if length == 0 || length > PROVISIONAL_NON_NORMATIVE_MAX_CIPHERTEXT_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidCiphertextLength);
        }
        let declared_digest = cursor.take_array::<32>()?;
        let ciphertext = cursor.take(length)?.to_vec();
        require_eof(&cursor)?;
        let frame = Self::new(kind, ciphertext)?;
        if frame.ciphertext_digest()? != declared_digest {
            return Err(ProvisionalNonNormativeWireErrorV2::DigestMismatch);
        }
        Ok(frame)
    }
}

impl fmt::Debug for ProvisionalNonNormativeFrameV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeFrameV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("kind", &self.kind)
            .field("ciphertext_length", &self.ciphertext.len())
            .field("ciphertext_digest", &self.ciphertext_digest().ok())
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE sender identity/role pair with private fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalNonNormativeSenderV2 {
    participant_id: ProvisionalNonNormativeParticipantIdV2,
    role: ProvisionalNonNormativeRoleV2,
}

impl ProvisionalNonNormativeSenderV2 {
    /// Constructs a PROVISIONAL/NON-NORMATIVE sender descriptor.
    pub const fn new(
        participant_id: ProvisionalNonNormativeParticipantIdV2,
        role: ProvisionalNonNormativeRoleV2,
    ) -> Self {
        Self {
            participant_id,
            role,
        }
    }

    /// Returns the public sender participant identifier.
    pub const fn participant_id(&self) -> ProvisionalNonNormativeParticipantIdV2 {
        self.participant_id
    }

    /// Returns the public sender role.
    pub const fn role(&self) -> ProvisionalNonNormativeRoleV2 {
        self.role
    }
}

impl fmt::Debug for ProvisionalNonNormativeSenderV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeSenderV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("participant_id", &self.participant_id)
            .field("role", &self.role)
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE per-sender transcript position.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalNonNormativeFlowV2 {
    epoch: u64,
    sequence: u64,
    previous_envelope_digest: [u8; 32],
    expires_at_unix_seconds: u64,
}

impl ProvisionalNonNormativeFlowV2 {
    /// Constructs a strict candidate flow position.
    pub fn new(
        epoch: u64,
        sequence: u64,
        previous_envelope_digest: [u8; 32],
        expires_at_unix_seconds: u64,
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        let predecessor_valid = if sequence == 0 {
            previous_envelope_digest == [0u8; 32]
        } else {
            nonzero_32(&previous_envelope_digest)
        };
        if epoch == 0 || expires_at_unix_seconds == 0 || !predecessor_valid {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidFlow);
        }
        Ok(Self {
            epoch,
            sequence,
            previous_envelope_digest,
            expires_at_unix_seconds,
        })
    }

    /// Returns the public epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the public per-sender sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the public predecessor envelope digest.
    pub const fn previous_envelope_digest(&self) -> [u8; 32] {
        self.previous_envelope_digest
    }

    /// Returns the public candidate expiry in Unix seconds.
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

impl fmt::Debug for ProvisionalNonNormativeFlowV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeFlowV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("epoch", &self.epoch)
            .field("sequence", &self.sequence)
            .field("previous_envelope_digest", &"<redacted:32>")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE signed Relay V2 envelope with private fields.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvisionalNonNormativeEnvelopeV2 {
    scope: ProvisionalNonNormativeRouteScopeV2,
    roster_digest: [u8; 32],
    sender: ProvisionalNonNormativeSenderV2,
    recipient_id: ProvisionalNonNormativeParticipantIdV2,
    flow: ProvisionalNonNormativeFlowV2,
    frame: ProvisionalNonNormativeFrameV2,
    signature: [u8; 64],
    signature_attached: bool,
}

impl ProvisionalNonNormativeEnvelopeV2 {
    /// Constructs an unsigned candidate envelope. It cannot be serialized for
    /// transport until [`Self::attach_signature`] consumes it.
    pub fn new_unsigned(
        scope: ProvisionalNonNormativeRouteScopeV2,
        roster_digest: [u8; 32],
        sender: ProvisionalNonNormativeSenderV2,
        recipient_id: ProvisionalNonNormativeParticipantIdV2,
        flow: ProvisionalNonNormativeFlowV2,
        frame: ProvisionalNonNormativeFrameV2,
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if !nonzero_32(&roster_digest) {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidRoster);
        }
        if sender.participant_id == recipient_id {
            return Err(ProvisionalNonNormativeWireErrorV2::SenderIsRecipient);
        }
        if !frame.kind.permitted_for(sender.role) {
            return Err(ProvisionalNonNormativeWireErrorV2::RoleNotPermitted);
        }
        Ok(Self {
            scope,
            roster_digest,
            sender,
            recipient_id,
            flow,
            frame,
            signature: [0u8; 64],
            signature_attached: false,
        })
    }

    /// Consumes an unsigned envelope and attaches a nonzero public signature.
    pub fn attach_signature(
        mut self,
        signature: [u8; 64],
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if signature == [0u8; 64] {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        self.signature = signature;
        self.signature_attached = true;
        Ok(self)
    }

    /// Returns the public route scope.
    pub const fn scope(&self) -> ProvisionalNonNormativeRouteScopeV2 {
        self.scope
    }

    /// Returns the public roster snapshot digest.
    pub const fn roster_digest(&self) -> [u8; 32] {
        self.roster_digest
    }

    /// Returns the public sender descriptor.
    pub const fn sender(&self) -> ProvisionalNonNormativeSenderV2 {
        self.sender
    }

    /// Returns the public recipient identifier.
    pub const fn recipient_id(&self) -> ProvisionalNonNormativeParticipantIdV2 {
        self.recipient_id
    }

    /// Returns the public flow position.
    pub const fn flow(&self) -> ProvisionalNonNormativeFlowV2 {
        self.flow
    }

    /// Returns the candidate frame. Its Debug output never contains ciphertext.
    pub const fn frame(&self) -> &ProvisionalNonNormativeFrameV2 {
        &self.frame
    }

    /// Returns exact unsigned bytes covered by the candidate BIP340 signature.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, ProvisionalNonNormativeWireErrorV2> {
        let frame_bytes = self.frame.canonical_bytes()?;
        let mut out = Vec::with_capacity(
            PROVISIONAL_NON_NORMATIVE_ENVELOPE_OVERHEAD_BYTES_V2 - 64 + frame_bytes.len(),
        );
        out.extend_from_slice(PROVISIONAL_NON_NORMATIVE_ENVELOPE_MAGIC_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_WIRE_VERSION_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_FLAGS_V2);
        put_scope(&mut out, self.scope);
        out.extend_from_slice(&self.roster_digest);
        out.extend_from_slice(self.sender.participant_id.as_bytes());
        out.extend_from_slice(self.recipient_id.as_bytes());
        out.push(self.sender.role.tag());
        put_u64(&mut out, self.flow.epoch);
        put_u64(&mut out, self.flow.sequence);
        out.extend_from_slice(&self.flow.previous_envelope_digest);
        put_u64(&mut out, self.flow.expires_at_unix_seconds);
        put_u32(&mut out, frame_bytes.len() as u32);
        out.extend_from_slice(&frame_bytes);
        Ok(out)
    }

    /// Returns the PROVISIONAL/NON-NORMATIVE signed envelope digest.
    pub fn envelope_digest(&self) -> Result<[u8; 32], ProvisionalNonNormativeWireErrorV2> {
        digest32(
            PROVISIONAL_NON_NORMATIVE_ENVELOPE_DOMAIN_V2,
            &self.unsigned_bytes()?,
        )
    }

    /// Returns exact canonical envelope bytes, refusing an unsigned object.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProvisionalNonNormativeWireErrorV2> {
        if !self.signature_attached {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        let mut out = self.unsigned_bytes()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Strictly decodes a bounded candidate envelope and requires exact EOF.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if bytes.len() > PROVISIONAL_NON_NORMATIVE_MAX_ENVELOPE_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::ObjectTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        require_prefix(&mut cursor, PROVISIONAL_NON_NORMATIVE_ENVELOPE_MAGIC_V2)?;
        require_version_and_flags(&mut cursor)?;
        let scope = take_scope(&mut cursor)?;
        let roster_digest = cursor.take_array::<32>()?;
        let sender_id = ProvisionalNonNormativeParticipantIdV2::new(cursor.take_array()?)?;
        let recipient_id = ProvisionalNonNormativeParticipantIdV2::new(cursor.take_array()?)?;
        let role = ProvisionalNonNormativeRoleV2::from_tag(cursor.take_u8()?)?;
        let flow = ProvisionalNonNormativeFlowV2::new(
            cursor.take_u64()?,
            cursor.take_u64()?,
            cursor.take_array()?,
            cursor.take_u64()?,
        )?;
        let frame_length = cursor.take_u32()? as usize;
        if frame_length > PROVISIONAL_NON_NORMATIVE_MAX_FRAME_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::ObjectTooLarge);
        }
        let frame = ProvisionalNonNormativeFrameV2::decode(cursor.take(frame_length)?)?;
        let signature = cursor.take_array::<64>()?;
        require_eof(&cursor)?;
        Self::new_unsigned(
            scope,
            roster_digest,
            ProvisionalNonNormativeSenderV2::new(sender_id, role),
            recipient_id,
            flow,
            frame,
        )?
        .attach_signature(signature)
    }

    /// Verifies scope, roster, role, recipient, transcript, expiry, and BIP340.
    pub fn verify_for_recipient(
        self,
        roster: &ProvisionalNonNormativeRosterV2,
        recipient: &ProvisionalNonNormativeRecipientV2,
    ) -> Result<ProvisionalNonNormativeVerifiedEnvelopeV2, ProvisionalNonNormativeWireErrorV2> {
        if self.scope != recipient.scope || self.scope != roster.scope {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongScope);
        }
        let roster_digest = roster.digest()?;
        if self.roster_digest != roster_digest || recipient.roster_digest != roster_digest {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongRoster);
        }
        if self.recipient_id != recipient.recipient_id {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongRecipient);
        }
        let sender_member = roster
            .member(self.sender.participant_id)
            .ok_or(ProvisionalNonNormativeWireErrorV2::UnknownSender)?;
        if sender_member.role != self.sender.role {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongSenderRole);
        }
        if roster.member(self.recipient_id).is_none() {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongRecipient);
        }
        if !self.frame.kind.permitted_for(self.sender.role) {
            return Err(ProvisionalNonNormativeWireErrorV2::RoleNotPermitted);
        }
        if self.flow.epoch != recipient.position.epoch {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongEpoch);
        }
        if self.flow.sequence != recipient.position.next_sequence {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongSequence);
        }
        if self.flow.previous_envelope_digest != recipient.position.previous_envelope_digest {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongPredecessor);
        }
        if self.flow.expires_at_unix_seconds < recipient.position.now_unix_seconds {
            return Err(ProvisionalNonNormativeWireErrorV2::Expired);
        }
        if !self.signature_attached {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        let digest = self.envelope_digest()?;
        verify_bip340(&sender_member.xonly_key, &digest, &self.signature)?;
        Ok(ProvisionalNonNormativeVerifiedEnvelopeV2 {
            envelope: self,
            digest,
        })
    }
}

impl fmt::Debug for ProvisionalNonNormativeEnvelopeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeEnvelopeV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("scope", &self.scope)
            .field("roster_digest", &"<redacted:32>")
            .field("sender", &self.sender)
            .field("recipient_id", &self.recipient_id)
            .field("flow", &self.flow)
            .field("frame", &self.frame)
            .field("signature", &"<redacted:64>")
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE expected recipient transcript position.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalNonNormativeRecipientPositionV2 {
    epoch: u64,
    next_sequence: u64,
    previous_envelope_digest: [u8; 32],
    now_unix_seconds: u64,
}

impl ProvisionalNonNormativeRecipientPositionV2 {
    /// Constructs the recipient's exact expected candidate position.
    pub fn new(
        epoch: u64,
        next_sequence: u64,
        previous_envelope_digest: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        let predecessor_valid = if next_sequence == 0 {
            previous_envelope_digest == [0u8; 32]
        } else {
            nonzero_32(&previous_envelope_digest)
        };
        if epoch == 0 || now_unix_seconds == 0 || !predecessor_valid {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidFlow);
        }
        Ok(Self {
            epoch,
            next_sequence,
            previous_envelope_digest,
            now_unix_seconds,
        })
    }
}

impl fmt::Debug for ProvisionalNonNormativeRecipientPositionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeRecipientPositionV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("epoch", &self.epoch)
            .field("next_sequence", &self.next_sequence)
            .field("previous_envelope_digest", &"<redacted:32>")
            .field("now_unix_seconds", &self.now_unix_seconds)
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE recipient validation context with private fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalNonNormativeRecipientV2 {
    scope: ProvisionalNonNormativeRouteScopeV2,
    roster_digest: [u8; 32],
    recipient_id: ProvisionalNonNormativeParticipantIdV2,
    position: ProvisionalNonNormativeRecipientPositionV2,
}

impl ProvisionalNonNormativeRecipientV2 {
    /// Constructs a recipient context bound to one roster and transcript tip.
    pub fn new(
        scope: ProvisionalNonNormativeRouteScopeV2,
        roster_digest: [u8; 32],
        recipient_id: ProvisionalNonNormativeParticipantIdV2,
        position: ProvisionalNonNormativeRecipientPositionV2,
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if !nonzero_32(&roster_digest) {
            return Err(ProvisionalNonNormativeWireErrorV2::InvalidRoster);
        }
        Ok(Self {
            scope,
            roster_digest,
            recipient_id,
            position,
        })
    }

    /// Returns the public recipient identifier.
    pub const fn recipient_id(&self) -> ProvisionalNonNormativeParticipantIdV2 {
        self.recipient_id
    }
}

impl fmt::Debug for ProvisionalNonNormativeRecipientV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeRecipientV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("scope", &self.scope)
            .field("roster_digest", &"<redacted:32>")
            .field("recipient_id", &self.recipient_id)
            .field("position", &self.position)
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE verified envelope; ciphertext remains private.
pub struct ProvisionalNonNormativeVerifiedEnvelopeV2 {
    envelope: ProvisionalNonNormativeEnvelopeV2,
    digest: [u8; 32],
}

impl ProvisionalNonNormativeVerifiedEnvelopeV2 {
    /// Returns the authenticated candidate envelope digest.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the authenticated sender.
    pub const fn sender(&self) -> ProvisionalNonNormativeSenderV2 {
        self.envelope.sender
    }

    /// Returns the authenticated flow position.
    pub const fn flow(&self) -> ProvisionalNonNormativeFlowV2 {
        self.envelope.flow
    }

    /// Returns the authenticated Noise frame.
    pub const fn frame(&self) -> &ProvisionalNonNormativeFrameV2 {
        &self.envelope.frame
    }

    /// Consumes the proof and returns the authenticated Noise frame.
    pub fn into_frame(self) -> ProvisionalNonNormativeFrameV2 {
        self.envelope.frame
    }
}

impl fmt::Debug for ProvisionalNonNormativeVerifiedEnvelopeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeVerifiedEnvelopeV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("digest", &self.digest)
            .field("sender", &self.envelope.sender)
            .field("flow", &self.envelope.flow)
            .field("frame", &self.envelope.frame)
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE signed durable ACK with private fields.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvisionalNonNormativeAckV2 {
    scope: ProvisionalNonNormativeRouteScopeV2,
    roster_digest: [u8; 32],
    sender: ProvisionalNonNormativeSenderV2,
    recipient_id: ProvisionalNonNormativeParticipantIdV2,
    epoch: u64,
    sequence: u64,
    envelope_digest: [u8; 32],
    status: ProvisionalNonNormativeAckStatusV2,
    signature: [u8; 64],
    signature_attached: bool,
}

impl ProvisionalNonNormativeAckV2 {
    /// Constructs an unsigned ACK for one exact signed candidate envelope.
    pub fn new_unsigned_for_envelope(
        envelope: &ProvisionalNonNormativeEnvelopeV2,
        roster: &ProvisionalNonNormativeRosterV2,
        sender_role: ProvisionalNonNormativeRoleV2,
        status: ProvisionalNonNormativeAckStatusV2,
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if envelope.scope != roster.scope || envelope.roster_digest != roster.digest()? {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongRoster);
        }
        if !envelope.signature_attached {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        let envelope_sender_member = roster
            .member(envelope.sender.participant_id)
            .ok_or(ProvisionalNonNormativeWireErrorV2::UnknownSender)?;
        if envelope_sender_member.role != envelope.sender.role {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongSenderRole);
        }
        let sender_member = roster
            .member(envelope.recipient_id)
            .ok_or(ProvisionalNonNormativeWireErrorV2::UnknownSender)?;
        if sender_member.role != sender_role {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongSenderRole);
        }
        Ok(Self {
            scope: envelope.scope,
            roster_digest: envelope.roster_digest,
            sender: ProvisionalNonNormativeSenderV2::new(envelope.recipient_id, sender_role),
            recipient_id: envelope.sender.participant_id,
            epoch: envelope.flow.epoch,
            sequence: envelope.flow.sequence,
            envelope_digest: envelope.envelope_digest()?,
            status,
            signature: [0u8; 64],
            signature_attached: false,
        })
    }

    /// Consumes an unsigned ACK and attaches a nonzero public signature.
    pub fn attach_signature(
        mut self,
        signature: [u8; 64],
    ) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if signature == [0u8; 64] {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        self.signature = signature;
        self.signature_attached = true;
        Ok(self)
    }

    /// Returns the closed PROVISIONAL/NON-NORMATIVE ACK status.
    pub const fn status(&self) -> ProvisionalNonNormativeAckStatusV2 {
        self.status
    }

    /// Returns the exact envelope digest acknowledged.
    pub const fn envelope_digest(&self) -> [u8; 32] {
        self.envelope_digest
    }

    /// Returns exact unsigned ACK bytes covered by BIP340.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROVISIONAL_NON_NORMATIVE_ACK_BYTES_V2 - 64);
        out.extend_from_slice(PROVISIONAL_NON_NORMATIVE_ACK_MAGIC_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_WIRE_VERSION_V2);
        put_u16(&mut out, PROVISIONAL_NON_NORMATIVE_FLAGS_V2);
        put_scope(&mut out, self.scope);
        out.extend_from_slice(&self.roster_digest);
        out.extend_from_slice(self.sender.participant_id.as_bytes());
        out.extend_from_slice(self.recipient_id.as_bytes());
        out.push(self.sender.role.tag());
        put_u64(&mut out, self.epoch);
        put_u64(&mut out, self.sequence);
        out.extend_from_slice(&self.envelope_digest);
        out.push(self.status.tag());
        out
    }

    /// Returns the PROVISIONAL/NON-NORMATIVE signed ACK digest.
    pub fn ack_digest(&self) -> Result<[u8; 32], ProvisionalNonNormativeWireErrorV2> {
        digest32(
            PROVISIONAL_NON_NORMATIVE_ACK_DOMAIN_V2,
            &self.unsigned_bytes(),
        )
    }

    /// Returns exact canonical ACK bytes, refusing an unsigned object.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProvisionalNonNormativeWireErrorV2> {
        if !self.signature_attached {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        let mut out = self.unsigned_bytes();
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Strictly decodes one exact-size candidate ACK and requires exact EOF.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProvisionalNonNormativeWireErrorV2> {
        if bytes.len() > PROVISIONAL_NON_NORMATIVE_ACK_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::ObjectTooLarge);
        }
        if bytes.len() != PROVISIONAL_NON_NORMATIVE_ACK_BYTES_V2 {
            return Err(ProvisionalNonNormativeWireErrorV2::LengthMismatch);
        }
        let mut cursor = Cursor::new(bytes);
        require_prefix(&mut cursor, PROVISIONAL_NON_NORMATIVE_ACK_MAGIC_V2)?;
        require_version_and_flags(&mut cursor)?;
        let scope = take_scope(&mut cursor)?;
        let roster_digest = cursor.take_array::<32>()?;
        let sender_id = ProvisionalNonNormativeParticipantIdV2::new(cursor.take_array()?)?;
        let recipient_id = ProvisionalNonNormativeParticipantIdV2::new(cursor.take_array()?)?;
        let role = ProvisionalNonNormativeRoleV2::from_tag(cursor.take_u8()?)?;
        let epoch = cursor.take_u64()?;
        let sequence = cursor.take_u64()?;
        let envelope_digest = cursor.take_array::<32>()?;
        let status = ProvisionalNonNormativeAckStatusV2::from_tag(cursor.take_u8()?)?;
        let signature = cursor.take_array::<64>()?;
        require_eof(&cursor)?;
        if epoch == 0 || !nonzero_32(&roster_digest) || !nonzero_32(&envelope_digest) {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongAckReference);
        }
        let ack = Self {
            scope,
            roster_digest,
            sender: ProvisionalNonNormativeSenderV2::new(sender_id, role),
            recipient_id,
            epoch,
            sequence,
            envelope_digest,
            status,
            signature,
            signature_attached: signature != [0u8; 64],
        };
        if !ack.signature_attached {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        Ok(ack)
    }

    /// Verifies that this signed ACK is the exact opposite-party receipt.
    pub fn verify_for_envelope(
        self,
        envelope: &ProvisionalNonNormativeEnvelopeV2,
        roster: &ProvisionalNonNormativeRosterV2,
    ) -> Result<ProvisionalNonNormativeVerifiedAckV2, ProvisionalNonNormativeWireErrorV2> {
        let envelope_digest = envelope.envelope_digest()?;
        if self.scope != envelope.scope
            || self.scope != roster.scope
            || self.roster_digest != envelope.roster_digest
            || self.roster_digest != roster.digest()?
            || self.sender.participant_id != envelope.recipient_id
            || self.recipient_id != envelope.sender.participant_id
            || self.epoch != envelope.flow.epoch
            || self.sequence != envelope.flow.sequence
            || self.envelope_digest != envelope_digest
        {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongAckReference);
        }
        let member = roster
            .member(self.sender.participant_id)
            .ok_or(ProvisionalNonNormativeWireErrorV2::UnknownSender)?;
        if member.role != self.sender.role {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongSenderRole);
        }
        let envelope_sender_member = roster
            .member(envelope.sender.participant_id)
            .ok_or(ProvisionalNonNormativeWireErrorV2::UnknownSender)?;
        if envelope_sender_member.role != envelope.sender.role {
            return Err(ProvisionalNonNormativeWireErrorV2::WrongSenderRole);
        }
        if !envelope.signature_attached {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        if !self.signature_attached {
            return Err(ProvisionalNonNormativeWireErrorV2::MissingSignature);
        }
        let digest = self.ack_digest()?;
        verify_bip340(&member.xonly_key, &digest, &self.signature)?;
        Ok(ProvisionalNonNormativeVerifiedAckV2 { ack: self, digest })
    }
}

impl fmt::Debug for ProvisionalNonNormativeAckV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeAckV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("scope", &self.scope)
            .field("sender", &self.sender)
            .field("recipient_id", &self.recipient_id)
            .field("epoch", &self.epoch)
            .field("sequence", &self.sequence)
            .field("envelope_digest", &self.envelope_digest)
            .field("status", &self.status)
            .field("signature", &"<redacted:64>")
            .finish()
    }
}

/// PROVISIONAL/NON-NORMATIVE verified ACK with private fields.
pub struct ProvisionalNonNormativeVerifiedAckV2 {
    ack: ProvisionalNonNormativeAckV2,
    digest: [u8; 32],
}

impl ProvisionalNonNormativeVerifiedAckV2 {
    /// Returns the authenticated ACK digest.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the authenticated ACK status.
    pub const fn status(&self) -> ProvisionalNonNormativeAckStatusV2 {
        self.ack.status
    }

    /// Returns the exact authenticated envelope digest acknowledged.
    pub const fn envelope_digest(&self) -> [u8; 32] {
        self.ack.envelope_digest
    }
}

impl fmt::Debug for ProvisionalNonNormativeVerifiedAckV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalNonNormativeVerifiedAckV2")
            .field("candidate_status", &PROVISIONAL_NON_NORMATIVE_STATUS_V2)
            .field("digest", &self.digest)
            .field("status", &self.ack.status)
            .field("envelope_digest", &self.ack.envelope_digest)
            .finish()
    }
}

#[cfg(feature = "provisional-non-normative-v2")]
fn verify_bip340(
    xonly_key: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ProvisionalNonNormativeWireErrorV2> {
    let context = btc_crypto::SecpContext::new(&[0xd0; 32]);
    context
        .verify_bip340(xonly_key, digest, signature)
        .map_err(|_| ProvisionalNonNormativeWireErrorV2::InvalidSignature)
}

#[cfg(not(feature = "provisional-non-normative-v2"))]
fn verify_bip340(
    _xonly_key: &[u8; 32],
    _digest: &[u8; 32],
    _signature: &[u8; 64],
) -> Result<(), ProvisionalNonNormativeWireErrorV2> {
    Err(ProvisionalNonNormativeWireErrorV2::CryptographyUnavailable)
}

fn nonzero_32(bytes: &[u8; 32]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn digest32(domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], ProvisionalNonNormativeWireErrorV2> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ProvisionalNonNormativeWireErrorV2::HashInitialization)?;
    hasher.update(domain);
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProvisionalNonNormativeWireErrorV2::HashInitialization)?;
    Ok(digest)
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_scope(out: &mut Vec<u8>, scope: ProvisionalNonNormativeRouteScopeV2) {
    out.extend_from_slice(&scope.network_id);
    out.extend_from_slice(&scope.relay_session_id);
    out.extend_from_slice(&scope.route_id);
}

fn take_scope(
    cursor: &mut Cursor<'_>,
) -> Result<ProvisionalNonNormativeRouteScopeV2, ProvisionalNonNormativeWireErrorV2> {
    ProvisionalNonNormativeRouteScopeV2::new(
        cursor.take_array()?,
        cursor.take_array()?,
        cursor.take_array()?,
    )
}

fn take_roster_member(
    cursor: &mut Cursor<'_>,
) -> Result<ProvisionalNonNormativeRosterMemberV2, ProvisionalNonNormativeWireErrorV2> {
    ProvisionalNonNormativeRosterMemberV2::new(
        ProvisionalNonNormativeParticipantIdV2::new(cursor.take_array()?)?,
        ProvisionalNonNormativeRoleV2::from_tag(cursor.take_u8()?)?,
        cursor.take_array()?,
    )
}

fn require_prefix(
    cursor: &mut Cursor<'_>,
    prefix: &[u8],
) -> Result<(), ProvisionalNonNormativeWireErrorV2> {
    if cursor.take(prefix.len())? != prefix {
        return Err(ProvisionalNonNormativeWireErrorV2::InvalidMagic);
    }
    Ok(())
}

fn require_version_and_flags(
    cursor: &mut Cursor<'_>,
) -> Result<(), ProvisionalNonNormativeWireErrorV2> {
    if cursor.take_u16()? != PROVISIONAL_NON_NORMATIVE_WIRE_VERSION_V2 {
        return Err(ProvisionalNonNormativeWireErrorV2::InvalidVersion);
    }
    if cursor.take_u16()? != PROVISIONAL_NON_NORMATIVE_FLAGS_V2 {
        return Err(ProvisionalNonNormativeWireErrorV2::UnknownFlags);
    }
    Ok(())
}

fn require_eof(cursor: &Cursor<'_>) -> Result<(), ProvisionalNonNormativeWireErrorV2> {
    if !cursor.finished() {
        return Err(ProvisionalNonNormativeWireErrorV2::TrailingBytes);
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProvisionalNonNormativeWireErrorV2> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProvisionalNonNormativeWireErrorV2::Truncated)?;
        if end > self.bytes.len() {
            return Err(ProvisionalNonNormativeWireErrorV2::Truncated);
        }
        let bytes = &self.bytes[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn take_array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], ProvisionalNonNormativeWireErrorV2> {
        let bytes = self.take(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn take_u8(&mut self) -> Result<u8, ProvisionalNonNormativeWireErrorV2> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, ProvisionalNonNormativeWireErrorV2> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, ProvisionalNonNormativeWireErrorV2> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, ProvisionalNonNormativeWireErrorV2> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2: &str =
        "PROVISIONAL/NON-NORMATIVE CANDIDATE VECTOR — NOT RATIFIED";
    const PROVISIONAL_NON_NORMATIVE_FRAME_VECTOR_HEX_V2: &str =
        "444f4d495246322100020000100100000019615a1da8c2663f812ec8e059c50060da2921eefcbcbbd926bb839c31b529b2a063616e6469646174652d6e6f6973652d68616e647368616b65";
    const PROVISIONAL_NON_NORMATIVE_ROSTER_DIGEST_VECTOR_HEX_V2: &str =
        "77aaa2656a09e3c5a12f03ebb32186a462750a341539a36e952565237fefdab1";
    const PROVISIONAL_NON_NORMATIVE_ENVELOPE_DIGEST_VECTOR_HEX_V2: &str =
        "706a145a24689cea8d7bbc55885c23e8d275145b7e4b087f5d015d800fadb617";
    const PROVISIONAL_NON_NORMATIVE_ACK_DIGEST_VECTOR_HEX_V2: &str =
        "23f2d81b0a45926519844f1eb8ec609cb59da023e8e0cb0068458c30b866c2c0";

    fn repeated(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn scope() -> ProvisionalNonNormativeRouteScopeV2 {
        ProvisionalNonNormativeRouteScopeV2::new(repeated(0x11), repeated(0x22), repeated(0x33))
            .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
    }

    fn initiator_id() -> ProvisionalNonNormativeParticipantIdV2 {
        ProvisionalNonNormativeParticipantIdV2::new(repeated(0x41))
            .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
    }

    fn responder_id() -> ProvisionalNonNormativeParticipantIdV2 {
        ProvisionalNonNormativeParticipantIdV2::new(repeated(0x51))
            .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
    }

    fn roster_with_keys(
        initiator_key: [u8; 32],
        responder_key: [u8; 32],
    ) -> ProvisionalNonNormativeRosterV2 {
        ProvisionalNonNormativeRosterV2::new(
            scope(),
            [
                ProvisionalNonNormativeRosterMemberV2::new(
                    initiator_id(),
                    ProvisionalNonNormativeRoleV2::Initiator,
                    initiator_key,
                )
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2),
                ProvisionalNonNormativeRosterMemberV2::new(
                    responder_id(),
                    ProvisionalNonNormativeRoleV2::Responder,
                    responder_key,
                )
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2),
            ],
        )
        .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
    }

    fn roster() -> ProvisionalNonNormativeRosterV2 {
        roster_with_keys(repeated(0x61), repeated(0x71))
    }

    fn frame() -> ProvisionalNonNormativeFrameV2 {
        ProvisionalNonNormativeFrameV2::new(
            ProvisionalNonNormativeFrameKindV2::InitiatorHandshake,
            b"candidate-noise-handshake".to_vec(),
        )
        .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
    }

    fn signed_envelope() -> ProvisionalNonNormativeEnvelopeV2 {
        let roster = roster();
        ProvisionalNonNormativeEnvelopeV2::new_unsigned(
            scope(),
            roster
                .digest()
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2),
            ProvisionalNonNormativeSenderV2::new(
                initiator_id(),
                ProvisionalNonNormativeRoleV2::Initiator,
            ),
            responder_id(),
            ProvisionalNonNormativeFlowV2::new(7, 0, [0u8; 32], 2_000_000_000)
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2),
            frame(),
        )
        .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
        .attach_signature([0x5a; 64])
        .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
    }

    fn signed_ack(envelope: &ProvisionalNonNormativeEnvelopeV2) -> ProvisionalNonNormativeAckV2 {
        ProvisionalNonNormativeAckV2::new_unsigned_for_envelope(
            envelope,
            &roster(),
            ProvisionalNonNormativeRoleV2::Responder,
            ProvisionalNonNormativeAckStatusV2::Persisted,
        )
        .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
        .attach_signature([0x6a; 64])
        .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn provisional_non_normative_candidate_vectors_are_frozen_but_not_ratified() {
        assert!(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2.contains("PROVISIONAL/NON-NORMATIVE"));
        let frame = frame();
        let roster = roster();
        let envelope = signed_envelope();
        let ack = signed_ack(&envelope);
        assert_eq!(
            hex(&frame
                .canonical_bytes()
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)),
            PROVISIONAL_NON_NORMATIVE_FRAME_VECTOR_HEX_V2
        );
        assert_eq!(
            hex(&roster
                .digest()
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)),
            PROVISIONAL_NON_NORMATIVE_ROSTER_DIGEST_VECTOR_HEX_V2
        );
        assert_eq!(
            hex(&envelope
                .envelope_digest()
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)),
            PROVISIONAL_NON_NORMATIVE_ENVELOPE_DIGEST_VECTOR_HEX_V2
        );
        assert_eq!(
            hex(&ack
                .ack_digest()
                .expect(PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2)),
            PROVISIONAL_NON_NORMATIVE_ACK_DIGEST_VECTOR_HEX_V2
        );
    }

    #[test]
    fn provisional_non_normative_all_codecs_roundtrip_and_require_exact_eof() {
        let roster = roster();
        let frame = frame();
        let envelope = signed_envelope();
        let ack = signed_ack(&envelope);

        let roster_bytes = roster.canonical_bytes().unwrap();
        assert_eq!(
            ProvisionalNonNormativeRosterV2::decode(&roster_bytes).unwrap(),
            roster
        );
        let frame_bytes = frame.canonical_bytes().unwrap();
        assert_eq!(
            ProvisionalNonNormativeFrameV2::decode(&frame_bytes).unwrap(),
            frame
        );
        let envelope_bytes = envelope.canonical_bytes().unwrap();
        assert_eq!(
            ProvisionalNonNormativeEnvelopeV2::decode(&envelope_bytes).unwrap(),
            envelope
        );
        let ack_bytes = ack.canonical_bytes().unwrap();
        assert_eq!(
            ProvisionalNonNormativeAckV2::decode(&ack_bytes).unwrap(),
            ack
        );

        for mut bytes in [roster_bytes, frame_bytes, envelope_bytes, ack_bytes] {
            bytes.push(0xaa);
            let rejected = ProvisionalNonNormativeRosterV2::decode(&bytes).is_err()
                && ProvisionalNonNormativeFrameV2::decode(&bytes).is_err()
                && ProvisionalNonNormativeEnvelopeV2::decode(&bytes).is_err()
                && ProvisionalNonNormativeAckV2::decode(&bytes).is_err();
            assert!(rejected, "{PROVISIONAL_NON_NORMATIVE_VECTOR_STATUS_V2}");
        }
    }

    #[test]
    fn provisional_non_normative_bounds_tags_hashes_and_debug_are_fail_closed() {
        assert_eq!(
            ProvisionalNonNormativeFrameV2::new(
                ProvisionalNonNormativeFrameKindV2::Transport,
                Vec::new(),
            )
            .unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::InvalidCiphertextLength
        );
        assert_eq!(
            ProvisionalNonNormativeFrameV2::new(
                ProvisionalNonNormativeFrameKindV2::Transport,
                vec![0u8; PROVISIONAL_NON_NORMATIVE_MAX_CIPHERTEXT_BYTES_V2 + 1],
            )
            .unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::InvalidCiphertextLength
        );

        let mut frame_bytes = frame().canonical_bytes().unwrap();
        frame_bytes[12..14].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(
            ProvisionalNonNormativeFrameV2::decode(&frame_bytes).unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::UnknownFrameKind
        );

        let mut frame_bytes = frame().canonical_bytes().unwrap();
        let last = frame_bytes.len() - 1;
        frame_bytes[last] ^= 1;
        assert_eq!(
            ProvisionalNonNormativeFrameV2::decode(&frame_bytes).unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::DigestMismatch
        );

        let private_marker = "candidate-noise-handshake";
        assert!(!format!("{:?}", frame()).contains(private_marker));
        assert!(!format!("{:?}", signed_envelope()).contains(private_marker));
        assert!(!format!("{:?}", signed_ack(&signed_envelope())).contains(private_marker));
        assert!(format!("{:?}", frame()).contains("PROVISIONAL/NON-NORMATIVE"));
    }

    #[test]
    fn provisional_non_normative_v1_and_v2_vectors_reject_each_other() {
        let v1 = relay::RelayEnvelopeV1 {
            network_id: repeated(0x11),
            message_type: relay::auth::message_type::RFQ,
            session_id: repeated(0x22),
            route_id: repeated(0x33),
            sender_id: relay::ParticipantId(repeated(0x41)),
            recipient_id: relay::ParticipantId(repeated(0x51)),
            sender_role: relay::SenderRoleV1::Initiator,
            sequence: 0,
            previous_transcript_hash: [0u8; 32],
            payload: b"ratified-v1-payload".to_vec(),
            expiry: relay::TimelockSpec::TimestampSeconds {
                value: 2_000_000_000,
            },
            policy_version: 1,
            roster_snapshot: repeated(0x77),
            signature: [0x7a; 64],
        };
        let v1_bytes = v1.canonical_bytes().unwrap();
        assert_eq!(
            ProvisionalNonNormativeEnvelopeV2::decode(&v1_bytes).unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::InvalidMagic
        );

        let v2_bytes = signed_envelope().canonical_bytes().unwrap();
        assert_eq!(
            relay::RelayEnvelopeV1::decode(&v2_bytes).unwrap_err(),
            relay::EnvelopeError::InvalidMagic
        );
        assert_ne!(&v1_bytes[..8], PROVISIONAL_NON_NORMATIVE_ENVELOPE_MAGIC_V2);

        let v1_ack = relay::server::AckV1 {
            key: relay::server::IdempotencyKeyV1 {
                session_id: repeated(0x22),
                sender_id: relay::ParticipantId(repeated(0x41)),
                recipient_id: relay::ParticipantId(repeated(0x51)),
                sequence: 0,
            },
            digest: repeated(0x66),
        };
        let v1_ack_bytes = v1_ack.canonical_bytes();
        assert_eq!(
            ProvisionalNonNormativeAckV2::decode(&v1_ack_bytes).unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::LengthMismatch
        );

        let v2_ack_bytes = signed_ack(&signed_envelope()).canonical_bytes().unwrap();
        assert_eq!(
            relay::server::AckV1::decode(&v2_ack_bytes).unwrap_err(),
            relay::server::AckCodecError::WrongLength
        );
        assert_ne!(&v1_ack_bytes[..8], PROVISIONAL_NON_NORMATIVE_ACK_MAGIC_V2);
    }

    #[test]
    fn provisional_non_normative_ack_refuses_an_envelope_sender_outside_the_roster() {
        let roster = roster();
        let unknown_sender = ProvisionalNonNormativeParticipantIdV2::new(repeated(0x42)).unwrap();
        let envelope = ProvisionalNonNormativeEnvelopeV2::new_unsigned(
            scope(),
            roster.digest().unwrap(),
            ProvisionalNonNormativeSenderV2::new(
                unknown_sender,
                ProvisionalNonNormativeRoleV2::Initiator,
            ),
            responder_id(),
            ProvisionalNonNormativeFlowV2::new(7, 0, [0u8; 32], 2_000_000_000).unwrap(),
            frame(),
        )
        .unwrap()
        .attach_signature([0x5a; 64])
        .unwrap();
        assert_eq!(
            ProvisionalNonNormativeAckV2::new_unsigned_for_envelope(
                &envelope,
                &roster,
                ProvisionalNonNormativeRoleV2::Responder,
                ProvisionalNonNormativeAckStatusV2::Persisted,
            )
            .unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::UnknownSender
        );
    }

    #[cfg(not(feature = "provisional-non-normative-v2"))]
    #[test]
    fn provisional_non_normative_default_build_refuses_crypto_validation() {
        let roster = roster();
        let envelope = signed_envelope();
        let recipient = ProvisionalNonNormativeRecipientV2::new(
            scope(),
            roster.digest().unwrap(),
            responder_id(),
            ProvisionalNonNormativeRecipientPositionV2::new(7, 0, [0u8; 32], 1_900_000_000)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            envelope
                .verify_for_recipient(&roster, &recipient)
                .unwrap_err(),
            ProvisionalNonNormativeWireErrorV2::CryptographyUnavailable
        );
    }

    #[cfg(feature = "provisional-non-normative-v2")]
    #[test]
    fn provisional_non_normative_pinned_bip340_verifies_envelope_and_ack() {
        let context = btc_crypto::SecpContext::new(&[0x91; 32]);
        let initiator_secret = repeated(0x52);
        let responder_secret = repeated(0x53);
        let (_, initiator_key) = context
            .sign_bip340(&initiator_secret, &[0u8; 32], &[0x01; 32])
            .unwrap();
        let (_, responder_key) = context
            .sign_bip340(&responder_secret, &[0u8; 32], &[0x02; 32])
            .unwrap();
        let roster = roster_with_keys(initiator_key, responder_key);
        let unsigned = ProvisionalNonNormativeEnvelopeV2::new_unsigned(
            scope(),
            roster.digest().unwrap(),
            ProvisionalNonNormativeSenderV2::new(
                initiator_id(),
                ProvisionalNonNormativeRoleV2::Initiator,
            ),
            responder_id(),
            ProvisionalNonNormativeFlowV2::new(7, 0, [0u8; 32], 2_000_000_000).unwrap(),
            frame(),
        )
        .unwrap();
        let digest = unsigned.envelope_digest().unwrap();
        let (signature, _) = context
            .sign_bip340(&initiator_secret, &digest, &[0x03; 32])
            .unwrap();
        let envelope = unsigned.attach_signature(signature).unwrap();
        let recipient = ProvisionalNonNormativeRecipientV2::new(
            scope(),
            roster.digest().unwrap(),
            responder_id(),
            ProvisionalNonNormativeRecipientPositionV2::new(7, 0, [0u8; 32], 1_900_000_000)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            envelope
                .clone()
                .verify_for_recipient(&roster, &recipient)
                .unwrap()
                .digest(),
            digest
        );

        let unsigned_ack = ProvisionalNonNormativeAckV2::new_unsigned_for_envelope(
            &envelope,
            &roster,
            ProvisionalNonNormativeRoleV2::Responder,
            ProvisionalNonNormativeAckStatusV2::Persisted,
        )
        .unwrap();
        let ack_digest = unsigned_ack.ack_digest().unwrap();
        let (ack_signature, _) = context
            .sign_bip340(&responder_secret, &ack_digest, &[0x04; 32])
            .unwrap();
        let ack = unsigned_ack.attach_signature(ack_signature).unwrap();
        assert_eq!(
            ack.verify_for_envelope(&envelope, &roster)
                .unwrap()
                .digest(),
            ack_digest
        );
    }
}

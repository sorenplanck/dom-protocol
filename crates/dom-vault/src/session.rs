//! Concrete statically selected signing-session authority (F1, D-005).
//!
//! `ValidatedSigningRoundStateV1::from_session_authority` (exposed at pin
//! a182563) requires the caller to name its `SigningSessionAuthorityV1`
//! composition root and hand over that authority's accepted-session handle.
//! This module supplies the DOM Interop side of that contract: a concrete
//! [`AcceptedSession`] (an immutable, durably-reconstructable view of one
//! accepted two-party session) and the [`SessionAuthority`] marker that
//! names it as the static authority type.
//!
//! The authority is intentionally minimal: it carries no capability and no
//! mutable state. Session-identifier uniqueness is enforced downstream by
//! the vault itself (`claim_fresh_reservation` claims a permanent session
//! tombstone) and, for the leg's own session bootstrap, by
//! [`crate::DurableSessionIdRegistry`]. What lives here is only the accepted
//! terms an authority freezes: chain, session id, roster, template, purpose,
//! adaptor point, initial transcript, and the canonical replay messages.

use dom_adaptor::{
    initial_transcript_hash_v1, AcceptedSigningSessionV1, ContractKindV1, ParticipantRosterV1,
    PurposeV1, SigningSessionAuthorityV1, TrustedChainIdV1,
};
use dom_crypto::PublicKey;

use crate::VaultError;

/// Immutable accepted two-party signing session frozen by the authority.
///
/// Every field is revalidated by the pin when the round state is built from
/// it, so this type carries no authority of its own — it is a faithful,
/// reconstructable description of one accepted session.
pub struct AcceptedSession {
    trusted_chain_id: TrustedChainIdV1,
    session_id: [u8; 32],
    contract_kind: ContractKindV1,
    purpose: PurposeV1,
    roster: ParticipantRosterV1,
    transaction_template: dom_consensus::Transaction,
    kernel_index: usize,
    adaptor_point: Option<PublicKey>,
    initial_transcript_hash: [u8; 32],
    messages: Vec<Vec<u8>>,
}

/// Complete typed request for one freshly accepted signing session.
pub struct AcceptedSessionFreshRequestV1 {
    /// Registry-authenticated DOM chain.
    pub trusted_chain_id: TrustedChainIdV1,
    /// Exact Scriptless Contracts session identifier.
    pub session_id: [u8; 32],
    /// Closed contract family.
    pub contract_kind: ContractKindV1,
    /// Closed signing purpose.
    pub purpose: PurposeV1,
    /// Exact authenticated two-party roster.
    pub roster: ParticipantRosterV1,
    /// Canonical transaction template retained by the session authority.
    pub transaction_template: dom_consensus::Transaction,
    /// Exact kernel position in the template.
    pub kernel_index: usize,
    /// Claim adaptor point, absent for non-adaptor purposes.
    pub adaptor_point: Option<PublicKey>,
}

impl AcceptedSession {
    /// Builds a fresh accepted session (no accepted messages yet).
    ///
    /// The initial transcript hash is recomputed from the pin's canonical
    /// function, exactly as the round bootstrap will recompute it — a
    /// divergent value makes `from_session_authority` fail closed.
    pub fn fresh(request: AcceptedSessionFreshRequestV1) -> Result<Self, VaultError> {
        let AcceptedSessionFreshRequestV1 {
            trusted_chain_id,
            session_id,
            contract_kind,
            purpose,
            roster,
            transaction_template,
            kernel_index,
            adaptor_point,
        } = request;
        if session_id == [0u8; 32] {
            return Err(VaultError::CorruptState);
        }
        let initial_transcript_hash =
            initial_transcript_hash_v1(&trusted_chain_id, &session_id, contract_kind, &roster);
        Ok(Self {
            trusted_chain_id,
            session_id,
            contract_kind,
            purpose,
            roster,
            transaction_template,
            kernel_index,
            adaptor_point,
            initial_transcript_hash,
            messages: Vec::new(),
        })
    }

    /// Appends one canonical accepted DSC1 message (peer replay order).
    ///
    /// Used to resume a session past the first barrier; a fresh session has
    /// none. The pin replays these under strict bounded-prefix rules.
    pub fn with_accepted_message(mut self, message: Vec<u8>) -> Self {
        self.messages.push(message);
        self
    }
}

impl AcceptedSigningSessionV1 for AcceptedSession {
    fn trusted_chain_id(&self) -> &TrustedChainIdV1 {
        &self.trusted_chain_id
    }

    fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    fn contract_kind(&self) -> ContractKindV1 {
        self.contract_kind
    }

    fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }

    fn transaction_template(&self) -> &dom_consensus::Transaction {
        &self.transaction_template
    }

    fn kernel_index(&self) -> usize {
        self.kernel_index
    }

    fn adaptor_point(&self) -> Option<&PublicKey> {
        self.adaptor_point.as_ref()
    }

    fn initial_transcript_hash(&self) -> &[u8; 32] {
        &self.initial_transcript_hash
    }

    fn accepted_signing_messages(&self) -> impl Iterator<Item = &[u8]> {
        self.messages.iter().map(Vec::as_slice)
    }
}

/// Statically selected signing-session authority for DOM Interop.
///
/// Names [`AcceptedSession`] as the accepted-session type. This is the
/// `Authority` type parameter passed to
/// `ValidatedSigningRoundStateV1::from_session_authority`, and the `Sessions`
/// parameter of `VaultBackedSignerV1`.
pub struct SessionAuthority;

impl SigningSessionAuthorityV1 for SessionAuthority {
    type Error = VaultError;
    type AcceptedSession = AcceptedSession;
}

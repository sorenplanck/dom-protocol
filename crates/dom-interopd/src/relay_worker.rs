//! Durable production Relay worker for one participant and one route.
//!
//! The worker composes the already-hardened sender outbox, recipient inbox,
//! V2 frame reassembler and Contracts session store.  It deliberately does
//! not infer a Contracts successor from an opaque DSC1 payload.  New messages
//! are admitted only through Store-issued, phase-specific capabilities;
//! already-journaled messages may use the Store's derived redelivery path.

use std::{
    path::{Path, PathBuf},
    rc::Rc,
};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use dom_scriptless_store::{
    CommittedOutboundDsc1V1, ContractsSessionStoreV1, DurableTransportOutcomeV1,
    DurableTransportReceiptV1, PreparedEarlyTransportAuthorityV1,
    PreparedOperationalBpTransportAuthorityV1, PreparedOperationalFinalClaimIngressAuthorityV2,
    PreparedOperationalFinalRefundTransportAuthorityV1, PreparedOperationalM8FundingGateV2,
    PreparedOperationalSigningTransportAuthorityV1,
    PreparedOperationalTemplateTransportAuthorityV1,
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV2, SessionPhaseV1, SessionStoreError,
};
use dom_scriptless_transport::SignedMessageV1;
use kaystra_core::types::Digest32;
use relay::auth::{message_type, RosterRegistryV1};
use relay::{ParticipantId, SenderRoleV1, TimelockSpec};
use route_transport::{
    ContractsRouteDeliveryV1, ContractsTransportPortV1, DurableFrameReassemblerConfigV2,
    DurableFrameReassemblerErrorV2, DurableFrameReassemblerStatsV2, DurableFrameReassemblerV2,
    DurableInboxConfigV1, DurableInboxError, DurableInboxIngestReportV1, DurableInboxStatsV1,
    DurableOutboundEnvelopeV1, DurablePayloadCommitV1, DurablePayloadDispositionV1,
    DurableProductionCreationStateV1, DurableRelayInboxV1, DurableRelaySenderConfigV1,
    DurableRelaySenderErrorV1, DurableRelaySenderStatsV1, DurableRelaySenderV1, F6DispatchErrorV1,
    F6DispatchReportV1, F6PayloadDeliveryV1, F6TransportPortV1, FramedContractsTransportErrorV2,
    FramedContractsTransportV2, RelayQueueV1, RouteApplicationDispositionV2, RouteDispatchErrorV1,
    RouteDispatchReportV1,
};

const RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/CONTRACTS-RELAY-RECEIPT/V1\0";
const FAILED_CLOSED_RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/CONTRACTS-RELAY-FAILED-CLOSED/V1\0";
const ZERO_DIGEST: Digest32 = [0; 32];

/// Owner-only directories used by the three independent Relay authorities.
pub struct RelayWorkerPathsV1 {
    sender_root: PathBuf,
    inbox_root: PathBuf,
    frame_reassembly_root: PathBuf,
}

impl core::fmt::Debug for RelayWorkerPathsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RelayWorkerPathsV1")
            .field("sender_root", &"[redacted]")
            .field("inbox_root", &"[redacted]")
            .field("frame_reassembly_root", &"[redacted]")
            .finish()
    }
}

impl RelayWorkerPathsV1 {
    /// Binds explicit roots.  Each underlying authority independently checks
    /// canonicality, owner, mode, link count and process exclusivity.
    pub fn new(
        sender_root: impl Into<PathBuf>,
        inbox_root: impl Into<PathBuf>,
        frame_reassembly_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            sender_root: sender_root.into(),
            inbox_root: inbox_root.into(),
            frame_reassembly_root: frame_reassembly_root.into(),
        }
    }

    /// Sender/outbox root.
    pub fn sender_root(&self) -> &Path {
        &self.sender_root
    }

    /// Recipient inbox root.
    pub fn inbox_root(&self) -> &Path {
        &self.inbox_root
    }

    /// V2 frame-reassembly root.
    pub fn frame_reassembly_root(&self) -> &Path {
        &self.frame_reassembly_root
    }
}

/// Frozen identities, wire binding and hard bounds for one Relay worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayWorkerConfigV1 {
    sender: DurableRelaySenderConfigV1,
    inbox: DurableInboxConfigV1,
    frames: DurableFrameReassemblerConfigV2,
}

impl RelayWorkerConfigV1 {
    /// Cross-checks the three authorities before any path is opened.
    pub fn new(
        sender: DurableRelaySenderConfigV1,
        inbox: DurableInboxConfigV1,
        frames: DurableFrameReassemblerConfigV2,
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        let wire = sender.wire_context();
        if inbox.wire_context() != wire
            || frames.wire_context() != wire
            || sender.sender_id() != inbox.recipient_id()
            || sender.sender_id() != frames.recipient_id()
        {
            return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            sender,
            inbox,
            frames,
        })
    }

    /// Shared frozen route wire context.
    pub const fn wire_context(&self) -> route_transport::RouteWireContextV1 {
        self.sender.wire_context()
    }

    /// Local participant owning the sender and recipient stores.
    pub const fn local_participant(&self) -> ParticipantId {
        self.sender.sender_id()
    }

    /// Remote participant addressed by the outbound flow.
    pub const fn remote_participant(&self) -> ParticipantId {
        self.sender.recipient_id()
    }

    pub(crate) const fn relay_signer_xonly(&self) -> &[u8; 32] {
        self.sender.signer_xonly()
    }

    pub(crate) const fn relay_sender_role(&self) -> SenderRoleV1 {
        self.sender.sender_role()
    }
}

/// Process-only Contracts ingress authority.
///
/// It has no codec, `Clone`, `Copy`, equality or debug surface.  The only
/// constructors consume opaque handles issued by `ContractsSessionStoreV1`.
/// A worker reopened after a crash must reissue the handle from the same
/// authenticated Store records.
pub struct PreparedContractsIngressV1 {
    inner: PreparedContractsIngressKindV1,
}

enum PreparedContractsIngressKindV1 {
    Early(PreparedEarlyTransportAuthorityV1),
    OperationalBp(PreparedOperationalBpTransportAuthorityV1),
    OperationalTemplate(PreparedOperationalTemplateTransportAuthorityV1),
    OperationalSigning(PreparedOperationalSigningTransportAuthorityV1),
    OperationalFinalRefund(PreparedOperationalFinalRefundTransportAuthorityV1),
    PostAnchorClaimPreSignature(Box<PreparedPostAnchorClaimPreSignatureTransportAuthorityV1>),
    PostAnchorClaimPreSignatureV2(Box<PreparedPostAnchorClaimPreSignatureTransportAuthorityV2>),
    ReadyToFundV2(PreparedOperationalM8FundingGateV2),
    FinalClaimIngressV2(Box<PreparedOperationalFinalClaimIngressAuthorityV2>),
}

impl PreparedContractsIngressV1 {
    /// Authorizes only the prepared DSC1 `Offer`, `Accept`, `ShareCommit` and
    /// `ShareReveal` state machine owned by the Store.
    pub fn early(authority: PreparedEarlyTransportAuthorityV1) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::Early(authority),
        }
    }

    /// Authorizes only the prepared operational Bulletproof transport rounds
    /// from `BpCommonCommitment` through `BpFinalProof` (`0x05`–`0x0a`).
    pub fn operational_bp(authority: PreparedOperationalBpTransportAuthorityV1) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalBp(authority),
        }
    }

    /// Authorizes only the two prepared operational `TxTemplateCommit`
    /// messages (`0x0b`) over the Store-frozen canonical templates.
    pub fn operational_template(
        authority: PreparedOperationalTemplateTransportAuthorityV1,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalTemplate(authority),
        }
    }

    /// Authorizes only one Store-frozen operational signing round across
    /// nonce commitments, nonce reveals and partial signatures (`0x0c`–`0x0e`).
    pub fn operational_signing(authority: PreparedOperationalSigningTransportAuthorityV1) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalSigning(authority),
        }
    }

    /// Authorizes only the exact Store-derived, fully signed operational
    /// Refund transaction (`FinalRefund`, `0x10`).
    pub fn operational_final_refund(
        authority: PreparedOperationalFinalRefundTransportAuthorityV1,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalFinalRefund(authority),
        }
    }

    /// Authorizes only the Store-frozen post-anchor Claim adaptor
    /// pre-signature transport edge (`0x0f`).
    pub fn post_anchor_claim_pre_signature(
        authority: PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(Box::new(authority)),
        }
    }

    /// Authorizes only the Store-frozen V2 post-anchor Claim adaptor
    /// pre-signature transport edge (`0x0f`).
    ///
    /// This is the productive constructor. The V1 form above remains available
    /// solely for legacy evidence-only recovery: its Store entrypoints refuse
    /// the ratified production profile.
    pub fn post_anchor_claim_pre_signature_v2(
        authority: PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(Box::new(
                authority,
            )),
        }
    }

    /// Authorizes only the next Store-derived M.8 `ReadyToFund` vote.
    pub fn ready_to_fund_v2(authority: PreparedOperationalM8FundingGateV2) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::ReadyToFundV2(authority),
        }
    }

    /// Authorizes only the reception of the counterparty's exact FinalClaim
    /// (`0x12`).
    ///
    /// The boxed capability is the Store's *ingress* authority, minted from
    /// the durable FinalClaim observation record; it is deliberately not the
    /// transport authority of the same phase, which is the emitter-side
    /// capability minted from the admission record and consumed by
    /// `prepare_final_claim_dsc1_signing_request_v2`.  Installing the emitter
    /// capability here would compile and then never accept a real `0x12`,
    /// because the Store's accept entrypoint takes the ingress form.
    ///
    /// This variant is reception-only.  A locally owned FinalClaim leaves
    /// through [`DurableRelayWorkerV1::stage_store_outbound_dsc1`] like every
    /// other Store-committed outbound DSC1 object, never through an installed
    /// ingress capability.
    pub fn final_claim_ingress_v2(
        authority: PreparedOperationalFinalClaimIngressAuthorityV2,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::FinalClaimIngressV2(Box::new(authority)),
        }
    }

    /// Recovers the linear M.8 gate after the Relay votes have been accepted,
    /// so the composition root can consume it at the funding boundary.
    ///
    /// Every authority for another phase is returned unchanged in `Err`; no
    /// capability is cloned, serialized or silently discarded.
    pub fn into_ready_to_fund_v2(self) -> Result<PreparedOperationalM8FundingGateV2, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::ReadyToFundV2(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers an early-phase authority without exposing any capability's
    /// representation. Authorities for other phases are returned unchanged in
    /// `Err`.
    pub fn into_early(self) -> Result<PreparedEarlyTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::Early(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the operational Bulletproof authority without exposing its
    /// representation.  Authorities for other phases are returned unchanged
    /// in `Err`.
    pub fn into_operational_bp(
        self,
    ) -> Result<PreparedOperationalBpTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalBp(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the operational template authority without exposing its
    /// representation. Authorities for other phases are returned unchanged
    /// in `Err`.
    pub fn into_operational_template(
        self,
    ) -> Result<PreparedOperationalTemplateTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalTemplate(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the operational signing authority without exposing its
    /// representation. Authorities for other phases are returned unchanged
    /// in `Err`.
    pub fn into_operational_signing(
        self,
    ) -> Result<PreparedOperationalSigningTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalSigning(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the exact final Refund authority without exposing its
    /// representation. Authorities for other phases are returned unchanged in
    /// `Err`.
    pub fn into_operational_final_refund(
        self,
    ) -> Result<PreparedOperationalFinalRefundTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalFinalRefund(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the post-anchor Claim pre-signature authority without
    /// exposing its representation. Authorities for other phases are returned
    /// unchanged in `Err`.
    pub fn into_post_anchor_claim_pre_signature(
        self,
    ) -> Result<PreparedPostAnchorClaimPreSignatureTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(authority) => {
                Ok(*authority)
            }
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the V2 post-anchor Claim pre-signature authority without
    /// exposing its representation. Authorities for other phases are returned
    /// unchanged in `Err`.
    pub fn into_post_anchor_claim_pre_signature_v2(
        self,
    ) -> Result<PreparedPostAnchorClaimPreSignatureTransportAuthorityV2, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(authority) => {
                Ok(*authority)
            }
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the FinalClaim ingress authority without exposing its
    /// representation. Authorities for other phases are returned unchanged in
    /// `Err`.
    pub fn into_final_claim_ingress_v2(
        self,
    ) -> Result<PreparedOperationalFinalClaimIngressAuthorityV2, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::FinalClaimIngressV2(authority) => Ok(*authority),
            inner @ (PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)) => Err(Box::new(Self { inner })),
        }
    }
}

/// Redacted construction/reopen failures.
#[derive(Debug, thiserror::Error)]
pub enum RelayWorkerOpenErrorV1 {
    /// Component identities, roles, wire contexts or roster facts diverge.
    #[error("invalid Relay worker configuration")]
    InvalidConfiguration,
    /// The sender/outbox authority refused creation or reopen.
    #[error("Relay sender authority: {0}")]
    Sender(#[from] DurableRelaySenderErrorV1),
    /// The recipient inbox authority refused creation or reopen.
    #[error("Relay inbox authority: {0}")]
    Inbox(#[from] DurableInboxError),
    /// The V2 reassembly authority refused creation or reopen.
    #[error("Relay frame authority: {0}")]
    Frames(#[from] DurableFrameReassemblerErrorV2),
    /// The Contracts Store could not authenticate the bound session.
    #[error("Contracts session authority: {0}")]
    Contracts(#[from] SessionStoreError),
    /// Operating-system entropy was unavailable for secp context hardening.
    #[error("operating-system entropy unavailable")]
    EntropyUnavailable,
}

/// Refusals at the strict Relay-to-Contracts boundary.
#[derive(Debug, thiserror::Error)]
pub enum ContractsRelayIngressErrorV1 {
    /// The single-threaded Contracts/Relay owner is already serving another
    /// operation; callers must retry without opening another worker.
    #[error("Contracts Relay owner is busy")]
    OwnerBusy,
    /// The Store refused, quarantined or could not authenticate the operation.
    #[error("Contracts Store refused Relay ingress: {0}")]
    Store(#[from] SessionStoreError),
    /// No Store-issued authority exists for this unseen message phase.
    #[error("unseen DSC1 message has no prepared Contracts authority")]
    UnpreparedMessage,
    /// A capability belongs to a different session or Store state.
    #[error("prepared Contracts ingress authority does not match this route")]
    WrongAuthority,
    /// A linear capability is already installed and must first be taken.
    #[error("a prepared Contracts ingress authority is already installed")]
    AuthorityAlreadyInstalled,
    /// A nonzero durable receipt could not be constructed.
    #[error("Contracts Store returned an invalid durable ingress receipt")]
    InvalidReceipt,
    /// The inner DSC1 envelope is malformed or not canonically encoded.
    #[error("Relay payload is not a canonical signed DSC1 envelope")]
    InvalidDsc1,
    /// The authenticated outer Relay sender differs from the inner DSC1 signer.
    #[error("outer Relay sender does not match the inner DSC1 sender")]
    SenderMismatch,
}

/// Redacted outbound worker failures.
#[derive(Debug, thiserror::Error)]
pub enum RelayWorkerOutboundErrorV1 {
    /// The single-threaded Contracts/Relay owner is already serving another
    /// operation; callers must retry through the same retained worker.
    #[error("Contracts Relay owner is busy")]
    OwnerBusy,
    /// Operating-system entropy was unavailable for BIP340 auxiliary input.
    #[error("operating-system entropy unavailable")]
    EntropyUnavailable,
    /// The durable sender refused preparation, submit, ACK or retained state.
    #[error("Relay sender authority: {0}")]
    Sender(#[from] DurableRelaySenderErrorV1),
    /// The shared Contracts Store rejected, quarantined or could not
    /// reauthenticate the Store-issued outbound handle.
    #[error("Contracts Store refused outbound Relay staging")]
    StoreRejected,
    /// The proposed inner payload is not one exact canonical DSC1 envelope.
    #[error("outbound DSC1 is not canonically encoded")]
    InvalidDsc1,
    /// The inner sender/session differs from the worker's frozen addressed flow.
    #[error("outbound DSC1 does not belong to this Relay sender")]
    WrongDsc1Scope,
}

/// A complete inbound step failed.  Accepted outer envelopes remain durable;
/// the first uncommitted downstream row remains pending for exact redelivery.
#[derive(Debug, thiserror::Error)]
pub enum RelayWorkerInboundErrorV1<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Mailbox authentication or inbox persistence failed.
    #[error("Relay inbox ingest: {0}")]
    Ingest(#[from] DurableInboxError),
    /// The shared F6 authority refused its next pending object.
    #[error("Relay F6 dispatch: {0}")]
    F6(#[source] F6DispatchErrorV1<E>),
    /// Frame reassembly or the Contracts Store refused its next pending DSC1.
    #[error("Relay Contracts dispatch: {0}")]
    Contracts(
        #[source]
        RouteDispatchErrorV1<FramedContractsTransportErrorV2<ContractsRelayIngressErrorV1>>,
    ),
}

/// Secret-free Contracts head information suitable for health reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractsSessionStatusV1 {
    /// Current durable revision.
    pub revision: u64,
    /// Current authenticated phase.
    pub phase: SessionPhaseV1,
}

/// Closed F6 kinds that share the outbound checkpoint with DSC1 traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayF6MessageKindV1 {
    /// RFQ emitted by the initiator.
    Rfq,
    /// Quote emitted by a solver.
    Quote,
    /// Quote acceptance emitted by the initiator.
    Acceptance,
    /// Deterministic selection emitted by the initiator.
    Selection,
}

impl RelayF6MessageKindV1 {
    const fn wire_kind(self) -> u16 {
        match self {
            Self::Rfq => message_type::RFQ,
            Self::Quote => message_type::QUOTE,
            Self::Acceptance => message_type::ACCEPTANCE,
            Self::Selection => message_type::SELECTION,
        }
    }
}

/// Secret-free evidence that an exact outbound envelope is already durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedRelayOutboundV1 {
    /// Ratified Relay kind.
    pub message_type: u16,
    /// Shared-flow sequence.
    pub sequence: u64,
    /// Digest of the exact retained signed envelope.
    pub envelope_digest: Digest32,
    /// Frame index for V2, absent for F6 and direct route messages.
    pub frame_index: Option<u16>,
    /// Total V2 frame count when framed.
    pub frame_count: Option<u16>,
}

/// Result of one outbound step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayOutboundStepV1 {
    /// No exact envelope is currently staged.  A Store application may still
    /// require re-staging to prepare its next reserved frame or reconcile its
    /// final durable ACK.
    Idle,
    /// One exact ACK and the advanced shared checkpoint are durable.
    Acked {
        /// Ratified Relay kind.
        message_type: u16,
        /// Frame index for V2, if this ACK belongs to a frame.
        frame_index: Option<u16>,
        /// Sequence that will be used by the next F6 or route envelope.
        next_sequence: u64,
        /// Digest acknowledged by the Relay.
        envelope_digest: Digest32,
    },
}

/// Result of dispatching the already-durable shared inbox in protocol order.
#[derive(Debug)]
pub struct RelayInboundDispatchReportV1 {
    /// F6 objects consumed before the currently eligible route segment.
    pub f6: F6DispatchReportV1,
    /// Direct envelopes or authenticated frames consumed by Contracts.
    pub contracts: RouteDispatchReportV1,
    /// Counters after both downstream authorities returned durable receipts.
    pub inbox: DurableInboxStatsV1,
    /// Bounded V2 reassembly counters after the step.
    pub frames: DurableFrameReassemblerStatsV2,
}

/// Full mailbox pull plus ordered downstream-dispatch report.
#[derive(Debug)]
pub struct RelayInboundPollReportV1 {
    /// Outer envelopes authenticated and committed before dispatch.
    pub ingest: DurableInboxIngestReportV1,
    /// Shared-order downstream results.
    pub dispatch: RelayInboundDispatchReportV1,
}

/// Explicit fail-closed F6 boundary for a composition that has not installed
/// its real RFQ/solver authority.  A pending F6 row blocks later route traffic
/// in the same flow instead of being skipped.
#[derive(Default)]
pub struct UnavailableF6AuthorityV1;

impl core::fmt::Debug for UnavailableF6AuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("UnavailableF6AuthorityV1").finish()
    }
}

/// Named fail-closed error from [`UnavailableF6AuthorityV1`].
#[derive(Debug, thiserror::Error)]
#[error("no production F6 authority is installed")]
pub struct UnavailableF6AuthorityErrorV1;

impl F6TransportPortV1 for UnavailableF6AuthorityV1 {
    type Error = UnavailableF6AuthorityErrorV1;

    fn accept_f6(
        &mut self,
        _delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        Err(UnavailableF6AuthorityErrorV1)
    }
}

struct ContractsStoreTransportPortV1 {
    store: Rc<ContractsSessionStoreV1>,
    session_id: Digest32,
    /// Participant this worker signs as, taken from the route configuration.
    /// It is never supplied by a caller at install time, so an installed
    /// capability cannot name its own recipient.
    local_participant: ParticipantId,
    /// The single counterparty this route addresses, from the same frozen
    /// configuration.
    remote_participant: ParticipantId,
    authority: Option<PreparedContractsIngressV1>,
}

impl ContractsStoreTransportPortV1 {
    fn new(
        store: Rc<ContractsSessionStoreV1>,
        session_id: Digest32,
        local_participant: ParticipantId,
        remote_participant: ParticipantId,
    ) -> Result<Self, SessionStoreError> {
        store.load_session(session_id)?;
        Ok(Self {
            store,
            session_id,
            local_participant,
            remote_participant,
            authority: None,
        })
    }

    fn install(
        &mut self,
        authority: PreparedContractsIngressV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        if self.authority.is_some() {
            return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled);
        }
        match &authority.inner {
            PreparedContractsIngressKindV1::Early(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalBp(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalTemplate(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalSigning(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalFinalRefund(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::FinalClaimIngressV2(prepared) => {
                // Three predicates, all against facts frozen before this call:
                // the session comes from the store opening, and the two
                // participants from the route configuration.  The Store has
                // already bound the identities into the capability; this is
                // the worker refusing a capability issued for another session
                // or another pair, so a misrouted `0x12` fails here and not
                // one layer down.
                if prepared.session_id() != &self.session_id
                    || ParticipantId(*prepared.final_claim_receiver_id()) != self.local_participant
                    || ParticipantId(*prepared.dom_claim_sender_id()) != self.remote_participant
                {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::ReadyToFundV2(prepared) => {
                match self
                    .store
                    .prepare_next_operational_m8_ready_to_fund_vote_v2(prepared)?
                {
                    Some(vote) if vote.session_id() != self.session_id => {
                        return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                    }
                    Some(_) => {}
                    // Both votes already durable means Relay ingress has no
                    // remaining work.  The caller must retain/take the gate
                    // for funding instead of installing a no-op authority.
                    None => return Err(ContractsRelayIngressErrorV1::UnpreparedMessage),
                }
            }
        }
        self.authority = Some(authority);
        Ok(())
    }

    fn take_authority(&mut self) -> Option<PreparedContractsIngressV1> {
        self.authority.take()
    }

    fn session_status(&self) -> Result<ContractsSessionStatusV1, SessionStoreError> {
        let current = self.store.load_session(self.session_id)?;
        Ok(ContractsSessionStatusV1 {
            revision: current.revision(),
            phase: current.phase(),
        })
    }

    fn terminal_commit(
        &self,
        duplicate: bool,
    ) -> Result<Option<DurablePayloadCommitV1>, ContractsRelayIngressErrorV1> {
        let current = self.store.load_session(self.session_id)?;
        if current.phase() != SessionPhaseV1::FailedClosed {
            return Ok(None);
        }
        let receipt = digest_parts(
            FAILED_CLOSED_RECEIPT_DOMAIN,
            &[&self.session_id, current.digest()],
        )?;
        DurablePayloadCommitV1::new(
            DurablePayloadDispositionV1::FailedClosed,
            receipt,
            duplicate,
        )
        .map(Some)
        .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)
    }

    fn map_outcome(
        &self,
        outcome: DurableTransportOutcomeV1,
    ) -> Result<DurablePayloadCommitV1, ContractsRelayIngressErrorV1> {
        match outcome {
            DurableTransportOutcomeV1::Accepted(receipt) => {
                let digest = accepted_receipt_digest(self.session_id, receipt)?;
                DurablePayloadCommitV1::new(
                    DurablePayloadDispositionV1::Applied,
                    digest,
                    receipt.duplicate,
                )
                .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)
            }
            DurableTransportOutcomeV1::EquivocationPersisted => self
                .terminal_commit(false)?
                .ok_or(ContractsRelayIngressErrorV1::InvalidReceipt),
        }
    }

    fn accept_unseen(
        &self,
        signed_dsc1: &[u8],
    ) -> Result<DurablePayloadCommitV1, ContractsRelayIngressErrorV1> {
        let Some(authority) = self.authority.as_ref() else {
            return self
                .terminal_commit(true)?
                .ok_or(ContractsRelayIngressErrorV1::UnpreparedMessage);
        };
        let accepted = match &authority.inner {
            PreparedContractsIngressKindV1::Early(prepared) => self
                .store
                .accept_prepared_early_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalBp(prepared) => self
                .store
                .accept_prepared_operational_bp_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalTemplate(prepared) => self
                .store
                .accept_prepared_operational_template_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalSigning(prepared) => self
                .store
                .accept_prepared_operational_signing_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalFinalRefund(prepared) => self
                .store
                .accept_prepared_operational_final_refund_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(prepared) => self
                .store
                .accept_prepared_post_anchor_dom_claim_pre_signature_transport_message(
                    prepared,
                    signed_dsc1,
                ),
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(prepared) => self
                .store
                .accept_prepared_post_anchor_dom_claim_pre_signature_transport_message_v2(
                    prepared,
                    signed_dsc1,
                ),
            PreparedContractsIngressKindV1::FinalClaimIngressV2(prepared) => self
                .store
                .accept_prepared_operational_final_claim_transport_message_v2(
                    prepared,
                    signed_dsc1,
                ),
            PreparedContractsIngressKindV1::ReadyToFundV2(prepared) => {
                let vote = self
                    .store
                    .prepare_next_operational_m8_ready_to_fund_vote_v2(prepared)?
                    .ok_or(ContractsRelayIngressErrorV1::UnpreparedMessage)?;
                self.store
                    .accept_prepared_operational_m8_ready_to_fund_vote_v2(
                        prepared,
                        vote,
                        signed_dsc1,
                    )?;
                // The purpose-specific Store method above owns semantic
                // validation and the first durable transition, but returns
                // `()`.  The generic derived entrypoint is then safe only as
                // an exact-redelivery readback: it retrieves the authenticated
                // receipt from the just-retained row.  It must report a
                // duplicate; the worker clears that flag for this first outer
                // delivery before committing its inbox row.
                let replay = self.store.accept_transport_message_derived(signed_dsc1)?;
                let receipt = first_delivery_receipt_from_prepared_readback(replay)
                    .map_err(ContractsRelayIngressErrorV1::Store)?;
                return self.map_accepted_receipt(receipt, false);
            }
        };
        match accepted {
            Ok(outcome) => self.map_outcome(outcome),
            Err(error) => self
                .terminal_commit(true)?
                .ok_or(ContractsRelayIngressErrorV1::Store(error)),
        }
    }

    fn map_accepted_receipt(
        &self,
        receipt: DurableTransportReceiptV1,
        duplicate: bool,
    ) -> Result<DurablePayloadCommitV1, ContractsRelayIngressErrorV1> {
        let digest = accepted_receipt_digest(self.session_id, receipt)?;
        DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, digest, duplicate)
            .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)
    }
}

impl ContractsTransportPortV1 for ContractsStoreTransportPortV1 {
    type Error = ContractsRelayIngressErrorV1;

    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let parsed = SignedMessageV1::decode_exact(delivery.signed_dsc1())
            .map_err(|_| ContractsRelayIngressErrorV1::InvalidDsc1)?;
        if ParticipantId(*parsed.unsigned().sender_id()) != delivery.sender_id() {
            return Err(ContractsRelayIngressErrorV1::SenderMismatch);
        }
        let was_failed_closed =
            self.store.load_session(self.session_id)?.phase() == SessionPhaseV1::FailedClosed;
        match self
            .store
            .accept_transport_message_derived(delivery.signed_dsc1())
        {
            Ok(DurableTransportOutcomeV1::EquivocationPersisted) if was_failed_closed => self
                .terminal_commit(true)?
                .ok_or(ContractsRelayIngressErrorV1::InvalidReceipt),
            Ok(outcome) => self.map_outcome(outcome),
            Err(SessionStoreError::InvalidTransition) => self.accept_unseen(delivery.signed_dsc1()),
            Err(error) => self
                .terminal_commit(true)?
                .ok_or(ContractsRelayIngressErrorV1::Store(error)),
        }
    }
}

/// Productive, durable Relay worker for one local participant and route.
///
/// `F` is the real F6 persistence authority.  Deployments that have not wired
/// it may explicitly select [`UnavailableF6AuthorityV1`], which blocks rather
/// than skips F6.  The Contracts authority is fixed to the real
/// `ContractsSessionStoreV1` and cannot be replaced by a caller-shaped port.
pub struct DurableRelayWorkerV1<F>
where
    F: F6TransportPortV1,
{
    sender: DurableRelaySenderV1,
    inbox: DurableRelayInboxV1,
    contracts: FramedContractsTransportV2<ContractsStoreTransportPortV1>,
    rosters: RosterRegistryV1,
    f6: F,
}

impl<F> core::fmt::Debug for DurableRelayWorkerV1<F>
where
    F: F6TransportPortV1,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableRelayWorkerV1")
            .field("sender", &self.sender)
            .field("inbox", &self.inbox)
            .field("contracts", &"[redacted]")
            .field("f6", &"[redacted]")
            .finish()
    }
}

impl<F> DurableRelayWorkerV1<F>
where
    F: F6TransportPortV1,
{
    /// Creates the three durable Relay authorities around the single shared
    /// opening of a production Contracts Store.  Partial creation remains on
    /// disk and is never silently replaced by a fresh store.
    pub fn create(
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        contracts_store: Rc<ContractsSessionStoreV1>,
        rosters: RosterRegistryV1,
        f6: F,
        signing_secret: [u8; 32],
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        validate_roster(&config, &rosters)?;
        let contracts = ContractsStoreTransportPortV1::new(
            contracts_store,
            config.wire_context().session_id,
            config.local_participant(),
            config.remote_participant(),
        )?;
        let sender = DurableRelaySenderV1::create(
            paths.sender_root(),
            config.sender,
            signing_secret,
            os_random_32().map_err(|_| RelayWorkerOpenErrorV1::EntropyUnavailable)?,
        )?;
        let inbox = DurableRelayInboxV1::create(paths.inbox_root(), config.inbox, &rosters)?;
        let frames =
            DurableFrameReassemblerV2::create(paths.frame_reassembly_root(), config.frames)?;
        Ok(Self {
            sender,
            inbox,
            contracts: FramedContractsTransportV2::new(frames, contracts),
            rosters,
            f6,
        })
    }

    /// Completes a Stage-11 production create after a crash at any of the
    /// three Relay authority boundaries. Each underlying resume accepts only
    /// its exact pristine creation prefix; an authority that has accepted or
    /// emitted economic traffic cannot be reclassified as provisioning.
    ///
    /// The caller supplies the same single `Rc` opening owned by
    /// `ProductionContractsV1`; this method never opens, clones, or replaces a
    /// Contracts Store.
    pub fn resume_create_production(
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        contracts_store: Rc<ContractsSessionStoreV1>,
        rosters: RosterRegistryV1,
        f6: F,
        signing_secret: [u8; 32],
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        validate_roster(&config, &rosters)?;
        let sender_state =
            DurableRelaySenderV1::production_creation_state(paths.sender_root(), config.sender)?;
        let inbox_state =
            DurableRelayInboxV1::production_creation_state(paths.inbox_root(), config.inbox)?;
        let frame_state = DurableFrameReassemblerV2::production_creation_state(
            paths.frame_reassembly_root(),
            config.frames,
        )?;
        if (inbox_state != DurableProductionCreationStateV1::Missing
            && sender_state != DurableProductionCreationStateV1::InitializedPristine)
            || (frame_state != DurableProductionCreationStateV1::Missing
                && inbox_state != DurableProductionCreationStateV1::InitializedPristine)
        {
            return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
        }
        let contracts = ContractsStoreTransportPortV1::new(
            contracts_store,
            config.wire_context().session_id,
            config.local_participant(),
            config.remote_participant(),
        )?;
        let sender = DurableRelaySenderV1::resume_create_production(
            paths.sender_root(),
            config.sender,
            signing_secret,
            os_random_32().map_err(|_| RelayWorkerOpenErrorV1::EntropyUnavailable)?,
        )?;
        let inbox = DurableRelayInboxV1::resume_create_production(
            paths.inbox_root(),
            config.inbox,
            &rosters,
        )?;
        let frames = DurableFrameReassemblerV2::resume_create_production(
            paths.frame_reassembly_root(),
            config.frames,
        )?;
        Ok(Self {
            sender,
            inbox,
            contracts: FramedContractsTransportV2::new(frames, contracts),
            rosters,
            f6,
        })
    }

    /// Reopens the exact three Relay stores around the single shared Contracts
    /// Store opening.  No missing database is created and no schema migration
    /// or capability reissuance happens implicitly.
    pub fn open_existing(
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        contracts_store: Rc<ContractsSessionStoreV1>,
        rosters: RosterRegistryV1,
        f6: F,
        signing_secret: [u8; 32],
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        validate_roster(&config, &rosters)?;
        let contracts = ContractsStoreTransportPortV1::new(
            contracts_store,
            config.wire_context().session_id,
            config.local_participant(),
            config.remote_participant(),
        )?;
        let sender = DurableRelaySenderV1::open_existing(
            paths.sender_root(),
            config.sender,
            signing_secret,
            os_random_32().map_err(|_| RelayWorkerOpenErrorV1::EntropyUnavailable)?,
        )?;
        let inbox = DurableRelayInboxV1::open(paths.inbox_root(), config.inbox, &rosters)?;
        let frames = DurableFrameReassemblerV2::open(paths.frame_reassembly_root(), config.frames)?;
        Ok(Self {
            sender,
            inbox,
            contracts: FramedContractsTransportV2::new(frames, contracts),
            rosters,
            f6,
        })
    }

    /// Installs one process-only Store-issued ingress capability.  This covers
    /// the early rounds, operational Bulletproof/template/signing rounds, the
    /// exact final Refund, the V2 post-anchor Claim pre-signature edge (or its
    /// legacy V1 recovery form), or the M.8 vote gate.
    /// An existing linear capability must first be taken; unsupported phases
    /// remain closed.
    pub fn install_contracts_ingress(
        &mut self,
        authority: PreparedContractsIngressV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts.contracts_mut().install(authority)
    }

    /// Takes the process-local capability without cloning or discarding it.
    ///
    /// This is required after both M.8 votes so the caller can unwrap the same
    /// linear gate with [`PreparedContractsIngressV1::into_ready_to_fund_v2`] and
    /// consume it at the Store's funding-authorization boundary.  It also
    /// permits restart-safe reissue of early, Bulletproof, template, signing,
    /// final Refund or post-anchor Claim pre-signature (V1 or V2) authorities.
    /// With no installed capability, unseen DSC1 messages remain fail-closed.
    pub fn take_contracts_ingress(&mut self) -> Option<PreparedContractsIngressV1> {
        self.contracts.contracts_mut().take_authority()
    }

    /// Returns only the secret-free authenticated Contracts head.
    ///
    /// The underlying Store is intentionally not exposed: its APIs mutate via
    /// shared references, so returning `&ContractsSessionStoreV1` would bypass
    /// the worker's phase authority and inbox ordering.
    pub fn contracts_session_status(
        &mut self,
    ) -> Result<ContractsSessionStatusV1, SessionStoreError> {
        self.contracts.contracts_mut().session_status()
    }

    /// Mutable access to the installed F6 authority for coordinated recovery.
    pub fn f6_mut(&mut self) -> &mut F {
        &mut self.f6
    }

    /// Persists one F6 envelope before any Relay submission.
    pub fn prepare_f6(
        &mut self,
        kind: RelayF6MessageKindV1,
        payload: &[u8],
        expiry: TimelockSpec,
    ) -> Result<PreparedRelayOutboundV1, RelayWorkerOutboundErrorV1> {
        let pending = self.sender.prepare_message(
            kind.wire_kind(),
            payload,
            expiry,
            os_random_32().map_err(|_| RelayWorkerOutboundErrorV1::EntropyUnavailable)?,
        )?;
        Ok(prepared_report(&pending))
    }

    /// Stages or reconciles one DSC1 object already signed and committed by
    /// the same physical Contracts Store opening embedded in this worker.
    ///
    /// The opaque handle is reauthenticated before its exact signed bytes are
    /// decoded and cross-checked against both the handle and the worker's
    /// frozen sender/session.  The bytes then enter only the durable Route
    /// application V2 API under the Store-minted application identifier.
    /// `AlreadyAcked` is returned only after the Store has durably recorded
    /// the completed Relay handoff.  A pending handle is deliberately not
    /// returned: crash recovery reissues it from the same Store journal.
    pub fn stage_store_outbound_dsc1(
        &mut self,
        outbound: CommittedOutboundDsc1V1,
        expiry: TimelockSpec,
    ) -> Result<RouteApplicationDispositionV2, RelayWorkerOutboundErrorV1> {
        let store = Rc::clone(&self.contracts.contracts_mut().store);
        store
            .revalidate_committed_outbound_dsc1(&outbound)
            .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?;

        let parsed = SignedMessageV1::decode_exact(outbound.signed_bytes())
            .map_err(|_| RelayWorkerOutboundErrorV1::InvalidDsc1)?;
        let checkpoint = self.sender.checkpoint()?;
        if parsed.unsigned().session_id() != outbound.session_id()
            || parsed.unsigned().sender_id() != outbound.sender_id()
            || parsed.unsigned().sequence() != outbound.sequence()
            || parsed.digest() != outbound.message_digest()
            || ParticipantId(*outbound.sender_id()) != checkpoint.sender_id()
            || parsed.unsigned().session_id() != &checkpoint.wire_context().session_id
        {
            return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
        }
        let aux = os_random_32().map_err(|_| RelayWorkerOutboundErrorV1::EntropyUnavailable)?;
        let disposition = self.sender.prepare_route_application(
            *outbound.application_id(),
            outbound.signed_bytes(),
            expiry,
            aux,
        )?;
        if disposition.status().application_id() != outbound.application_id() {
            return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
        }
        match disposition {
            RouteApplicationDispositionV2::Pending(_) => Ok(disposition),
            RouteApplicationDispositionV2::AlreadyAcked(_) => {
                store
                    .complete_outbound_dsc1_relay_handoff(outbound)
                    .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?;
                Ok(disposition)
            }
        }
    }

    /// Submits at most one exact durable envelope.  Lost or inconsistent ACKs
    /// leave it pending byte-identically.  If an application-managed V2 frame
    /// was just acknowledged, the next frame is persisted only by repeating
    /// [`Self::stage_store_outbound_dsc1`] with the Store-recovered handle;
    /// this method never enters the legacy caller-shaped frame path.
    pub fn submit_outbound_once<Q: RelayQueueV1>(
        &mut self,
        queue: &mut Q,
    ) -> Result<RelayOutboundStepV1, RelayWorkerOutboundErrorV1> {
        if self.sender.pending_envelope()?.is_none() {
            return Ok(RelayOutboundStepV1::Idle);
        }
        let committed = self.sender.submit_pending(queue)?;
        Ok(RelayOutboundStepV1::Acked {
            message_type: committed.message_type(),
            frame_index: committed.frame_index(),
            next_sequence: committed.checkpoint().next_sequence(),
            envelope_digest: committed.ack().digest,
        })
    }

    /// Pulls and authenticates the mailbox through the one durable transcript,
    /// without dispatching any downstream payload.
    pub fn ingest_mailbox<Q: RelayQueueV1>(
        &mut self,
        queue: &Q,
        now: TimelockSpec,
    ) -> Result<DurableInboxIngestReportV1, DurableInboxError> {
        self.inbox.ingest(queue, &self.rosters, now)
    }

    /// Dispatches the already-durable inbox in shared F6/route order.  F6 is
    /// attempted first; the inbox itself prevents either class from jumping a
    /// still-pending predecessor in the other class.
    pub fn dispatch_inbound(
        &mut self,
    ) -> Result<RelayInboundDispatchReportV1, RelayWorkerInboundErrorV1<F::Error>> {
        let f6 = self
            .inbox
            .dispatch_f6(&mut self.f6)
            .map_err(RelayWorkerInboundErrorV1::F6)?;
        let contracts = self
            .inbox
            .dispatch_routes(&mut self.contracts)
            .map_err(RelayWorkerInboundErrorV1::Contracts)?;
        let inbox = self.inbox.stats()?;
        let frames = self.contracts.stats().map_err(|error| {
            RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
                FramedContractsTransportErrorV2::Reassembly(error),
            ))
        })?;
        Ok(RelayInboundDispatchReportV1 {
            f6,
            contracts,
            inbox,
            frames,
        })
    }

    /// Executes one mailbox pull followed by the ordered downstream step.
    pub fn poll_inbound<Q: RelayQueueV1>(
        &mut self,
        queue: &Q,
        now: TimelockSpec,
    ) -> Result<RelayInboundPollReportV1, RelayWorkerInboundErrorV1<F::Error>> {
        let ingest = self.ingest_mailbox(queue, now)?;
        let dispatch = self.dispatch_inbound()?;
        Ok(RelayInboundPollReportV1 { ingest, dispatch })
    }

    /// Secret-free sender/outbox counters.
    pub fn sender_stats(&self) -> Result<DurableRelaySenderStatsV1, DurableRelaySenderErrorV1> {
        self.sender.stats()
    }

    /// Secret-free inbox counters.
    pub fn inbox_stats(&self) -> Result<DurableInboxStatsV1, DurableInboxError> {
        self.inbox.stats()
    }

    /// Bounded V2 frame counters.
    pub fn frame_stats(
        &self,
    ) -> Result<DurableFrameReassemblerStatsV2, DurableFrameReassemblerErrorV2> {
        self.contracts.stats()
    }
}

fn validate_roster(
    config: &RelayWorkerConfigV1,
    rosters: &RosterRegistryV1,
) -> Result<(), RelayWorkerOpenErrorV1> {
    let Some(snapshot) = rosters.snapshot(&config.wire_context().roster_snapshot) else {
        return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
    };
    let Some(local) = snapshot.member(&config.local_participant()) else {
        return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
    };
    if local.role != config.sender.sender_role()
        || local.xonly_key != *config.sender.signer_xonly()
        || snapshot.member(&config.remote_participant()).is_none()
    {
        return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn prepared_report(pending: &DurableOutboundEnvelopeV1) -> PreparedRelayOutboundV1 {
    PreparedRelayOutboundV1 {
        message_type: pending.message_type(),
        sequence: pending.sequence(),
        envelope_digest: *pending.envelope_digest(),
        frame_index: pending.frame_index(),
        frame_count: pending.frame_count(),
    }
}

fn accepted_receipt_digest(
    session_id: Digest32,
    receipt: DurableTransportReceiptV1,
) -> Result<Digest32, ContractsRelayIngressErrorV1> {
    let sequence = receipt.sequence.to_be_bytes();
    let message_type = [receipt.message_type];
    digest_parts(
        RECEIPT_DOMAIN,
        &[
            &session_id,
            &receipt.message_digest,
            &receipt.transcript_hash,
            &sequence,
            &message_type,
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ContractsRelayIngressErrorV1> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)?;
    if digest == ZERO_DIGEST {
        return Err(ContractsRelayIngressErrorV1::InvalidReceipt);
    }
    Ok(digest)
}

fn os_random_32() -> Result<[u8; 32], getrandom::Error> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(bytes)
}

fn first_delivery_receipt_from_prepared_readback(
    outcome: DurableTransportOutcomeV1,
) -> Result<DurableTransportReceiptV1, SessionStoreError> {
    match outcome {
        DurableTransportOutcomeV1::Accepted(receipt) if receipt.duplicate => Ok(receipt),
        DurableTransportOutcomeV1::Accepted(_)
        | DurableTransportOutcomeV1::EquivocationPersisted => Err(SessionStoreError::Quarantined),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_anchor_claim_pre_signature_ingress_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
        ) -> PreparedContractsIngressV1 =
            PreparedContractsIngressV1::post_anchor_claim_pre_signature;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_post_anchor_claim_pre_signature;
    }

    #[test]
    fn post_anchor_claim_pre_signature_v2_ingress_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
        ) -> PreparedContractsIngressV1 =
            PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_post_anchor_claim_pre_signature_v2;
    }

    #[test]
    fn operational_final_refund_ingress_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedOperationalFinalRefundTransportAuthorityV1,
        ) -> PreparedContractsIngressV1 = PreparedContractsIngressV1::operational_final_refund;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedOperationalFinalRefundTransportAuthorityV1,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_operational_final_refund;
    }

    /// The FinalClaim ingress variant must name the *ingress* authority on
    /// both sides of the linear surface.
    ///
    /// This is the discriminating half of the test: the emitter-side
    /// `PreparedOperationalFinalClaimTransportAuthorityV2` is a distinct type,
    /// so if the variant were ever retyped to carry it, these two coercions
    /// stop compiling.  A variant carrying the emitter capability would
    /// otherwise build cleanly and refuse every real `0x12` at run time.
    #[test]
    fn final_claim_ingress_v2_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedOperationalFinalClaimIngressAuthorityV2,
        ) -> PreparedContractsIngressV1 = PreparedContractsIngressV1::final_claim_ingress_v2;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedOperationalFinalClaimIngressAuthorityV2,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_final_claim_ingress_v2;
    }

    #[test]
    fn prepared_m8_readback_must_be_the_exact_durable_duplicate() {
        let duplicate = DurableTransportReceiptV1 {
            message_digest: [0x11; 32],
            transcript_hash: [0x22; 32],
            sequence: 7,
            message_type: 0x11,
            duplicate: true,
        };
        assert_eq!(
            first_delivery_receipt_from_prepared_readback(DurableTransportOutcomeV1::Accepted(
                duplicate
            ))
            .expect("prepared Store transition must be readable as an exact duplicate"),
            duplicate
        );

        let impossible_first = DurableTransportReceiptV1 {
            duplicate: false,
            ..duplicate
        };
        assert!(matches!(
            first_delivery_receipt_from_prepared_readback(DurableTransportOutcomeV1::Accepted(
                impossible_first
            )),
            Err(SessionStoreError::Quarantined)
        ));
        assert!(matches!(
            first_delivery_receipt_from_prepared_readback(
                DurableTransportOutcomeV1::EquivocationPersisted
            ),
            Err(SessionStoreError::Quarantined)
        ));
    }
}

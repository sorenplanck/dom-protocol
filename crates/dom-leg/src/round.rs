//! REAL 2-of-2 round of the DOM leg over the pinned `dom-adaptor`.
//!
//! DOM Interop Foundation Document v0.2 §2.2, §2.2.6 and §4.4.
//!
//! ## Why the round is driven by the public API, not by the pin's driver
//!
//! The crate's own driver (`VaultBackedSignerV1`) **is not usable from the
//! outside**: `ValidatedSigningRoundStateV1::from_accepted_session` and
//! `::from_bootstrap` are `#[cfg(any(test, fuzzing))] pub(crate)`
//! (`signing_round.rs:523` and `:568`), and the crate itself freezes that
//! with a `compile_fail` doctest in `lib.rs:70-76`. This leg therefore drives
//! commitment → reveal → partial through the public API, which is sufficient,
//! and never reimplements any primitive, challenge, or verifier (I15):
//!
//! | Step | Authority used |
//! |---|---|
//! | chain id | `TrustedChainIdV1::from_authenticated_genesis` |
//! | session id | `generate_session_id_v1` + the caller's `SessionIdRegistryV1` |
//! | template | `canonical_template_v1` over `dom_consensus::Transaction` |
//! | transcript | `initial_transcript_hash_v1` + `advance_transcript_hash_v1` |
//! | context | `SessionContextV1::from_trusted_chain` |
//! | share PoK | `prove_share_knowledge_v1` / `verify_share_knowledge_v1` |
//! | commitment | `nonce_commitment_hash_v1` |
//! | binding | `binding_factor_v1` |
//! | aggregation | `aggregate_public_nonces_v1` / `aggregate_partial_signatures_v1` |
//! | partial | `secret_scalar_mul_add_assign` + `PartialSignatureV1::verify_bound` |
//! | Funding/Refund | `finalize_plain_signature_v1` (reaches the real verifier) |
//! | ClaimAdaptor | `AdaptorPreSignatureV1::{verify,adapt,extract}` |
//!
//! ## Known blockers in the pin
//!
//! - `SigningShareV1::as_be_bytes` is `pub(crate)` (`signing_share.rs:44`),
//!   and the pin's secret-nonce derivation is `compile_fail` for external
//!   consumers (`lib.rs:13-22`). The leg therefore has to keep the share
//!   bytes in [`LocalSigningShare`] and generate the two nonces locally.
//! - `AdaptorSecret` (`adaptor.rs:43`) and `dom_scriptless_primitives::SecretScalar` do not
//!   export bytes. An extracted `t` can only be compared through the public
//!   POINT — see [`ExtractedAdaptorSecret`].

use core::fmt;

use counterparty_api::{AdaptorPointBytes, RevealedSecretBytes};
use dom_adaptor::{
    advance_transcript_hash_v1, aggregate_partial_signatures_v1, aggregate_public_nonces_v1,
    binding_factor_v1, canonical_template_v1, finalize_plain_signature_v1, generate_session_id_v1,
    initial_transcript_hash_v1, nonce_commitment_hash_v1, prove_share_knowledge_v1,
    session_message_digest_v1, verify_share_knowledge_v1, AdaptorError, AdaptorPreSignatureV1,
    AdaptorSecret, BindingContextV1, BindingFactorV1, ContractKindV1, DirectionV1,
    NonceCommitmentV1, NonceRevealV1, PartialSignatureV1, ParticipantIdentityV1,
    ParticipantPublicNoncesV1, ParticipantRosterV1, PurposeV1, SessionContextInputsV1,
    SessionContextV1, SessionIdRegistryV1, SharePoPStatementV1, ShareProofV1, SigningPhaseV1,
    SigningShareV1, TrustedChainIdV1,
};
use dom_consensus::Transaction;
use dom_crypto::{
    schnorr_add_public_keys, schnorr_challenge, PartialSig, PublicKey, SchnorrSignature,
};
use dom_scriptless_primitives::{
    scalar_bytes_are_canonical, secret_scalar_mul_add_assign, secret_scalar_public_key,
};
use dom_serialization::DomDeserialize;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{LegError, PreSignatureBytes};

/// Canonical encoded length of a DOM Schnorr signature: `R` compressed (33)
/// followed by `s` (32). Declared here because the pinned crate does not
/// export it, and the wire boundary must cap the length before parsing (I14).
const SCHNORR_SIGNATURE_LEN: usize = 65;

/// Scalar canonicity: `0 < t < n`.
///
/// Same name and signature as the backend-less build's helper, so downstream
/// code has ONE predicate in both configurations rather than a function that
/// vanishes when the feature is switched on. This is not a second
/// implementation: it delegates to `dom_scriptless_primitives::scalar_bytes_are_canonical`,
/// the pin's own predicate, so the authority decides canonicity here as
/// everywhere else (I15).
pub fn scalar_is_canonical(scalar: &[u8; 32]) -> bool {
    // `allow_zero = false`: an adaptor secret of zero is not a secret, and the
    // backend-less helper rejects it too. The two builds must answer alike.
    scalar_bytes_are_canonical(scalar, false)
}

/// Local signing share of the DOM leg.
///
/// Holds the opaque `SigningShareV1` (required by `SessionContextV1` and by
/// the PoK) and, separately, the canonical bytes — because
/// `SigningShareV1::as_be_bytes` is `pub(crate)` in the pin and without them
/// `secret_scalar_mul_add_assign` cannot produce the partial. Implements no
/// `Clone`, no useful `Debug`, no `Display`, and no serialization; the bytes
/// are zeroed on drop.
pub struct LocalSigningShare {
    share: SigningShareV1,
    be_bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for LocalSigningShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalSigningShare(<redacted>)")
    }
}

impl LocalSigningShare {
    /// Validates the scalar through the real parser and retains the canonical copy.
    pub fn from_be_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, LegError> {
        let share = SigningShareV1::from_be_bytes(*bytes)?;
        Ok(Self {
            share,
            be_bytes: bytes,
        })
    }

    /// Canonical public key of the share.
    pub fn public_key(&self) -> &PublicKey {
        self.share.public_key()
    }

    fn share(&self) -> &SigningShareV1 {
        &self.share
    }

    fn be_bytes(&self) -> &[u8; 32] {
        &self.be_bytes
    }
}

/// Opening parameters for a real DOM leg session.
///
/// No derived field (session id, template hash, transcript) enters through
/// here: all of them are produced by the pin's functions inside
/// [`SessionBindings::open`] (§4.4).
pub struct SessionOpenRequest<'a> {
    /// Chain id coming from the authenticated chain adapter.
    pub chain_id: TrustedChainIdV1,
    /// Closed contract-kind registry entry.
    pub contract_kind: ContractKindV1,
    /// Roster validated and ordered by participant id. Every entry is
    /// rederived against `chain_id` before durable session registration.
    pub roster: ParticipantRosterV1,
    /// Participant id of the initiator (who generates the session id).
    pub initiator_participant_id: [u8; 32],
    /// Frozen purpose of the phase.
    pub purpose: PurposeV1,
    /// Adaptor point `T`; mandatory in `ClaimAdaptor`, forbidden elsewhere.
    pub adaptor_point: Option<PublicKey>,
    /// DOM transaction that defines the canonical template.
    pub template_tx: &'a dom_consensus::Transaction,
    /// DOM kernel digest signed in this phase.
    pub kernel_message_digest: [u8; 32],
    /// Direction of the participant emitting the opening message.
    pub opening_direction: DirectionV1,
    /// Subphase accepted by the opening message.
    pub opening_phase: SigningPhaseV1,
    /// Non-zero digest of the canonical terms (binds the share PoK).
    pub terms_hash: [u8; 32],
    /// Non-zero digest of the recovery binding (binds the share PoK).
    pub recovery_binding_hash: [u8; 32],
}

/// Retained facts of one already-completed round, supplied by a caller that
/// holds them, for [`SessionBindings::open_with_caller_supplied_identity_v1`].
///
/// Read that constructor's documentation before filling this in: the session
/// identity here is **supplied**, not proved, and what makes supplying it safe
/// is where the values came from, not this type.
pub struct CallerSuppliedIdentitySessionRequestV1<'a> {
    /// Chain id coming from the authenticated chain adapter.
    pub chain_id: TrustedChainIdV1,
    /// Closed contract-kind registry entry.
    pub contract_kind: ContractKindV1,
    /// Roster the retained round was bound to. Rederived against `chain_id`.
    pub roster: ParticipantRosterV1,
    /// Frozen purpose of the phase.
    pub purpose: PurposeV1,
    /// Adaptor point `T`; mandatory in `ClaimAdaptor`, forbidden elsewhere.
    pub adaptor_point: Option<PublicKey>,
    /// Exact canonical DOM transaction bytes of the frozen template.
    ///
    /// Bytes rather than a decoded transaction, because that is the shape a
    /// retained record has: the decode belongs in the crate that owns the
    /// consensus pin, not spread across every consumer that holds retained
    /// facts. A caller hands over what it stored.
    pub canonical_transaction_bytes: &'a [u8],
    /// DOM kernel digest signed in this phase.
    pub kernel_message_digest: [u8; 32],
    /// Non-zero digest of the canonical terms (binds the share PoK).
    pub terms_hash: [u8; 32],
    /// Non-zero digest of the recovery binding (binds the share PoK).
    pub recovery_binding_hash: [u8; 32],
    /// Session identity of the retained round. **Supplied, never generated.**
    pub session_id: [u8; 32],
    /// Initial transcript the retained record carries.
    ///
    /// The constructor recomputes the initial transcript from `chain_id`,
    /// `session_id`, `contract_kind` and the rederived roster and requires
    /// equality with this value. That is the whole of the identity check.
    pub expected_initial_transcript_hash: [u8; 32],
    /// Accepted transcript the round had reached.
    ///
    /// For a Claim adaptor round this is the **reveal** transcript, because
    /// that is the one the retained pre-signature is bound to and the one
    /// [`DomLegSession::pre_signature_from_wire`] compares against.
    pub transcript_hash: [u8; 32],
}

/// Immutable bindings of a DOM leg session.
///
/// Built exactly once by the pin's functions. No field is accepted from a
/// network message without being recomputed here (§4.4).
pub struct SessionBindings {
    chain_id: TrustedChainIdV1,
    contract_kind: ContractKindV1,
    session_id: [u8; 32],
    roster: ParticipantRosterV1,
    signing_keys: Vec<PublicKey>,
    template_bytes: Vec<u8>,
    template_hash: [u8; 32],
    initial_transcript_hash: [u8; 32],
    transcript_hash: [u8; 32],
    purpose: PurposeV1,
    adaptor_point: Option<PublicKey>,
    kernel_message_digest: [u8; 32],
    terms_hash: [u8; 32],
    recovery_binding_hash: [u8; 32],
}

impl fmt::Debug for SessionBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionBindings")
            .field("session_id", &self.session_id)
            .field("purpose", &self.purpose)
            .field("template_hash", &self.template_hash)
            .field("transcript_hash", &self.transcript_hash)
            .finish_non_exhaustive()
    }
}

impl SessionBindings {
    /// Opens the session after rederiving the complete roster against the
    /// trusted chain, then creates the durable session id, canonical template,
    /// and transcript.
    ///
    /// `registry` is the caller's DURABLE `SessionIdRegistryV1` — the
    /// `dom-vault` owns it; this leg never implements one (§4.7).
    pub fn open<R: SessionIdRegistryV1>(
        request: SessionOpenRequest<'_>,
        registry: &mut R,
    ) -> Result<Self, LegError> {
        let rebound_entries = request
            .roster
            .entries()
            .iter()
            .map(|entry| {
                ParticipantIdentityV1::new(
                    &request.chain_id,
                    entry.identity_public_key().clone(),
                    entry.signing_public_key().clone(),
                    entry.direction(),
                )
                .map_err(|_| LegError::RosterMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rebound_roster =
            ParticipantRosterV1::new(rebound_entries).map_err(|_| LegError::RosterMismatch)?;
        if rebound_roster != request.roster {
            return Err(LegError::RosterMismatch);
        }
        if !rebound_roster
            .entries()
            .iter()
            .any(|entry| entry.participant_id() == &request.initiator_participant_id)
        {
            return Err(LegError::RosterMismatch);
        }

        // Sponsor is closed off here, by the pin's own registry.
        let purpose = request.purpose.require_strict_phase1()?;

        // The grammar `SessionOpenRequest::adaptor_point` states — mandatory in
        // `ClaimAdaptor`, forbidden elsewhere — enforced instead of assumed.
        // The first half was already refused, but late, at
        // `build_claim_pre_signature`. The second half was refused nowhere, and
        // its absence is not cosmetic: `BoundRound::bind` folds the point into
        // the aggregate nonce whenever it is `Some`, without consulting the
        // purpose, so a `Refund` or `Funding` session opened with a point
        // silently signs against a displaced `R̂` and nothing downstream
        // notices. Strictly restrictive: no request that was accepted before is
        // refused now unless it carried that contradiction.
        match (purpose, request.adaptor_point.as_ref()) {
            (PurposeV1::ClaimAdaptor, None) => return Err(LegError::AdaptorPointMissing),
            (PurposeV1::ClaimAdaptor, Some(_)) => {}
            (_, Some(_)) => return Err(LegError::PurposeMismatch),
            (_, None) => {}
        }

        let session_id = generate_session_id_v1(
            &request.chain_id,
            &request.initiator_participant_id,
            request.contract_kind,
            registry,
        )?;

        let (template_bytes, template_hash) = canonical_template_v1(request.template_tx)?;

        let initial_transcript_hash = initial_transcript_hash_v1(
            &request.chain_id,
            &session_id,
            request.contract_kind,
            &rebound_roster,
        );
        let opening_digest = session_message_digest_v1(&template_bytes);
        let transcript_hash = advance_transcript_hash_v1(
            &initial_transcript_hash,
            &opening_digest,
            request.opening_direction,
            request.opening_phase,
        );

        let mut signing_keys: Vec<PublicKey> = rebound_roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(PublicKey::to_compressed_bytes);

        Ok(Self {
            chain_id: request.chain_id,
            contract_kind: request.contract_kind,
            session_id,
            roster: rebound_roster,
            signing_keys,
            template_bytes,
            template_hash,
            initial_transcript_hash,
            transcript_hash,
            purpose,
            adaptor_point: request.adaptor_point,
            kernel_message_digest: request.kernel_message_digest,
            terms_hash: request.terms_hash,
            recovery_binding_hash: request.recovery_binding_hash,
        })
    }

    /// Reassembles the bindings of an already-completed round from retained
    /// facts, taking the session identity from the caller instead of drawing
    /// one.
    ///
    /// **What the tie-back proves, and what it does not.** The `session_id`
    /// this accepts is checked in exactly one way: the initial transcript is
    /// recomputed from the chain id, that `session_id`, the contract kind and
    /// the rederived roster, and must equal the
    /// `expected_initial_transcript_hash` the caller supplied. That proves the
    /// supplied `session_id` is the one the supplied initial transcript
    /// commits to — [`initial_transcript_hash_v1`] hashes the session id into
    /// its body — and it proves **nothing about where either value came
    /// from**. In particular it does **not** prove the identity was ever
    /// drawn: anyone presenting a mutually consistent pair passes, and
    /// fabricating such a pair is one call to that same function. **The
    /// security is in the provenance of the pair**, which has to come from the
    /// durable, authenticated record of the Contracts Store and from nowhere
    /// else. A caller that reads the pair from anywhere a peer can influence
    /// has authenticated nothing here, whatever this constructor returns.
    ///
    /// Four things are rederived here, and they are the same four
    /// [`Self::open`] rederives, byte for byte: the roster is rebuilt entry by
    /// entry against the trusted chain and required to equal the one supplied,
    /// the purpose must be a strict phase-1 purpose, the canonical template and
    /// its hash are recomputed from the transaction, and the signing keys are
    /// collected and ordered. They are written out again here rather than
    /// shared with `open` through a helper, deliberately: sharing would mean
    /// editing the live path to make room for this one, and the two are allowed
    /// to diverge later without either silently dragging the other.
    ///
    /// Four other fields cross this constructor **textually** — neither
    /// rederived nor tied to anything: `kernel_message_digest`, `terms_hash`,
    /// `recovery_binding_hash`, and the point inside `adaptor_point`. `open`
    /// carries them the same way, so this is parity and not a weakening, but
    /// the sentence above says *rederived* and it means only those four, not
    /// these.
    ///
    /// The adaptor-point grammar **is** enforced here, unlike in `open`: a
    /// `ClaimAdaptor` request without a point is
    /// [`LegError::AdaptorPointMissing`], and any other purpose carrying one is
    /// [`LegError::PurposeMismatch`]. The field documentation has always said
    /// "mandatory in `ClaimAdaptor`, forbidden elsewhere" and nothing enforced
    /// the second half; a point accepted on a non-adaptor purpose silently
    /// displaces the aggregate nonce, because [`BoundRound::bind`] adds it
    /// whenever it is `Some` without consulting the purpose. This constructor
    /// is filled in by a consumer reading retained facts rather than by a live
    /// protocol flow, so the grammar is checked where the values enter.
    ///
    /// Three structural refusals precede all of it: a zero `session_id`, a zero
    /// `expected_initial_transcript_hash` or a zero `transcript_hash` is
    /// [`LegError::MalformedRetainedFacts`]. Being exact about what those are
    /// worth: against a caller that fabricates its inputs they are worth
    /// **nothing**, because whoever chooses an identity chooses a non-zero one
    /// at the same cost. They catch a field a caller failed to populate — an
    /// accident, not an attack — and all three have that property equally,
    /// which is why all three are guarded and not one of them.
    ///
    /// What it does not do, by contrast with `open`: it takes no
    /// [`SessionIdRegistryV1`] and reaches no source of randomness. It cannot
    /// register a new session and cannot mint an identity.
    ///
    /// The accepted transcript is taken, not advanced. Advancing it would
    /// require the direction and subphase of the opening message, which no
    /// durable record retains; taking it is also what a consumer needs, since
    /// the value that matters downstream is the reveal transcript the retained
    /// pre-signature is bound to.
    pub fn open_with_caller_supplied_identity_v1(
        request: CallerSuppliedIdentitySessionRequestV1<'_>,
    ) -> Result<Self, LegError> {
        // Accident detectors, symmetric on purpose: none of the three can be a
        // legitimate value, none of the three survives a caller that chooses
        // its own inputs, and singling one out would suggest the other two were
        // somehow safer.
        if request.session_id == [0; 32]
            || request.expected_initial_transcript_hash == [0; 32]
            || request.transcript_hash == [0; 32]
        {
            return Err(LegError::MalformedRetainedFacts);
        }

        let rebound_entries = request
            .roster
            .entries()
            .iter()
            .map(|entry| {
                ParticipantIdentityV1::new(
                    &request.chain_id,
                    entry.identity_public_key().clone(),
                    entry.signing_public_key().clone(),
                    entry.direction(),
                )
                .map_err(|_| LegError::RosterMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rebound_roster =
            ParticipantRosterV1::new(rebound_entries).map_err(|_| LegError::RosterMismatch)?;
        if rebound_roster != request.roster {
            return Err(LegError::RosterMismatch);
        }

        let purpose = request.purpose.require_strict_phase1()?;

        // The grammar the field documentation states, enforced where the value
        // enters. `BoundRound::bind` consults only whether the point is
        // present, so a point admitted on a non-adaptor purpose would displace
        // the aggregate nonce with nothing to catch it downstream.
        match (purpose, request.adaptor_point.as_ref()) {
            (PurposeV1::ClaimAdaptor, None) => return Err(LegError::AdaptorPointMissing),
            (PurposeV1::ClaimAdaptor, Some(_)) => {}
            (_, Some(_)) => return Err(LegError::PurposeMismatch),
            (_, None) => {}
        }

        // The decode is here, in the crate that owns the consensus pin. It is
        // not followed by a re-encode: the retained bytes a caller hands over
        // are already the round-trip-checked encoding, and re-checking that
        // here would compare this crate's encoder against itself rather than
        // against anything the caller supplied.
        let template_tx = Transaction::from_bytes(request.canonical_transaction_bytes)
            .map_err(|_| LegError::MalformedRetainedFacts)?;
        let (template_bytes, template_hash) = canonical_template_v1(&template_tx)?;

        // The tie-back. The identity is accepted only because everything else
        // reproduces the transcript that commits it.
        let initial_transcript_hash = initial_transcript_hash_v1(
            &request.chain_id,
            &request.session_id,
            request.contract_kind,
            &rebound_roster,
        );
        if initial_transcript_hash != request.expected_initial_transcript_hash {
            return Err(LegError::TranscriptMismatch);
        }

        let mut signing_keys: Vec<PublicKey> = rebound_roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(PublicKey::to_compressed_bytes);

        Ok(Self {
            chain_id: request.chain_id,
            contract_kind: request.contract_kind,
            session_id: request.session_id,
            roster: rebound_roster,
            signing_keys,
            template_bytes,
            template_hash,
            initial_transcript_hash,
            transcript_hash: request.transcript_hash,
            purpose,
            adaptor_point: request.adaptor_point,
            kernel_message_digest: request.kernel_message_digest,
            terms_hash: request.terms_hash,
            recovery_binding_hash: request.recovery_binding_hash,
        })
    }

    /// Trusted chain id.
    pub fn chain_id(&self) -> &TrustedChainIdV1 {
        &self.chain_id
    }
    /// Contract kind of the session.
    pub fn contract_kind(&self) -> ContractKindV1 {
        self.contract_kind
    }
    /// Durable session id.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Roster ordered by participant id.
    pub fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }
    /// Canonical signing roster (strictly increasing SEC1).
    pub fn signing_keys(&self) -> &[PublicKey] {
        &self.signing_keys
    }
    /// Exact bytes of the canonical template.
    pub fn template_bytes(&self) -> &[u8] {
        &self.template_bytes
    }
    /// Hash of the canonical template.
    pub fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }
    /// Initial transcript, before the first `advance`.
    pub fn initial_transcript_hash(&self) -> &[u8; 32] {
        &self.initial_transcript_hash
    }
    /// Frozen transcript of this phase.
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }
    /// Frozen purpose.
    pub fn purpose(&self) -> PurposeV1 {
        self.purpose
    }
    /// The session's adaptor point, when there is one.
    pub fn adaptor_point(&self) -> Option<&PublicKey> {
        self.adaptor_point.as_ref()
    }
    /// Signed kernel digest.
    pub fn kernel_message_digest(&self) -> &[u8; 32] {
        &self.kernel_message_digest
    }

    fn participant_ids(&self) -> Vec<[u8; 32]> {
        self.roster
            .entries()
            .iter()
            .map(|entry| *entry.participant_id())
            .collect()
    }

    fn roster_index_of(&self, participant_id: &[u8; 32]) -> Result<u16, LegError> {
        let position = self
            .roster
            .entries()
            .iter()
            .position(|entry| entry.participant_id() == participant_id)
            .ok_or(LegError::RosterMismatch)?;
        u16::try_from(position).map_err(|_| LegError::IndexOutOfRange)
    }

    /// Recomputes a counterparty's nonce commitment and checks that the
    /// received reveal actually opens it. Fails closed on any divergence.
    pub fn check_reveal_opens_commitment(
        &self,
        participant_id: &[u8; 32],
        commitment: &NonceCommitmentV1,
        reveal: &NonceRevealV1,
    ) -> Result<(), LegError> {
        if commitment.purpose() != self.purpose || reveal.purpose() != self.purpose {
            return Err(LegError::PurposeMismatch);
        }
        if commitment.participant_index() != reveal.participant_index() {
            return Err(LegError::CommitmentMismatch);
        }
        let recomputed = nonce_commitment_hash_v1(
            self.chain_id.as_bytes(),
            &self.session_id,
            participant_id,
            self.purpose,
            &self.template_hash,
            reveal.first(),
            reveal.second(),
            self.adaptor_point.as_ref(),
        )?;
        if recomputed.as_bytes() != commitment.nonce_reveal_hash() {
            return Err(LegError::CommitmentMismatch);
        }
        Ok(())
    }
}

/// Aggregate signing key of the session.
///
/// §2.2.6, "without exception": this value has exactly two constructors and
/// **both** verify share proofs of knowledge BEFORE adding any public point.
/// [`LegParticipant::accept_share_proofs`] is the signer's, and verifies ALL
/// counterparties, skipping only the local participant, who does not prove
/// knowledge to itself. [`AggregateSigningKey::from_verified_share_proofs_v1`]
/// is the shareless verifier's, and has no local participant to skip, so it
/// verifies **every** roster entry. There is no constructor that skips the
/// step, and every nonce aggregation and every finalization requires this
/// value as proof that the step happened.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AggregateSigningKey(PublicKey);

impl AggregateSigningKey {
    /// Aggregate point `X`.
    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }

    /// Aggregates after verifying the share proof of **every** roster entry.
    ///
    /// The sibling of [`LegParticipant::accept_share_proofs`], for a caller
    /// that holds no signing share. It exists because a consumer reassembling a
    /// completed round — to verify a claim, never to sign — needs the aggregate
    /// key and nothing else, and the participant-shaped route would make it
    /// carry a secret it never uses: `accept_share_proofs` reads only
    /// `self.roster_index` and builds statements out of `bindings`, so the
    /// share it demands does no arithmetic on that path. Demanding a secret in
    /// order to perform a public computation is an argument too many on a
    /// security path, and this removes it.
    ///
    /// §2.2.6 is not relaxed but tightened. `accept_share_proofs` skips the
    /// local participant's own index, because a signer does not prove
    /// knowledge to itself; this has no local index to skip, so it requires and
    /// verifies a proof for **every** entry of the roster, the local one
    /// included. No public point is added until all of them have verified.
    ///
    /// **What it does not verify, and cannot.** That the caller holds the
    /// signing share of any of these participants. It has no share and asks for
    /// none. It establishes that a proof exists for each roster entry, that
    /// each proof's statement is byte-identical to the statement this session's
    /// bindings imply for that entry, and that each proof verifies against it —
    /// and nothing beyond that. A caller is not authenticated as a participant
    /// by calling this, and a value returned by it says nothing about who asked.
    pub fn from_verified_share_proofs_v1(
        bindings: &SessionBindings,
        proofs: &[(SharePoPStatementV1, ShareProofV1)],
    ) -> Result<Self, LegError> {
        let participant_ids = bindings.participant_ids();
        for (position, entry) in bindings.roster.entries().iter().enumerate() {
            let index = u16::try_from(position).map_err(|_| LegError::IndexOutOfRange)?;
            let (received, proof) = proofs
                .iter()
                .find(|(statement, _)| statement.participant_index() == index)
                .ok_or(LegError::MissingShareProof)?;
            let expected = SharePoPStatementV1::new(
                &bindings.chain_id,
                bindings.session_id,
                &participant_ids,
                entry.direction(),
                index,
                entry.signing_public_key().clone(),
                bindings.terms_hash,
                bindings.recovery_binding_hash,
            )?;
            if received.to_bytes() != expected.to_bytes() {
                return Err(LegError::ShareStatementMismatch);
            }
            if !verify_share_knowledge_v1(&expected, proof)? {
                return Err(LegError::ShareProofRejected);
            }
        }
        // Only now: no public-point addition happened before this.
        let aggregate =
            schnorr_add_public_keys(&bindings.signing_keys).map_err(AdaptorError::from)?;
        Ok(Self(aggregate))
    }
}

/// Secret nonces of a round, single-use.
///
/// No copy, no `Clone`, no useful `Debug`; zeroed on drop.
/// [`LegParticipant::sign_partial`] consumes the value.
pub struct RoundNonces {
    first_secret: Zeroizing<[u8; 32]>,
    second_secret: Zeroizing<[u8; 32]>,
    first: PublicKey,
    second: PublicKey,
}

impl fmt::Debug for RoundNonces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RoundNonces(<redacted>)")
    }
}

impl RoundNonces {
    fn generate() -> Result<Self, LegError> {
        let first_secret = random_canonical_scalar()?;
        let second_secret = random_canonical_scalar()?;
        if first_secret[..] == second_secret[..] {
            return Err(LegError::Randomness);
        }
        let first = secret_scalar_public_key(&first_secret).map_err(AdaptorError::from)?;
        let second = secret_scalar_public_key(&second_secret).map_err(AdaptorError::from)?;
        Ok(Self {
            first_secret,
            second_secret,
            first,
            second,
        })
    }

    /// First public nonce `R_i1`.
    pub fn first(&self) -> &PublicKey {
        &self.first
    }
    /// Second public nonce `R_i2`.
    pub fn second(&self) -> &PublicKey {
        &self.second
    }
}

fn random_canonical_scalar() -> Result<Zeroizing<[u8; 32]>, LegError> {
    for _ in 0..64u8 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut bytes[..])
            .map_err(|_| LegError::Randomness)?;
        if scalar_bytes_are_canonical(&bytes, false) {
            return Ok(bytes);
        }
    }
    Err(LegError::Randomness)
}

/// Local participant of the 2-of-2 round.
pub struct LegParticipant {
    share: LocalSigningShare,
    identity: ParticipantIdentityV1,
    roster_index: u16,
    signing_index: u16,
    context: SessionContextV1,
}

impl fmt::Debug for LegParticipant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegParticipant")
            .field("roster_index", &self.roster_index)
            .field("signing_index", &self.signing_index)
            .finish_non_exhaustive()
    }
}

impl LegParticipant {
    /// Joins the session and builds the REAL `SessionContextV1`.
    ///
    /// `SessionContextV1::from_trusted_chain` revalidates the chain id, the
    /// roster ordering, uniqueness, the local index, and the adaptor-point
    /// grammar.
    pub fn join(
        bindings: &SessionBindings,
        share: LocalSigningShare,
        identity: ParticipantIdentityV1,
    ) -> Result<Self, LegError> {
        if identity.signing_public_key() != share.public_key() {
            return Err(LegError::RosterMismatch);
        }
        let roster_index = bindings.roster_index_of(identity.participant_id())?;
        let signing_index = bindings.roster.signing_index(identity.participant_id())?;

        let context = SessionContextV1::from_trusted_chain(
            SessionContextInputsV1 {
                chain_id: *bindings.chain_id.as_bytes(),
                session_id: bindings.session_id,
                purpose: bindings.purpose,
                direction: identity.direction(),
                signing_phase: SigningPhaseV1::SigNonceCommit,
                template_hash: bindings.template_hash,
                message_digest: bindings.kernel_message_digest,
                transcript_hash: bindings.transcript_hash,
                retry_counter: 0,
                participant_public_keys: bindings.signing_keys.clone(),
                participant_index: signing_index,
                adaptor_point: bindings.adaptor_point.clone(),
            },
            &bindings.chain_id,
            share.share(),
        )?;

        Ok(Self {
            share,
            identity,
            roster_index,
            signing_index,
            context,
        })
    }

    /// Canonical identity of this participant.
    pub fn identity(&self) -> &ParticipantIdentityV1 {
        &self.identity
    }
    /// Index in the roster ordered by participant id.
    pub fn roster_index(&self) -> u16 {
        self.roster_index
    }
    /// Index in the canonical signing roster.
    pub fn signing_index(&self) -> u16 {
        self.signing_index
    }
    /// Validated session context.
    pub fn context(&self) -> &SessionContextV1 {
        &self.context
    }

    fn statement_for(
        &self,
        bindings: &SessionBindings,
        participant_index: u16,
        role: DirectionV1,
        share_point: PublicKey,
    ) -> Result<SharePoPStatementV1, LegError> {
        SharePoPStatementV1::new(
            &bindings.chain_id,
            bindings.session_id,
            &bindings.participant_ids(),
            role,
            participant_index,
            share_point,
            bindings.terms_hash,
            bindings.recovery_binding_hash,
        )
        .map_err(Into::into)
    }

    /// Proves knowledge of its own share (§2.2.6).
    pub fn prove_share(
        &self,
        bindings: &SessionBindings,
    ) -> Result<(SharePoPStatementV1, ShareProofV1), LegError> {
        let statement = self.statement_for(
            bindings,
            self.roster_index,
            self.identity.direction(),
            self.share.public_key().clone(),
        )?;
        let proof = prove_share_knowledge_v1(&statement, self.share.share())?;
        Ok((statement, proof))
    }

    /// Verifies the share PoK of ALL counterparties and only then aggregates.
    ///
    /// §2.2.6 "without exception": public-point aggregation is unreachable
    /// without going through here, because [`AggregateSigningKey`] has no
    /// other constructor. The received statement is compared byte for byte
    /// with this session's canonical statement, which binds the chain id,
    /// session id, roster, role, index, terms, and recovery binding.
    pub fn accept_share_proofs(
        &self,
        bindings: &SessionBindings,
        proofs: &[(SharePoPStatementV1, ShareProofV1)],
    ) -> Result<AggregateSigningKey, LegError> {
        for (position, entry) in bindings.roster.entries().iter().enumerate() {
            let index = u16::try_from(position).map_err(|_| LegError::IndexOutOfRange)?;
            if index == self.roster_index {
                continue;
            }
            let (received, proof) = proofs
                .iter()
                .find(|(statement, _)| statement.participant_index() == index)
                .ok_or(LegError::MissingShareProof)?;
            let expected = self.statement_for(
                bindings,
                index,
                entry.direction(),
                entry.signing_public_key().clone(),
            )?;
            if received.to_bytes() != expected.to_bytes() {
                return Err(LegError::ShareStatementMismatch);
            }
            if !verify_share_knowledge_v1(&expected, proof)? {
                return Err(LegError::ShareProofRejected);
            }
        }
        // Only now: no public-point addition happened before this.
        let aggregate =
            schnorr_add_public_keys(&bindings.signing_keys).map_err(AdaptorError::from)?;
        Ok(AggregateSigningKey(aggregate))
    }

    /// Round phase 1: generates the nonces and the pin's commitment.
    pub fn begin_round(
        &self,
        bindings: &SessionBindings,
    ) -> Result<(RoundNonces, NonceCommitmentV1), LegError> {
        let nonces = RoundNonces::generate()?;
        let hash = nonce_commitment_hash_v1(
            bindings.chain_id.as_bytes(),
            &bindings.session_id,
            self.identity.participant_id(),
            bindings.purpose,
            &bindings.template_hash,
            &nonces.first,
            &nonces.second,
            bindings.adaptor_point.as_ref(),
        )?;
        let commitment =
            NonceCommitmentV1::new(bindings.purpose, self.signing_index, *hash.as_bytes());
        Ok((nonces, commitment))
    }

    /// Round phase 2: opens the commitment.
    pub fn reveal(&self, bindings: &SessionBindings, nonces: &RoundNonces) -> NonceRevealV1 {
        NonceRevealV1::new(
            bindings.purpose,
            self.signing_index,
            nonces.first.clone(),
            nonces.second.clone(),
        )
    }

    /// Phase 3: partial bound to the binding factor, self-verified by the
    /// real verifier before leaving the process.
    pub fn sign_partial(
        &self,
        bindings: &SessionBindings,
        round: &BoundRound,
        nonces: RoundNonces,
    ) -> Result<PartialSignatureV1, LegError> {
        let challenge = schnorr_challenge(
            &round.aggregate_nonce_hat.to_compressed_bytes(),
            round.aggregate_signing_key.public_key(),
            bindings.chain_id.as_bytes(),
            &bindings.kernel_message_digest,
        );

        // s_i = k_i1 + b*k_i2 + e*x_i, all arithmetic in dom-crypto.
        let mut accumulator = Zeroizing::new(*nonces.first_secret);
        secret_scalar_mul_add_assign(
            &mut accumulator,
            &nonces.second_secret,
            &round.binding_factor.to_be_bytes(),
        )
        .map_err(AdaptorError::from)?;
        secret_scalar_mul_add_assign(
            &mut accumulator,
            self.share.be_bytes(),
            challenge.as_bytes(),
        )
        .map_err(AdaptorError::from)?;

        let partial = PartialSig::from_bytes(accumulator.as_ref()).map_err(AdaptorError::from)?;
        let signature = PartialSignatureV1::new(
            bindings.purpose,
            self.signing_index,
            bindings.template_hash,
            partial,
        );

        let bound_nonce = round.bound_nonce(self.signing_index)?;
        if !signature.verify_bound(
            bindings.purpose,
            &bindings.template_hash,
            bound_nonce,
            self.share.public_key(),
            &round.aggregate_nonce_hat,
            round.aggregate_signing_key.public_key(),
            bindings.chain_id.as_bytes(),
            &bindings.kernel_message_digest,
        )? {
            return Err(LegError::PartialRejected);
        }
        Ok(signature)
    }
}

/// Public state of the round after commitment → reveal.
#[derive(Debug)]
pub struct BoundRound {
    binding_factor: BindingFactorV1,
    bound_nonces: Vec<PublicKey>,
    aggregate_nonce: PublicKey,
    aggregate_nonce_hat: PublicKey,
    aggregate_signing_key: AggregateSigningKey,
}

impl BoundRound {
    /// Derives the binding factor and the nonce aggregates.
    ///
    /// Requires [`AggregateSigningKey`], i.e., the share PoK of all
    /// counterparties has already verified (§2.2.6). In `ClaimAdaptor`,
    /// `R̂ = R + T`.
    pub fn bind(
        bindings: &SessionBindings,
        aggregate_signing_key: &AggregateSigningKey,
        reveals: &[NonceRevealV1],
    ) -> Result<Self, LegError> {
        let count = bindings.signing_keys.len();
        if reveals.len() != count {
            return Err(LegError::RosterMismatch);
        }
        let mut participants = Vec::with_capacity(count);
        for position in 0..count {
            let index = u16::try_from(position).map_err(|_| LegError::IndexOutOfRange)?;
            let reveal = reveals
                .iter()
                .find(|candidate| candidate.participant_index() == index)
                .ok_or(LegError::RosterMismatch)?;
            if reveal.purpose() != bindings.purpose {
                return Err(LegError::PurposeMismatch);
            }
            let signing_key = bindings
                .signing_keys
                .get(position)
                .ok_or(LegError::IndexOutOfRange)?
                .clone();
            participants.push(ParticipantPublicNoncesV1 {
                participant_index: index,
                signing_key,
                first_nonce: reveal.first().clone(),
                second_nonce: reveal.second().clone(),
            });
        }

        let binding_factor = binding_factor_v1(
            &BindingContextV1 {
                chain_id: *bindings.chain_id.as_bytes(),
                session_id: bindings.session_id,
                purpose: bindings.purpose,
                template_hash: bindings.template_hash,
            },
            &participants,
            bindings.adaptor_point.as_ref(),
        )?;

        let mut bound_nonces = Vec::with_capacity(count);
        for participant in &participants {
            bound_nonces.push(
                binding_factor
                    .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)?,
            );
        }

        let aggregate_nonce = aggregate_public_nonces_v1(&bound_nonces)?;
        let aggregate_nonce_hat = match bindings.adaptor_point.as_ref() {
            Some(point) => aggregate_public_nonces_v1(&[aggregate_nonce.clone(), point.clone()])?,
            None => aggregate_nonce.clone(),
        };

        Ok(Self {
            binding_factor,
            bound_nonces,
            aggregate_nonce,
            aggregate_nonce_hat,
            aggregate_signing_key: aggregate_signing_key.clone(),
        })
    }

    /// A participant's bound nonce `R_i = R_i1 + b*R_i2`.
    pub fn bound_nonce(&self, signing_index: u16) -> Result<&PublicKey, LegError> {
        self.bound_nonces
            .get(usize::from(signing_index))
            .ok_or(LegError::IndexOutOfRange)
    }

    /// Aggregate nonce `R` (without the adaptor point).
    pub fn aggregate_nonce(&self) -> &PublicKey {
        &self.aggregate_nonce
    }
    /// Aggregate nonce `R̂` used in the challenge.
    pub fn aggregate_nonce_hat(&self) -> &PublicKey {
        &self.aggregate_nonce_hat
    }
    /// Aggregate signing key, already dependent on the share PoK.
    pub fn aggregate_signing_key(&self) -> &AggregateSigningKey {
        &self.aggregate_signing_key
    }

    /// Verifies a counterparty's partial through the real verifier.
    pub fn verify_partial(
        &self,
        bindings: &SessionBindings,
        partial: &PartialSignatureV1,
        participant_key: &PublicKey,
    ) -> Result<(), LegError> {
        let bound_nonce = self.bound_nonce(partial.participant_index())?;
        if !partial.verify_bound(
            bindings.purpose,
            &bindings.template_hash,
            bound_nonce,
            participant_key,
            &self.aggregate_nonce_hat,
            self.aggregate_signing_key.public_key(),
            bindings.chain_id.as_bytes(),
            &bindings.kernel_message_digest,
        )? {
            return Err(LegError::PartialRejected);
        }
        Ok(())
    }
}

/// Finalizes `Funding` and `Refund` through the pin's plain path.
///
/// `finalize_plain_signature_v1` calls the real DOM verifier before
/// returning. Purposes outside `Funding`/`Refund` are rejected by the crate
/// itself — §4.4 forbids "fixing" that here.
pub fn finalize_plain(
    bindings: &SessionBindings,
    round: &BoundRound,
    partials: &[PartialSignatureV1],
) -> Result<SchnorrSignature, LegError> {
    finalize_plain_signature_v1(
        partials,
        bindings.purpose,
        &bindings.template_hash,
        &round.aggregate_nonce,
        round.aggregate_signing_key.public_key(),
        bindings.chain_id.as_bytes(),
        &bindings.kernel_message_digest,
    )
    .map_err(Into::into)
}

/// Builds the `ClaimAdaptor` pre-signature and verifies it against the real
/// equation.
///
/// This is the ONLY `ClaimAdaptor` path: never `finalize_plain`.
pub fn build_claim_pre_signature(
    bindings: &SessionBindings,
    round: &BoundRound,
    partials: &[PartialSignatureV1],
) -> Result<AdaptorPreSignatureV1, LegError> {
    if bindings.purpose != PurposeV1::ClaimAdaptor {
        return Err(LegError::PurposeMismatch);
    }
    let adaptor_point = bindings
        .adaptor_point
        .as_ref()
        .ok_or(LegError::AdaptorPointMissing)?;
    let scalar_hat =
        aggregate_partial_signatures_v1(partials, bindings.purpose, &bindings.template_hash)?;
    let pre = AdaptorPreSignatureV1::new(
        bindings.template_hash,
        adaptor_point.clone(),
        round.aggregate_nonce_hat.clone(),
        scalar_hat,
        bindings.transcript_hash,
    );
    if !pre.verify(
        &bindings.template_hash,
        &bindings.transcript_hash,
        round.aggregate_signing_key.public_key(),
        bindings.chain_id.as_bytes(),
        &bindings.kernel_message_digest,
    )? {
        return Err(LegError::VerificationFailed);
    }
    Ok(pre)
}

/// Adaptor secret `t` extracted from a final signature.
///
/// `AdaptorSecret` (`adaptor.rs:43`) and the `SecretScalar` it wraps still
/// expose no bytes, so this opaque type can only prove it holds the right `t`
/// by comparing the public POINT. That is the right default and it stays.
///
/// RESOLVED (D-016, pin eb6aa1c): when the other leg genuinely needs the
/// scalar — the counterparty leg is claimed with those 32 bytes — the route
/// is [`DomLegSession::extract_revealed_secret`], which goes through the
/// authority's own export and returns the value only after the full
/// verification. It does not go through this type. I1/I6 still hold here:
/// nothing is printed or serialized.
pub struct ExtractedAdaptorSecret(AdaptorSecret);

impl fmt::Debug for ExtractedAdaptorSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExtractedAdaptorSecret(<redacted>)")
    }
}

impl ExtractedAdaptorSecret {
    /// Point `T = t*G` derived from the extracted secret.
    pub fn public_point(&self) -> Result<PublicKey, LegError> {
        self.0.public_point().map_err(Into::into)
    }

    /// Same point in the counterparty boundary's opaque encoding.
    pub fn adaptor_point_bytes(&self) -> Result<AdaptorPointBytes, LegError> {
        Ok(AdaptorPointBytes(
            self.public_point()?.to_compressed_bytes(),
        ))
    }
}

/// DOM leg session for `ClaimAdaptor` `verify`/`adapt`/`extract`.
#[derive(Debug)]
pub struct DomLegSession {
    bindings: SessionBindings,
    round: BoundRound,
}

impl DomLegSession {
    /// Creates the session from the bindings and the already bound round.
    pub fn new(bindings: SessionBindings, round: BoundRound) -> Self {
        Self { bindings, round }
    }

    /// Immutable bindings.
    pub fn bindings(&self) -> &SessionBindings {
        &self.bindings
    }

    /// Bound round.
    pub fn round(&self) -> &BoundRound {
        &self.round
    }

    /// Mandatory revalidation: the pre-signature must belong to THIS
    /// session. Mirrors the checks `AdaptorPreSignatureV1::verify` performs
    /// before touching the equation, and adds the adaptor point.
    pub fn check_belongs_to_session(&self, pre: &AdaptorPreSignatureV1) -> Result<(), LegError> {
        if pre.claim_template_hash() != &self.bindings.template_hash {
            return Err(LegError::TemplateMismatch);
        }
        if pre.transcript_hash() != &self.bindings.transcript_hash {
            return Err(LegError::TranscriptMismatch);
        }
        if self.bindings.adaptor_point.as_ref() != Some(pre.adaptor_point()) {
            return Err(LegError::SecretPointMismatch);
        }
        Ok(())
    }

    /// Rehydrates the pre-signature from the transport bytes and revalidates it.
    ///
    /// §4.4: no constructor accepts a template/transcript "from outside"
    /// without revalidating against the session.
    pub fn pre_signature_from_wire(
        &self,
        wire: &PreSignatureBytes,
    ) -> Result<AdaptorPreSignatureV1, LegError> {
        if wire.claim_template_hash() != self.bindings.template_hash {
            return Err(LegError::TemplateMismatch);
        }
        if wire.transcript_hash() != self.bindings.transcript_hash {
            return Err(LegError::TranscriptMismatch);
        }
        let pre = AdaptorPreSignatureV1::from_bytes(wire.as_bytes())?;
        self.check_belongs_to_session(&pre)?;
        Ok(pre)
    }

    /// Verifies the pre-signature equation against the real DOM challenge.
    pub fn verify_pre_signature(&self, pre: &AdaptorPreSignatureV1) -> Result<(), LegError> {
        self.check_belongs_to_session(pre)?;
        if !pre.verify(
            &self.bindings.template_hash,
            &self.bindings.transcript_hash,
            self.round.aggregate_signing_key.public_key(),
            self.bindings.chain_id.as_bytes(),
            &self.bindings.kernel_message_digest,
        )? {
            return Err(LegError::VerificationFailed);
        }
        Ok(())
    }

    /// Adapts with `t` and returns the final DOM signature.
    ///
    /// Delegates entirely to `AdaptorPreSignatureV1::adapt`, which checks the
    /// point, the equation, and the final signature before returning.
    pub fn adapt_claim(
        &self,
        pre: &AdaptorPreSignatureV1,
        secret: &AdaptorSecret,
    ) -> Result<SchnorrSignature, LegError> {
        self.check_belongs_to_session(pre)?;
        pre.adapt(
            secret,
            &self.bindings.template_hash,
            &self.bindings.transcript_hash,
            self.round.aggregate_signing_key.public_key(),
            self.bindings.chain_id.as_bytes(),
            &self.bindings.kernel_message_digest,
        )
        .map_err(Into::into)
    }

    /// Extracts `t` from the observed final signature.
    pub fn extract_secret(
        &self,
        pre: &AdaptorPreSignatureV1,
        final_signature: &SchnorrSignature,
    ) -> Result<ExtractedAdaptorSecret, LegError> {
        self.check_belongs_to_session(pre)?;
        pre.extract(
            final_signature,
            &self.bindings.template_hash,
            &self.bindings.transcript_hash,
            self.round.aggregate_signing_key.public_key(),
            self.bindings.chain_id.as_bytes(),
            &self.bindings.kernel_message_digest,
        )
        .map(ExtractedAdaptorSecret)
        .map_err(Into::into)
    }

    // ---------------------------------------------------------------------
    // The wire boundary — the shape both builds of this crate share
    // ---------------------------------------------------------------------
    //
    // `disabled.rs` speaks bytes, because without the pin there are no
    // `AdaptorPreSignatureV1`/`SchnorrSignature` types to speak. The two
    // methods below give the real backend the SAME boundary, so a downstream
    // crate (the F3 harness) compiles against one API in both configurations
    // and cannot accidentally be written against a shape that only exists
    // when the feature is on.
    //
    // They add no cryptographic decision of their own: each rehydrates the
    // wire pre-signature through `pre_signature_from_wire` (which revalidates
    // it against the session) and then delegates to the typed method above.

    /// Adapts a wire pre-signature with `t`, returning the final DOM signature
    /// as canonical bytes.
    pub fn adapt_claim_from_wire(
        &self,
        wire: &PreSignatureBytes,
        secret: &Zeroizing<[u8; 32]>,
    ) -> Result<Vec<u8>, LegError> {
        let pre = self.pre_signature_from_wire(wire)?;
        // Non-canonical input is named as such rather than surfacing as a
        // generic backend refusal.
        let secret =
            AdaptorSecret::from_be_bytes(**secret).map_err(|_| LegError::NonCanonicalScalar)?;
        let signature = self.adapt_claim(&pre, &secret)?;
        Ok(signature.to_bytes().to_vec())
    }

    /// Extracts `t` from a wire pre-signature and an observed final signature,
    /// returning the revealed scalar as bytes.
    ///
    /// This is the one place the DOM leg hands a secret scalar to the other
    /// leg, and it is sound for one reason: by the time this returns, `t` is
    /// **public by construction** — it is `s - s_hat` over two signatures that
    /// are both already published, so any observer can recompute it. The
    /// counterparty leg is claimed with exactly these bytes.
    ///
    /// The authority performs the export itself
    /// (`AdaptorPreSignatureV1::extract_revealed_secret_be_bytes`, pin
    /// eb6aa1c, D-016): the adaptor arithmetic stays in one place, and the
    /// same verification the opaque path runs — the pre-signature equation,
    /// the final signature, `t*G == T` — runs here before any byte is
    /// returned.
    pub fn extract_revealed_secret(
        &self,
        wire: &PreSignatureBytes,
        final_signature: &[u8],
    ) -> Result<RevealedSecretBytes, LegError> {
        // Cap the length before parsing (I14).
        if final_signature.len() != SCHNORR_SIGNATURE_LEN {
            return Err(LegError::InvalidLength {
                expected: SCHNORR_SIGNATURE_LEN,
                got: final_signature.len(),
            });
        }
        let pre = self.pre_signature_from_wire(wire)?;
        let signature =
            SchnorrSignature::from_bytes(final_signature).map_err(AdaptorError::from)?;
        let revealed = pre
            .extract_revealed_secret_be_bytes(
                &signature,
                &self.bindings.template_hash,
                &self.bindings.transcript_hash,
                self.round.aggregate_signing_key.public_key(),
                self.bindings.chain_id.as_bytes(),
                &self.bindings.kernel_message_digest,
            )
            .map_err(LegError::from)?;
        // Constructed through `new` rather than the tuple field: stage 2 of the
        // `RevealedSecretBytes` migration closes that field and trades `Copy`
        // for `Clone + ZeroizeOnDrop`, and this is the one production site in
        // this crate that would otherwise have to change on that day.
        Ok(RevealedSecretBytes::new(*revealed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_adaptor::Result as AdaptorResult;
    use dom_consensus::Transaction;
    use dom_crypto::Hash256;
    use dom_serialization::DomSerialize;

    const GROUP_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    /// Test-only registry. The durable one belongs to `dom-vault` (D-005), never here.
    struct MemoryRegistry(Vec<[u8; 32]>);

    impl SessionIdRegistryV1 for MemoryRegistry {
        fn register_unique_session_id(&mut self, session_id: &[u8; 32]) -> AdaptorResult<bool> {
            if self.0.contains(session_id) {
                return Ok(false);
            }
            self.0.push(*session_id);
            Ok(true)
        }
    }

    fn scalar(value: u8) -> Zeroizing<[u8; 32]> {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        Zeroizing::new(bytes)
    }

    fn share(value: u8) -> LocalSigningShare {
        LocalSigningShare::from_be_bytes(scalar(value)).expect("canonical share")
    }

    fn point(value: u8) -> PublicKey {
        secret_scalar_public_key(&scalar(value)).expect("canonical point")
    }

    /// `Result::unwrap_err` requires `Debug` on the Ok type — and the pin, on
    /// purpose, does not implement `Debug` for `AdaptorPreSignatureV1`
    /// (signature material). Extracts the error without requiring that bound.
    fn expect_leg_err<T>(result: Result<T, LegError>, what: &str) -> LegError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("{what}: value was wrongly accepted"),
        }
    }

    fn chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_authenticated_genesis(0x1234_5678, &Hash256::from_bytes([0x11; 32]))
    }

    fn template_tx() -> Transaction {
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: Vec::new(),
            offset: [0x33; 32],
        }
    }

    fn roster_for(chain_id: &TrustedChainIdV1) -> ParticipantRosterV1 {
        let mut entries = vec![
            ParticipantIdentityV1::new(chain_id, point(21), point(7), DirectionV1::Initiator)
                .expect("initiator identity"),
            ParticipantIdentityV1::new(chain_id, point(22), point(9), DirectionV1::Responder)
                .expect("responder identity"),
        ];
        entries.sort_by_key(|entry| *entry.participant_id());
        ParticipantRosterV1::new(entries).expect("roster")
    }

    struct Fixture {
        bindings: SessionBindings,
        first: LegParticipant,
        second: LegParticipant,
        aggregate: AggregateSigningKey,
    }

    fn open(
        purpose: PurposeV1,
        adaptor_point: Option<PublicKey>,
        phase: SigningPhaseV1,
        offset: u8,
    ) -> SessionBindings {
        let chain_id = chain();
        let roster = roster_for(&chain_id);
        let initiator = *roster.entries()[0].participant_id();
        let mut tx = template_tx();
        tx.offset = [offset; 32];
        SessionBindings::open(
            SessionOpenRequest {
                chain_id,
                contract_kind: ContractKindV1::WitnessOrTimeout,
                roster,
                initiator_participant_id: initiator,
                purpose,
                adaptor_point,
                template_tx: &tx,
                kernel_message_digest: [0x44; 32],
                opening_direction: DirectionV1::Initiator,
                opening_phase: phase,
                terms_hash: [0x55; 32],
                recovery_binding_hash: [0x66; 32],
            },
            &mut MemoryRegistry(Vec::new()),
        )
        .expect("session opens")
    }

    fn join_all(bindings: &SessionBindings) -> (LegParticipant, LegParticipant) {
        let entries = bindings.roster().entries().to_vec();
        let mut joined = Vec::new();
        for entry in entries {
            let local = if entry.signing_public_key() == &point(7) {
                share(7)
            } else {
                share(9)
            };
            joined.push(LegParticipant::join(bindings, local, entry).expect("join"));
        }
        let second = joined.pop().expect("second participant");
        let first = joined.pop().expect("first participant");
        (first, second)
    }

    fn fixture(purpose: PurposeV1, adaptor_point: Option<PublicKey>) -> Fixture {
        fixture_with(purpose, adaptor_point, SigningPhaseV1::SigNonceCommit, 0x33)
    }

    fn fixture_with(
        purpose: PurposeV1,
        adaptor_point: Option<PublicKey>,
        phase: SigningPhaseV1,
        offset: u8,
    ) -> Fixture {
        let bindings = open(purpose, adaptor_point, phase, offset);
        let (first, second) = join_all(&bindings);
        let proof_a = first.prove_share(&bindings).expect("prove a");
        let proof_b = second.prove_share(&bindings).expect("prove b");
        let aggregate = first
            .accept_share_proofs(&bindings, &[proof_b])
            .expect("a accepts b");
        let mirrored = second
            .accept_share_proofs(&bindings, &[proof_a])
            .expect("b accepts a");
        assert_eq!(aggregate, mirrored, "both sides aggregate the same key");
        Fixture {
            bindings,
            first,
            second,
            aggregate,
        }
    }

    fn run_round(fixture: &Fixture) -> (BoundRound, Vec<PartialSignatureV1>) {
        let (nonces_a, commit_a) = fixture
            .first
            .begin_round(&fixture.bindings)
            .expect("commit a");
        let (nonces_b, commit_b) = fixture
            .second
            .begin_round(&fixture.bindings)
            .expect("commit b");
        let reveal_a = fixture.first.reveal(&fixture.bindings, &nonces_a);
        let reveal_b = fixture.second.reveal(&fixture.bindings, &nonces_b);

        fixture
            .bindings
            .check_reveal_opens_commitment(
                fixture.second.identity().participant_id(),
                &commit_b,
                &reveal_b,
            )
            .expect("b opens its commitment");
        fixture
            .bindings
            .check_reveal_opens_commitment(
                fixture.first.identity().participant_id(),
                &commit_a,
                &reveal_a,
            )
            .expect("a opens its commitment");

        let round = BoundRound::bind(
            &fixture.bindings,
            &fixture.aggregate,
            &[reveal_a.clone(), reveal_b.clone()],
        )
        .expect("bind");

        let partial_a = fixture
            .first
            .sign_partial(&fixture.bindings, &round, nonces_a)
            .expect("partial a");
        let partial_b = fixture
            .second
            .sign_partial(&fixture.bindings, &round, nonces_b)
            .expect("partial b");

        round
            .verify_partial(
                &fixture.bindings,
                &partial_b,
                fixture.second.identity().signing_public_key(),
            )
            .expect("partial b verifies");
        round
            .verify_partial(
                &fixture.bindings,
                &partial_a,
                fixture.first.identity().signing_public_key(),
            )
            .expect("partial a verifies");

        let mut partials = vec![partial_a, partial_b];
        partials.sort_by_key(PartialSignatureV1::participant_index);
        (round, partials)
    }

    /// The shareless aggregation requires, and verifies, every roster entry.
    ///
    /// Four calls over one fixture, differing in exactly one input each, with
    /// the positive first so the three refusals are attributable to what was
    /// changed and not to anything upstream of it. The positive also asserts
    /// the value equals the one the participant-shaped route produced, which is
    /// the real claim: removing the secret removed an argument, not a check.
    #[test]
    fn shareless_share_proof_aggregation_requires_every_roster_entry() {
        let local = fixture(PurposeV1::ClaimAdaptor, Some(point(31)));
        let proof_a = local
            .first
            .prove_share(&local.bindings)
            .expect("first participant proves its share");
        let proof_b = local
            .second
            .prove_share(&local.bindings)
            .expect("second participant proves its share");
        assert_eq!(proof_a.0.participant_index(), 0);
        assert_eq!(proof_b.0.participant_index(), 1);
        let both = [proof_a.clone(), proof_b.clone()];

        // Positive anchor: both proofs, and the same key the signer's route
        // reaches with a share in hand.
        let aggregate = AggregateSigningKey::from_verified_share_proofs_v1(&local.bindings, &both)
            .expect("every roster entry has a verifying proof");
        assert_eq!(aggregate, local.aggregate);

        // One entry unproved. `accept_share_proofs` would have accepted this
        // set, because it skips the local index; this must not.
        let Err(error) =
            AggregateSigningKey::from_verified_share_proofs_v1(&local.bindings, &both[..1])
        else {
            panic!("a roster entry without a proof must fail closed");
        };
        assert_eq!(error, LegError::MissingShareProof);

        // A statement bound to another session, presented under the right
        // index. The bytes cannot match what these bindings imply.
        let other = fixture(PurposeV1::ClaimAdaptor, Some(point(31)));
        // Asserted rather than assumed: the case below only tests what it
        // claims if the two sessions really are distinct, and the identity is
        // drawn from `OsRng` rather than derived, so nothing but this line
        // establishes it.
        assert_ne!(local.bindings.session_id(), other.bindings.session_id());
        let foreign = other
            .first
            .prove_share(&other.bindings)
            .expect("the other session proves its own share");
        let Err(error) = AggregateSigningKey::from_verified_share_proofs_v1(
            &local.bindings,
            &[foreign, proof_b.clone()],
        ) else {
            panic!("a statement from another session must fail closed");
        };
        assert_eq!(error, LegError::ShareStatementMismatch);

        // The right statement carrying the other entry's proof: the statement
        // matches byte for byte and the proof does not open it.
        let swapped = (proof_a.0.clone(), proof_b.1.clone());
        let Err(error) = AggregateSigningKey::from_verified_share_proofs_v1(
            &local.bindings,
            &[swapped, proof_b],
        ) else {
            panic!("a proof belonging to another entry must fail closed");
        };
        assert_eq!(error, LegError::ShareProofRejected);
    }

    /// The adaptor-point grammar on the live path, both halves.
    ///
    /// `SessionOpenRequest::adaptor_point` has always documented the rule —
    /// mandatory in `ClaimAdaptor`, forbidden elsewhere — and only the first
    /// half was ever refused, late, at `build_claim_pre_signature`. The second
    /// half mattered more than it looked: `BoundRound::bind` folds the point
    /// into the aggregate nonce whenever it is `Some` without consulting the
    /// purpose, so a non-adaptor session opened with one would have signed
    /// against a displaced `R̂` with nothing downstream to catch it.
    ///
    /// Both halves are asserted to be refused **before the registry is
    /// consulted**, so a contradiction cannot burn a session identity on its
    /// way to being rejected.
    #[test]
    fn session_open_enforces_the_adaptor_point_grammar_before_registry_use() {
        for (case, purpose, adaptor_point, expected) in [
            (
                "claim adaptor without its point",
                PurposeV1::ClaimAdaptor,
                None,
                LegError::AdaptorPointMissing,
            ),
            (
                "refund carrying a point",
                PurposeV1::Refund,
                Some(point(31)),
                LegError::PurposeMismatch,
            ),
            (
                "funding carrying a point",
                PurposeV1::Funding,
                Some(point(31)),
                LegError::PurposeMismatch,
            ),
        ] {
            let chain_id = chain();
            let roster = roster_for(&chain_id);
            let initiator = *roster.entries()[0].participant_id();
            let tx = template_tx();
            let mut registry = MemoryRegistry(Vec::new());
            let Err(error) = SessionBindings::open(
                SessionOpenRequest {
                    chain_id,
                    contract_kind: ContractKindV1::WitnessOrTimeout,
                    roster,
                    initiator_participant_id: initiator,
                    purpose,
                    adaptor_point,
                    template_tx: &tx,
                    kernel_message_digest: [0x44; 32],
                    opening_direction: DirectionV1::Initiator,
                    opening_phase: SigningPhaseV1::SigNonceCommit,
                    terms_hash: [0x55; 32],
                    recovery_binding_hash: [0x66; 32],
                },
                &mut registry,
            ) else {
                panic!("{case}: the adaptor-point grammar must fail closed");
            };
            assert_eq!(error, expected, "{case}");
            assert!(
                registry.0.is_empty(),
                "{case}: the grammar must be refused before a session id is drawn"
            );
        }
    }

    /// The tie-back is the whole identity check, and it fires.
    ///
    /// Every case below is the same reassembly with exactly **one** value
    /// perturbed, against bindings the live path produced, so a refusal is
    /// attributable to the perturbation and to nothing upstream of it. The
    /// paired positive at the top is what makes that attribution sound: it
    /// proves the unperturbed request reaches the end.
    ///
    /// What it deliberately does not claim to test: that a caller cannot
    /// fabricate a consistent pair. A caller can — the last case here does
    /// exactly that and is accepted — and the constructor's documentation says
    /// so. This test pins the tie-back, not a provenance the type cannot check.
    #[test]
    fn caller_supplied_identity_is_accepted_only_when_the_transcript_commits_it() {
        fn retained<'a>(
            bytes: &'a [u8],
            adaptor_point: &PublicKey,
            session_id: [u8; 32],
            expected_initial_transcript_hash: [u8; 32],
            transcript_hash: [u8; 32],
        ) -> CallerSuppliedIdentitySessionRequestV1<'a> {
            let chain_id = chain();
            let roster = roster_for(&chain_id);
            CallerSuppliedIdentitySessionRequestV1 {
                chain_id,
                contract_kind: ContractKindV1::WitnessOrTimeout,
                roster,
                purpose: PurposeV1::ClaimAdaptor,
                adaptor_point: Some(adaptor_point.clone()),
                canonical_transaction_bytes: bytes,
                kernel_message_digest: [0x44; 32],
                terms_hash: [0x55; 32],
                recovery_binding_hash: [0x66; 32],
                session_id,
                expected_initial_transcript_hash,
                transcript_hash,
            }
        }

        let adaptor_point = point(31);
        let live = open(
            PurposeV1::ClaimAdaptor,
            Some(adaptor_point.clone()),
            SigningPhaseV1::SigNonceCommit,
            0x33,
        );
        let mut tx = template_tx();
        tx.offset = [0x33; 32];
        let bytes = tx.to_bytes().expect("canonical template bytes");
        let session_id = *live.session_id();
        let initial = *live.initial_transcript_hash();
        let transcript = *live.transcript_hash();

        // Positive: the pair the live path produced reassembles the same
        // bindings, identity and transcripts included.
        let rehydrated = SessionBindings::open_with_caller_supplied_identity_v1(retained(
            &bytes,
            &adaptor_point,
            session_id,
            initial,
            transcript,
        ))
        .expect("the retained pair reassembles");
        assert_eq!(rehydrated.session_id(), &session_id);
        assert_eq!(rehydrated.initial_transcript_hash(), &initial);
        assert_eq!(rehydrated.transcript_hash(), &transcript);
        assert_eq!(rehydrated.template_hash(), live.template_hash());
        assert_eq!(rehydrated.contract_kind(), live.contract_kind());

        // A forged identity against the retained transcript: the recomputed
        // initial transcript no longer equals the one supplied.
        let mut forged = session_id;
        forged[0] ^= 0x01;
        let Err(error) = SessionBindings::open_with_caller_supplied_identity_v1(retained(
            &bytes,
            &adaptor_point,
            forged,
            initial,
            transcript,
        )) else {
            panic!("a session identity the initial transcript does not commit must fail closed");
        };
        assert_eq!(error, LegError::TranscriptMismatch);

        // The mirror image: the true identity against a tampered initial
        // transcript. The same gate refuses it, from the other side.
        let mut tampered = initial;
        tampered[31] ^= 0x80;
        let Err(error) = SessionBindings::open_with_caller_supplied_identity_v1(retained(
            &bytes,
            &adaptor_point,
            session_id,
            tampered,
            transcript,
        )) else {
            panic!("a tampered initial transcript must fail closed");
        };
        assert_eq!(error, LegError::TranscriptMismatch);

        // The three structural refusals, all three asserted, because the
        // argument for guarding them is that they are indistinguishable and a
        // test that covered one would invite someone to drop the others.
        for (case, id, expected_initial, accepted) in [
            ("zero identity", [0; 32], initial, transcript),
            ("zero initial transcript", session_id, [0; 32], transcript),
            ("zero accepted transcript", session_id, initial, [0; 32]),
        ] {
            let Err(error) = SessionBindings::open_with_caller_supplied_identity_v1(retained(
                &bytes,
                &adaptor_point,
                id,
                expected_initial,
                accepted,
            )) else {
                panic!("{case}: a structurally empty field must fail closed");
            };
            assert_eq!(error, LegError::MalformedRetainedFacts, "{case}");
        }

        // The roster gate of this constructor, exercised on this constructor.
        // The equivalent gate on `open` is covered by its own tests, and the
        // reason that is not enough is that the two blocks are separate text:
        // the day one of them is edited, only a test aimed here notices.
        let foreign_chain = TrustedChainIdV1::from_authenticated_genesis(
            0x2345_6789,
            &Hash256::from_bytes([0x12; 32]),
        );
        let mut wrong_roster = retained(&bytes, &adaptor_point, session_id, initial, transcript);
        wrong_roster.roster = roster_for(&foreign_chain);
        let Err(error) = SessionBindings::open_with_caller_supplied_identity_v1(wrong_roster)
        else {
            panic!("a roster bound to another chain must fail closed");
        };
        assert_eq!(error, LegError::RosterMismatch);

        // The purpose gate. `Sponsor` is the one purpose `require_strict_phase1`
        // refuses, and it is refused before the template is touched, so an
        // adaptor error at this point can only have come from that gate.
        let mut sponsored = retained(&bytes, &adaptor_point, session_id, initial, transcript);
        sponsored.purpose = PurposeV1::Sponsor;
        let Err(error) = SessionBindings::open_with_caller_supplied_identity_v1(sponsored) else {
            panic!("a purpose outside strict phase 1 must fail closed");
        };
        assert!(
            matches!(error, LegError::Adaptor(_)),
            "the purpose registry must be the refusing authority, got {error:?}"
        );

        // The adaptor-point grammar, both halves. The second half is the one
        // nothing enforced before: a point on a non-adaptor purpose would
        // otherwise displace the aggregate nonce with nothing downstream to
        // catch it.
        let mut pointless = retained(&bytes, &adaptor_point, session_id, initial, transcript);
        pointless.adaptor_point = None;
        let Err(error) = SessionBindings::open_with_caller_supplied_identity_v1(pointless) else {
            panic!("a claim-adaptor round without its point must fail closed");
        };
        assert_eq!(error, LegError::AdaptorPointMissing);

        let mut refund_with_point =
            retained(&bytes, &adaptor_point, session_id, initial, transcript);
        refund_with_point.purpose = PurposeV1::Refund;
        let Err(error) = SessionBindings::open_with_caller_supplied_identity_v1(refund_with_point)
        else {
            panic!("a non-adaptor purpose carrying a point must fail closed");
        };
        assert_eq!(error, LegError::PurposeMismatch);

        // And the honest limit, asserted rather than left to prose: a caller
        // who computes the matching initial transcript for an identity of its
        // own choosing is accepted. Nothing here proves provenance, and this
        // case exists so that the day someone believes it does, the test that
        // says otherwise is already on the page.
        let chosen = [0x7c; 32];
        let consistent = initial_transcript_hash_v1(
            &chain(),
            &chosen,
            ContractKindV1::WitnessOrTimeout,
            &roster_for(&chain()),
        );
        let fabricated = SessionBindings::open_with_caller_supplied_identity_v1(retained(
            &bytes,
            &adaptor_point,
            chosen,
            consistent,
            transcript,
        ))
        .expect("a mutually consistent pair passes: the tie-back is not provenance");
        assert_eq!(fabricated.session_id(), &chosen);
    }
    #[test]
    fn session_open_rederives_the_complete_roster_before_registry_use() {
        let expected_chain = chain();
        let foreign_chain = TrustedChainIdV1::from_authenticated_genesis(
            0x1234_5678,
            &Hash256::from_bytes([0x12; 32]),
        );
        let mut mixed_entries = vec![
            ParticipantIdentityV1::new(
                &expected_chain,
                point(21),
                point(7),
                DirectionV1::Initiator,
            )
            .expect("local-chain participant"),
            ParticipantIdentityV1::new(&foreign_chain, point(22), point(9), DirectionV1::Responder)
                .expect("foreign-chain participant"),
        ];
        mixed_entries.sort_by_key(|entry| *entry.participant_id());
        let mixed_roster = ParticipantRosterV1::new(mixed_entries).expect("mixed-chain roster");
        let initiator = *mixed_roster.entries()[0].participant_id();
        let tx = template_tx();
        let mut registry = MemoryRegistry(Vec::new());

        let error = expect_leg_err(
            SessionBindings::open(
                SessionOpenRequest {
                    chain_id: expected_chain,
                    contract_kind: ContractKindV1::WitnessOrTimeout,
                    roster: mixed_roster,
                    initiator_participant_id: initiator,
                    purpose: PurposeV1::Funding,
                    adaptor_point: None,
                    template_tx: &tx,
                    kernel_message_digest: [0x44; 32],
                    opening_direction: DirectionV1::Initiator,
                    opening_phase: SigningPhaseV1::SigNonceCommit,
                    terms_hash: [0x55; 32],
                    recovery_binding_hash: [0x66; 32],
                },
                &mut registry,
            ),
            "mixed-chain roster",
        );
        assert_eq!(error, LegError::RosterMismatch);
        assert!(
            registry.0.is_empty(),
            "chain/roster mismatch must fail before durable session-ID registration"
        );
    }

    #[test]
    fn session_open_rejects_a_nonmember_initiator_before_registry_use() {
        let chain_id = chain();
        let roster = roster_for(&chain_id);
        let foreign_participant_id = [0x99; 32];
        assert!(roster
            .entries()
            .iter()
            .all(|entry| entry.participant_id() != &foreign_participant_id));
        let tx = template_tx();
        let mut registry = MemoryRegistry(Vec::new());

        let error = expect_leg_err(
            SessionBindings::open(
                SessionOpenRequest {
                    chain_id,
                    contract_kind: ContractKindV1::WitnessOrTimeout,
                    roster,
                    initiator_participant_id: foreign_participant_id,
                    purpose: PurposeV1::Funding,
                    adaptor_point: None,
                    template_tx: &tx,
                    kernel_message_digest: [0x44; 32],
                    opening_direction: DirectionV1::Initiator,
                    opening_phase: SigningPhaseV1::SigNonceCommit,
                    terms_hash: [0x55; 32],
                    recovery_binding_hash: [0x66; 32],
                },
                &mut registry,
            ),
            "nonmember initiator",
        );
        assert_eq!(error, LegError::RosterMismatch);
        assert!(
            registry.0.is_empty(),
            "initiator membership must fail before durable session-ID registration"
        );
    }

    #[test]
    fn funding_reaches_the_real_dom_verifier() {
        let fixture = fixture(PurposeV1::Funding, None);
        let (round, partials) = run_round(&fixture);
        let signature =
            finalize_plain(&fixture.bindings, &round, &partials).expect("funding finalizes");
        assert_eq!(
            signature.r_compressed(),
            &round.aggregate_nonce().to_compressed_bytes()
        );
    }

    #[test]
    fn refund_reaches_the_real_dom_verifier() {
        let fixture = fixture(PurposeV1::Refund, None);
        let (round, partials) = run_round(&fixture);
        assert!(finalize_plain(&fixture.bindings, &round, &partials).is_ok());
    }

    #[test]
    fn a_single_partial_alone_fails_the_real_verifier() {
        // Unilateral spend impossible: the test reaches the real verifier.
        let fixture = fixture(PurposeV1::Funding, None);
        let (round, mut partials) = run_round(&fixture);
        let solo = vec![partials.remove(0)];
        assert_eq!(
            finalize_plain(&fixture.bindings, &round, &solo).unwrap_err(),
            LegError::Adaptor(AdaptorError::VerificationFailed(
                "aggregated plain DOM Schnorr signature"
            ))
        );
        let other = vec![partials.remove(0)];
        assert!(finalize_plain(&fixture.bindings, &round, &other).is_err());
    }

    #[test]
    fn claim_adaptor_extract_recovers_the_committed_point() {
        let secret_bytes = scalar(0x2b);
        let secret = AdaptorSecret::from_be_bytes(*secret_bytes).expect("t");
        let adaptor_point = secret.public_point().expect("T");
        let fixture = fixture(PurposeV1::ClaimAdaptor, Some(adaptor_point.clone()));
        let (round, partials) = run_round(&fixture);
        let pre =
            build_claim_pre_signature(&fixture.bindings, &round, &partials).expect("pre-signature");

        // Byte-identical transport (I7) and rehydration with revalidation.
        let wire = PreSignatureBytes::from_slice(&pre.to_bytes()).expect("wire");
        let session = DomLegSession::new(fixture.bindings, round);
        let rehydrated = session.pre_signature_from_wire(&wire).expect("rehydrate");
        session
            .verify_pre_signature(&rehydrated)
            .expect("real equation");

        let final_signature = session.adapt_claim(&rehydrated, &secret).expect("adapt");
        let extracted = session
            .extract_secret(&rehydrated, &final_signature)
            .expect("extract");
        assert_eq!(
            extracted.public_point().expect("extracted point"),
            adaptor_point,
            "extract(adapt(pre)) == t, compared through the public point"
        );
        assert_eq!(
            extracted.adaptor_point_bytes().expect("bytes").0,
            adaptor_point.to_compressed_bytes()
        );
    }

    #[test]
    fn adapt_with_the_wrong_secret_is_rejected() {
        let secret = AdaptorSecret::from_be_bytes(*scalar(0x2b)).expect("t");
        let adaptor_point = secret.public_point().expect("T");
        let fixture = fixture(PurposeV1::ClaimAdaptor, Some(adaptor_point));
        let (round, partials) = run_round(&fixture);
        let pre =
            build_claim_pre_signature(&fixture.bindings, &round, &partials).expect("pre-signature");
        let session = DomLegSession::new(fixture.bindings, round);
        let wrong = AdaptorSecret::from_be_bytes(*scalar(0x2c)).expect("t'");
        assert_eq!(
            session.adapt_claim(&pre, &wrong).unwrap_err(),
            LegError::Adaptor(AdaptorError::VerificationFailed(
                "adaptor secret does not match the committed point"
            ))
        );
    }

    #[test]
    fn claim_adaptor_is_never_finalized_as_a_plain_signature() {
        let secret = AdaptorSecret::from_be_bytes(*scalar(0x2b)).expect("t");
        let adaptor_point = secret.public_point().expect("T");
        let fixture = fixture(PurposeV1::ClaimAdaptor, Some(adaptor_point));
        let (round, partials) = run_round(&fixture);
        assert_eq!(
            finalize_plain(&fixture.bindings, &round, &partials).unwrap_err(),
            LegError::Adaptor(AdaptorError::InvalidTranscript(
                "plain finalization is restricted to Funding and Refund"
            )),
            "the rejection comes from the real crate, not a local shortcut"
        );
    }

    #[test]
    fn the_reserved_codec_purpose_has_no_execution_path() {
        // Byte 0x04 belongs to the canonical registry; recognizing it never activates it.
        let reserved = PurposeV1::try_from(0x04u8).expect("registry byte");
        assert!(!reserved.is_strict_v1_authorized());
        let fixture = fixture(PurposeV1::Funding, None);
        let (round, partials) = run_round(&fixture);
        assert!(finalize_plain_signature_v1(
            &partials,
            reserved,
            fixture.bindings.template_hash(),
            round.aggregate_nonce(),
            round.aggregate_signing_key().public_key(),
            fixture.bindings.chain_id().as_bytes(),
            fixture.bindings.kernel_message_digest(),
        )
        .is_err());
        // And session opening itself closes off before any crypto.
        let chain_id = chain();
        let roster = roster_for(&chain_id);
        let initiator = *roster.entries()[0].participant_id();
        let tx = template_tx();
        assert!(SessionBindings::open(
            SessionOpenRequest {
                chain_id,
                contract_kind: ContractKindV1::WitnessOrTimeout,
                roster,
                initiator_participant_id: initiator,
                purpose: reserved,
                adaptor_point: None,
                template_tx: &tx,
                kernel_message_digest: [0x44; 32],
                opening_direction: DirectionV1::Initiator,
                opening_phase: SigningPhaseV1::SigNonceCommit,
                terms_hash: [0x55; 32],
                recovery_binding_hash: [0x66; 32],
            },
            &mut MemoryRegistry(Vec::new()),
        )
        .is_err());
    }

    #[test]
    fn adaptor_secret_rejects_zero_order_and_above() {
        assert!(AdaptorSecret::from_be_bytes([0u8; 32]).is_err(), "t = 0");
        assert!(AdaptorSecret::from_be_bytes(GROUP_ORDER).is_err(), "t = n");
        let mut above = GROUP_ORDER;
        above[31] = 0x42;
        assert!(AdaptorSecret::from_be_bytes(above).is_err(), "t > n");
        assert!(AdaptorSecret::from_be_bytes([0xff; 32]).is_err(), "t >> n");
        assert!(AdaptorSecret::from_be_bytes(*scalar(1)).is_ok());
    }

    #[test]
    fn non_canonical_pre_signature_encodings_are_rejected() {
        let secret = AdaptorSecret::from_be_bytes(*scalar(0x2b)).expect("t");
        let adaptor_point = secret.public_point().expect("T");
        let fixture = fixture(PurposeV1::ClaimAdaptor, Some(adaptor_point));
        let (round, partials) = run_round(&fixture);
        let pre =
            build_claim_pre_signature(&fixture.bindings, &round, &partials).expect("pre-signature");
        let encoded = pre.to_bytes();
        let session = DomLegSession::new(fixture.bindings, round);

        // Zeroed scalar.
        let mut zero_scalar = encoded;
        zero_scalar[98..130].fill(0);
        let wire = PreSignatureBytes::from_slice(&zero_scalar).expect("length");
        assert!(session.pre_signature_from_wire(&wire).is_err());

        // Scalar >= n.
        let mut over = encoded;
        over[98..130].copy_from_slice(&GROUP_ORDER);
        let wire = PreSignatureBytes::from_slice(&over).expect("length");
        assert!(session.pre_signature_from_wire(&wire).is_err());

        // Invalid SEC1 point.
        let mut bad_point = encoded;
        bad_point[65] = 0x05;
        let wire = PreSignatureBytes::from_slice(&bad_point).expect("length");
        assert!(session.pre_signature_from_wire(&wire).is_err());

        // Non-canonical length.
        assert!(PreSignatureBytes::from_slice(&encoded[..161]).is_err());
    }

    #[test]
    fn divergent_template_transcript_and_adaptor_point_fail_closed() {
        let secret = AdaptorSecret::from_be_bytes(*scalar(0x2b)).expect("t");
        let adaptor_point = secret.public_point().expect("T");
        let fixture = fixture(PurposeV1::ClaimAdaptor, Some(adaptor_point));
        let (round, partials) = run_round(&fixture);
        let pre =
            build_claim_pre_signature(&fixture.bindings, &round, &partials).expect("pre-signature");
        let encoded = pre.to_bytes();
        let session = DomLegSession::new(fixture.bindings, round);

        let mut other_template = encoded;
        other_template[..32].fill(0xAA);
        assert_eq!(
            expect_leg_err(
                session.pre_signature_from_wire(
                    &PreSignatureBytes::from_slice(&other_template).expect("length")
                ),
                "template from another session",
            ),
            LegError::TemplateMismatch
        );

        let mut other_transcript = encoded;
        other_transcript[130..].fill(0xBB);
        assert_eq!(
            expect_leg_err(
                session.pre_signature_from_wire(
                    &PreSignatureBytes::from_slice(&other_transcript).expect("length")
                ),
                "transcript from another session",
            ),
            LegError::TranscriptMismatch
        );

        let mut other_point = encoded;
        other_point[32..65].copy_from_slice(&point(0x5f).to_compressed_bytes());
        assert_eq!(
            expect_leg_err(
                session.pre_signature_from_wire(
                    &PreSignatureBytes::from_slice(&other_point).expect("length")
                ),
                "divergent adaptor point",
            ),
            LegError::SecretPointMismatch
        );
    }

    #[test]
    fn a_divergent_phase_produces_a_foreign_transcript() {
        // Comparing two independently opened sessions does not isolate the
        // subphase: `generate_session_id_v1` draws a fresh session_id per
        // `open()` and it feeds into `initial_transcript_hash_v1`. The
        // correct proof starts from ONE session and advances the SAME
        // initial transcript with different subphases — only the subphase
        // varies.
        let fixture = fixture_with(
            PurposeV1::Funding,
            None,
            SigningPhaseV1::SigNonceCommit,
            0x33,
        );
        let opening_digest = session_message_digest_v1(fixture.bindings.template_bytes());
        let advanced_commit = advance_transcript_hash_v1(
            fixture.bindings.initial_transcript_hash(),
            &opening_digest,
            DirectionV1::Initiator,
            SigningPhaseV1::SigNonceCommit,
        );
        let advanced_reveal = advance_transcript_hash_v1(
            fixture.bindings.initial_transcript_hash(),
            &opening_digest,
            DirectionV1::Initiator,
            SigningPhaseV1::SigNonceReveal,
        );
        assert_ne!(
            advanced_commit, advanced_reveal,
            "the subphase feeds into advance_transcript_hash_v1"
        );
        // And the session's transcript is exactly the advance with the
        // opening subphase — nothing but the subphase changed.
        assert_eq!(fixture.bindings.transcript_hash(), &advanced_commit);
    }

    #[test]
    fn a_divergent_template_produces_a_foreign_session() {
        let a = fixture_with(
            PurposeV1::Funding,
            None,
            SigningPhaseV1::SigNonceCommit,
            0x33,
        );
        let b = fixture_with(
            PurposeV1::Funding,
            None,
            SigningPhaseV1::SigNonceCommit,
            0x34,
        );
        assert_ne!(a.bindings.template_hash(), b.bindings.template_hash());
        assert_ne!(a.bindings.transcript_hash(), b.bindings.transcript_hash());

        let (round_a, partials_a) = run_round(&a);
        // A's partials cannot be finalized against B's template.
        assert!(finalize_plain_signature_v1(
            &partials_a,
            b.bindings.purpose(),
            b.bindings.template_hash(),
            round_a.aggregate_nonce(),
            round_a.aggregate_signing_key().public_key(),
            b.bindings.chain_id().as_bytes(),
            b.bindings.kernel_message_digest(),
        )
        .is_err());
    }

    #[test]
    fn a_divergent_purpose_cannot_reuse_partials() {
        let funding = fixture(PurposeV1::Funding, None);
        let (round, partials) = run_round(&funding);
        assert_eq!(
            finalize_plain_signature_v1(
                &partials,
                PurposeV1::Refund,
                funding.bindings.template_hash(),
                round.aggregate_nonce(),
                round.aggregate_signing_key().public_key(),
                funding.bindings.chain_id().as_bytes(),
                funding.bindings.kernel_message_digest(),
            )
            .unwrap_err(),
            AdaptorError::InvalidTranscript(
                "partial signature binding differs from the aggregate session"
            )
        );
    }

    #[test]
    fn a_divergent_roster_changes_transcript_and_aggregate_key() {
        let chain_id = chain();
        let roster = roster_for(&chain_id);
        let other = {
            let mut entries = vec![
                ParticipantIdentityV1::new(&chain_id, point(21), point(7), DirectionV1::Initiator)
                    .expect("initiator"),
                ParticipantIdentityV1::new(&chain_id, point(23), point(11), DirectionV1::Responder)
                    .expect("responder"),
            ];
            entries.sort_by_key(|entry| *entry.participant_id());
            ParticipantRosterV1::new(entries).expect("roster")
        };
        let session_id = [0x77; 32];
        assert_ne!(
            initial_transcript_hash_v1(
                &chain_id,
                &session_id,
                ContractKindV1::WitnessOrTimeout,
                &roster
            ),
            initial_transcript_hash_v1(
                &chain_id,
                &session_id,
                ContractKindV1::WitnessOrTimeout,
                &other
            )
        );
    }

    #[test]
    fn share_proofs_are_verified_before_any_public_point_aggregation() {
        let bindings = open(
            PurposeV1::Funding,
            None,
            SigningPhaseV1::SigNonceCommit,
            0x33,
        );
        let (first, second) = join_all(&bindings);

        // With no proof at all: there is no path to the aggregate key.
        assert_eq!(
            first.accept_share_proofs(&bindings, &[]).unwrap_err(),
            LegError::MissingShareProof
        );

        // Valid proof, statement from another session: closes off before aggregating.
        let foreign = open(
            PurposeV1::Funding,
            None,
            SigningPhaseV1::SigNonceCommit,
            0x34,
        );
        let (_, foreign_second) = join_all(&foreign);
        let foreign_proof = foreign_second.prove_share(&foreign).expect("foreign proof");
        assert_eq!(
            first
                .accept_share_proofs(&bindings, &[foreign_proof])
                .unwrap_err(),
            LegError::ShareStatementMismatch
        );

        // Correct statement with a tampered proof: rejected by the verifier.
        let (statement, proof) = second.prove_share(&bindings).expect("proof");
        let mut tampered = proof.to_bytes();
        tampered[64] ^= 0x01;
        let tampered = ShareProofV1::from_bytes(&tampered).expect("proof reencode");
        assert_eq!(
            first
                .accept_share_proofs(&bindings, &[(statement, tampered)])
                .unwrap_err(),
            LegError::ShareProofRejected
        );
    }

    #[test]
    fn a_reveal_that_does_not_open_its_commitment_is_rejected() {
        let fixture = fixture(PurposeV1::Funding, None);
        let (_, commit_a) = fixture
            .first
            .begin_round(&fixture.bindings)
            .expect("commit");
        let (nonces_b, _) = fixture
            .second
            .begin_round(&fixture.bindings)
            .expect("commit b");
        let foreign_reveal = fixture.second.reveal(&fixture.bindings, &nonces_b);
        assert_eq!(
            fixture
                .bindings
                .check_reveal_opens_commitment(
                    fixture.first.identity().participant_id(),
                    &commit_a,
                    &foreign_reveal,
                )
                .unwrap_err(),
            LegError::CommitmentMismatch
        );
    }

    #[test]
    fn secrets_never_reach_debug_output() {
        let local = share(7);
        assert_eq!(format!("{local:?}"), "LocalSigningShare(<redacted>)");
        let nonces = RoundNonces::generate().expect("nonces");
        assert_eq!(format!("{nonces:?}"), "RoundNonces(<redacted>)");
        let secret = AdaptorSecret::from_be_bytes(*scalar(0x2b)).expect("t");
        let extracted = ExtractedAdaptorSecret(secret);
        assert_eq!(
            format!("{extracted:?}"),
            "ExtractedAdaptorSecret(<redacted>)"
        );
    }
}

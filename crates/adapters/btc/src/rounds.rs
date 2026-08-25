//! The 2-of-2 MuSig2 adaptor claim rounds (Annex M M.6.7).
//!
//! This is the orchestration that ties the durable one-shot vault
//! (`btc-vault`) to the crypto backend (`btc-crypto`) under the
//! persist-before-exposure discipline. Legacy F5 keeps the memory-only
//! crash-to-refund rule. The additive F7 path first seals the backend seed
//! and commits its exact public nonce atomically, so an ordinary process
//! crash reopens the same owner. Only authenticated owner corruption makes
//! the F7 path refund-eligible.
//!
//! The non-negotiable rule (M.6.7): every partial — including our own —
//! goes through `partial_verify`, and no pre-signature is released until
//! both partials verify.

use btc_crypto::{KeyAggContext, MusigSession, NonceParity, SecNonce, SecpContext};
use btc_vault::{
    BitcoinNoncePermitV1, BitcoinNonceReservationIdV1, BitcoinNonceSealKeyV1, BitcoinNonceStateV1,
    BitcoinNonceVault, EntropySource, PersistedArtifactDescriptorV1, PublicAbortReasonV1,
    VaultError,
};

use crate::{roster::ParticipantKeyRosterV1, timelock::AnchoredCrossChainWindowV1};

/// The round a local claim signer is in (M.6.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimRoundV1 {
    /// Prepared; nonce not yet generated.
    Prepared,
    /// The local public nonce is persisted (not yet exposed).
    LocalPubNoncePersisted,
    /// Both public nonces are present.
    PubNoncesComplete,
    /// The session (with adaptor) is processed.
    SessionProcessed,
    /// The local partial is persisted.
    LocalPartialPersisted,
    /// Both partials verified; the pre-signature may be aggregated.
    PartialsVerified,
    /// The pre-signature is persisted/available.
    PreSignatureReady,
    /// Terminal: aborted to refund.
    Aborted,
}

/// Round-machine failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoundError {
    /// The vault rejected an operation.
    #[error("vault error")]
    Vault,
    /// The roster does not satisfy M.1.3 and therefore has no digest.
    ///
    /// Audit finding F2: `roster_hash` used to swallow this and return the
    /// digest of an empty encoding, so every invalid roster produced the
    /// same continuation binding. The round now refuses instead.
    #[error("invalid roster")]
    InvalidRoster,
    /// The crypto backend rejected an operation.
    #[error("crypto error")]
    Crypto,
    /// A counterparty artifact failed verification (M.6.7).
    #[error("counterparty artifact rejected")]
    CounterpartyRejected,
    /// The call was made in the wrong round.
    #[error("wrong round")]
    WrongRound,
    /// The local secret nonce was lost (crash); abort to refund.
    #[error("secret nonce lost")]
    SecNonceLost,
    /// The M.8 authorization belongs to different frozen settlement terms.
    #[error("M.8 anchored-window authorization mismatch")]
    M8AuthorizationMismatch,
    /// F7 refused to create a crash-fragile economic nonce owner.
    #[error("restartable nonce-owner authority required")]
    RestartAuthorityRequired,
    /// Durable restart state is temporarily unavailable; retry without
    /// selecting the refund path.
    #[error("restartable nonce-owner storage unavailable")]
    RestartStorageUnavailable,
    /// The authenticated restart owner or its exact public continuation is
    /// corrupt; the route may select its pre-armed refund path.
    #[error("restartable nonce-owner corruption")]
    RestartOwnerCorrupt,
}

fn map_restart_vault_error(error: VaultError) -> RoundError {
    match error {
        VaultError::StorageUnavailable
        | VaultError::EntropyUnavailable
        | VaultError::KeyStoreUnavailable => RoundError::RestartStorageUnavailable,
        VaultError::CorruptState
        | VaultError::BindingMismatch
        | VaultError::SealAuthenticationFailed
        | VaultError::SealedOwnerUnavailable
        | VaultError::InvalidKeyStoreObject
        | VaultError::InvalidSealKey => RoundError::RestartOwnerCorrupt,
        VaultError::NoSuchReservation
        | VaultError::AlreadyConsumed
        | VaultError::IllegalTransition
        | VaultError::RevisionConflict
        | VaultError::NoSuchArtifact => RoundError::Vault,
    }
}

/// Which roster index is the local signer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LocalSigner {
    /// Roster index 0.
    First,
    /// Roster index 1.
    Second,
}

impl LocalSigner {
    fn local_idx(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => 1,
        }
    }
    fn remote_idx(self) -> usize {
        match self {
            Self::First => 1,
            Self::Second => 0,
        }
    }
}

/// The immutable inputs of a claim round.
pub struct ClaimRoundInputs<'a> {
    /// The pinned crypto backend.
    pub crypto: &'a SecpContext,
    /// The key-aggregation context (already TapTweak-applied).
    pub keyagg: &'a KeyAggContext,
    /// The ordered 2-of-2 roster.
    pub roster: &'a ParticipantKeyRosterV1,
    /// Which roster index is the local signer.
    pub local: LocalSigner,
    /// The local signer's secret key.
    pub local_secret: &'a [u8; 32],
    /// The frozen key-path sighash.
    pub tap_sighash: &'a [u8; 32],
    /// The adaptor point `T` (compressed).
    pub adaptor_point: &'a [u8; 33],
    /// The x-only Taproot output key `x(Q)`.
    pub output_xonly: &'a [u8; 32],
    /// The vault permit for this reservation.
    pub permit: &'a BitcoinNoncePermitV1,
}

/// The live claim round: holds the memory-only secnonce and the durable
/// reservation. Not `Clone`/`Copy`; the secnonce never leaves.
pub struct ClaimRound<'a> {
    inputs: ClaimRoundInputs<'a>,
    reservation: BitcoinNonceReservationIdV1,
    m8_anchor_evidence_digest: Option<[u8; 32]>,
    secnonce: Option<SecNonce>,
    local_pubnonce: Option<[u8; 66]>,
    local_pubnonce_desc: Option<PersistedArtifactDescriptorV1>,
    remote_pubnonce: Option<[u8; 66]>,
    session: Option<MusigSession>,
    local_partial: Option<[u8; 32]>,
    local_partial_desc: Option<PersistedArtifactDescriptorV1>,
    round: ClaimRoundV1,
}

impl<'a> ClaimRound<'a> {
    /// The current round.
    #[must_use]
    pub fn round(&self) -> ClaimRoundV1 {
        self.round
    }

    /// Prepares a legacy F5 round without the additive F7 M.8 gate.
    ///
    /// This API is preserved for the already-frozen F5 flow.  It is not an
    /// eligible F7 entry point: F7 callers must use [`Self::prepare_after_m8`]
    /// so real funding anchors and the cross-chain inequality are validated
    /// before a nonce is reserved or generated.
    pub fn prepare<E: EntropySource>(
        inputs: ClaimRoundInputs<'a>,
        vault: &mut BitcoinNonceVault<E>,
    ) -> Result<Self, RoundError> {
        Self::prepare_with_anchor_binding(inputs, None, None, vault)
    }

    fn prepare_with_anchor_binding<E: EntropySource>(
        inputs: ClaimRoundInputs<'a>,
        m8_anchor_evidence_digest: Option<[u8; 32]>,
        restart_seal_key: Option<&BitcoinNonceSealKeyV1>,
        vault: &mut BitcoinNonceVault<E>,
    ) -> Result<Self, RoundError> {
        let reservation = match m8_anchor_evidence_digest.as_ref() {
            Some(digest) => vault.reserve_after_m8(inputs.permit, digest),
            None => vault.reserve(inputs.permit),
        }
        .map_err(|_| RoundError::Vault)?;
        let local_key = inputs.roster.participants()[inputs.local.local_idx()].compressed_key;
        let (secnonce, public_nonce, desc, persisted_partial) =
            match (m8_anchor_evidence_digest.as_ref(), restart_seal_key) {
                (Some(digest), Some(seal_key)) => {
                    let continuation = Self::continuation_binding_digest(&inputs, &local_key)?;
                    let state = vault
                        .state_of(&reservation)
                        .map_err(map_restart_vault_error)?;
                    match state {
                        BitcoinNonceStateV1::Reserved => {
                            let (secret, public, descriptor) = vault
                                .prepare_restartable_public_nonce_after_m8(
                                    &reservation,
                                    inputs.permit,
                                    digest,
                                    &continuation,
                                    seal_key,
                                    |secrand| {
                                        inputs
                                            .crypto
                                            .nonce_gen(
                                                secrand,
                                                inputs.local_secret,
                                                &local_key,
                                                inputs.tap_sighash,
                                                inputs.keyagg,
                                            )
                                            .map(|(secret, public)| (secret, public.0))
                                            .map_err(|_| ())
                                    },
                                )
                                .map_err(map_restart_vault_error)?;
                            (Some(secret), public, descriptor, None)
                        }
                        BitcoinNonceStateV1::PublicArtifactCommitted
                        | BitcoinNonceStateV1::PublicArtifactExposed => {
                            let (secret, public, descriptor) = vault
                                .reopen_restartable_nonce_after_m8(
                                    &reservation,
                                    inputs.permit,
                                    digest,
                                    &continuation,
                                    seal_key,
                                    |secrand| {
                                        inputs
                                            .crypto
                                            .nonce_gen(
                                                secrand,
                                                inputs.local_secret,
                                                &local_key,
                                                inputs.tap_sighash,
                                                inputs.keyagg,
                                            )
                                            .map(|(secret, public)| (secret, public.0))
                                            .map_err(|_| ())
                                    },
                                )
                                .map_err(map_restart_vault_error)?;
                            (Some(secret), public, descriptor, None)
                        }
                        BitcoinNonceStateV1::PartialArtifactCommitted
                        | BitcoinNonceStateV1::Spent => {
                            let (public, partial, descriptor, partial_descriptor) = vault
                                .reopen_tombstoned_partial_after_m8(
                                    &reservation,
                                    inputs.permit,
                                    digest,
                                    &continuation,
                                )
                                .map_err(map_restart_vault_error)?;
                            (
                                None,
                                public,
                                descriptor,
                                Some((partial, partial_descriptor)),
                            )
                        }
                        BitcoinNonceStateV1::ConsumptionCommitted
                        | BitcoinNonceStateV1::Aborted
                        | BitcoinNonceStateV1::Equivocated => return Err(RoundError::Vault),
                    }
                }
                (Some(_), None) => return Err(RoundError::RestartAuthorityRequired),
                (None, _) => {
                    let secret = vault
                        .consume(&reservation, inputs.permit)
                        .map_err(|_| RoundError::Vault)?;
                    let (secnonce, pubnonce) = secret
                        .use_once(|secrand| {
                            inputs.crypto.nonce_gen(
                                secrand,
                                inputs.local_secret,
                                &local_key,
                                inputs.tap_sighash,
                                inputs.keyagg,
                            )
                        })
                        .map_err(|_| RoundError::Crypto)?;
                    let desc = vault
                        .persist_public_nonce(&reservation, inputs.permit, &pubnonce.0)
                        .map_err(|_| RoundError::Vault)?;
                    (Some(secnonce), pubnonce.0, desc, None)
                }
            };
        let (local_partial, local_partial_desc) = match persisted_partial {
            Some((partial, descriptor)) => (Some(partial), Some(descriptor)),
            None => (None, None),
        };

        Ok(Self {
            inputs,
            reservation,
            m8_anchor_evidence_digest,
            secnonce,
            local_pubnonce: Some(public_nonce),
            local_pubnonce_desc: Some(desc),
            remote_pubnonce: None,
            session: None,
            local_partial,
            local_partial_desc,
            round: ClaimRoundV1::LocalPubNoncePersisted,
        })
    }

    /// Prepares an F7 claim round only after real funding anchors passed M.8.
    ///
    /// The opaque authorization is constructible only by
    /// [`crate::timelock::bind_and_validate_funding_anchors`].  Its frozen
    /// terms hash must equal the one already carried by the durable nonce
    /// permit.  The comparison occurs before the vault is touched, so a
    /// mismatch consumes neither a reservation nor nonce material.
    pub fn prepare_after_m8<E: EntropySource>(
        inputs: ClaimRoundInputs<'a>,
        authorization: AnchoredCrossChainWindowV1,
        restart_seal_key: &BitcoinNonceSealKeyV1,
        vault: &mut BitcoinNonceVault<E>,
    ) -> Result<Self, RoundError> {
        if inputs.permit.terms_hash != authorization.settlement_terms_hash() {
            return Err(RoundError::M8AuthorizationMismatch);
        }
        let anchor_evidence_digest = authorization.anchor_evidence_digest();
        Self::prepare_with_anchor_binding(
            inputs,
            Some(anchor_evidence_digest),
            Some(restart_seal_key),
            vault,
        )
    }

    fn continuation_binding_digest(
        inputs: &ClaimRoundInputs<'_>,
        local_key: &[u8; 33],
    ) -> Result<[u8; 32], RoundError> {
        let roster_hash = inputs
            .roster
            .roster_hash()
            .map_err(|_| RoundError::InvalidRoster)?;
        Ok(
            BitcoinNonceVault::<btc_vault::OsEntropy>::continuation_binding_digest(
                inputs.permit,
                local_key,
                &roster_hash,
                inputs.output_xonly,
            ),
        )
    }

    /// Exposes the persisted local public nonce (M.6.5): only now do its
    /// bytes leave the process.
    pub fn expose_local_pubnonce<E: EntropySource>(
        &mut self,
        vault: &mut BitcoinNonceVault<E>,
    ) -> Result<[u8; 66], RoundError> {
        let desc = self
            .local_pubnonce_desc
            .as_ref()
            .ok_or(RoundError::WrongRound)?;
        let bytes = match self.m8_anchor_evidence_digest.as_ref() {
            Some(digest) => vault.expose_after_m8(desc, digest),
            None => vault.expose(desc),
        }
        .map_err(|error| {
            if self.m8_anchor_evidence_digest.is_some() {
                map_restart_vault_error(error)
            } else {
                RoundError::Vault
            }
        })?;
        bytes.try_into().map_err(|_| RoundError::Vault)
    }

    /// Ingests the counterparty public nonce.
    pub fn ingest_counterparty_pubnonce(
        &mut self,
        remote_pubnonce: [u8; 66],
    ) -> Result<(), RoundError> {
        if self.round != ClaimRoundV1::LocalPubNoncePersisted {
            return Err(RoundError::WrongRound);
        }
        self.remote_pubnonce = Some(remote_pubnonce);
        self.round = ClaimRoundV1::PubNoncesComplete;
        Ok(())
    }

    /// Aggregates the nonces in roster order and processes the session
    /// with the adaptor point `T` (M.4.2 steps 1-3).
    pub fn process_session(&mut self) -> Result<NonceParity, RoundError> {
        if self.round != ClaimRoundV1::PubNoncesComplete {
            return Err(RoundError::WrongRound);
        }
        let local = self.local_pubnonce.ok_or(RoundError::WrongRound)?;
        let remote = self.remote_pubnonce.ok_or(RoundError::WrongRound)?;
        // Aggregate strictly in roster order (M.4.2 step 1).
        let ordered = match self.inputs.local {
            LocalSigner::First => [local, remote],
            LocalSigner::Second => [remote, local],
        };
        let aggnonce = self
            .inputs
            .crypto
            .nonce_agg(&ordered)
            .map_err(|_| RoundError::Crypto)?;
        let session = self
            .inputs
            .crypto
            .nonce_process(
                &aggnonce,
                self.inputs.tap_sighash,
                self.inputs.keyagg,
                self.inputs.adaptor_point,
            )
            .map_err(|_| RoundError::Crypto)?;
        let parity = session.nonce_parity;
        self.session = Some(session);
        self.round = if self.local_partial.is_some() {
            ClaimRoundV1::LocalPartialPersisted
        } else {
            ClaimRoundV1::SessionProcessed
        };
        Ok(parity)
    }

    /// Produces and persists the local partial, self-verifying it inside
    /// the backend (M.6.7). Consumes the memory-only secnonce.
    pub fn produce_local_partial<E: EntropySource>(
        &mut self,
        vault: &mut BitcoinNonceVault<E>,
    ) -> Result<[u8; 32], RoundError> {
        if self.round == ClaimRoundV1::LocalPartialPersisted {
            let descriptor = self
                .local_partial_desc
                .as_ref()
                .ok_or(RoundError::WrongRound)?;
            let bytes = match self.m8_anchor_evidence_digest.as_ref() {
                Some(digest) => vault.resend_after_m8(descriptor, digest),
                None => vault.resend(descriptor),
            }
            .map_err(|error| {
                if self.m8_anchor_evidence_digest.is_some() {
                    map_restart_vault_error(error)
                } else {
                    RoundError::Vault
                }
            })?;
            return bytes.try_into().map_err(|_| RoundError::Vault);
        }
        if self.round != ClaimRoundV1::SessionProcessed {
            return Err(RoundError::WrongRound);
        }
        let secnonce = match self.secnonce.take() {
            Some(secnonce) => secnonce,
            None if self.m8_anchor_evidence_digest.is_some() => {
                return Err(RoundError::RestartStorageUnavailable)
            }
            None => return Err(RoundError::SecNonceLost),
        };
        let session = self.session.as_ref().ok_or(RoundError::WrongRound)?;
        let local_key =
            self.inputs.roster.participants()[self.inputs.local.local_idx()].compressed_key;
        let local_pubnonce = self.local_pubnonce.ok_or(RoundError::WrongRound)?;
        let partial = self
            .inputs
            .crypto
            .partial_sign(
                secnonce,
                self.inputs.local_secret,
                &local_key,
                &local_pubnonce,
                self.inputs.keyagg,
                session,
            )
            .map_err(|_| RoundError::Crypto)?;
        let descriptor = match self.m8_anchor_evidence_digest.as_ref() {
            Some(digest) => vault.persist_partial_signature_after_m8(
                &self.reservation,
                self.inputs.permit,
                digest,
                &partial,
            ),
            None => {
                vault.persist_partial_signature(&self.reservation, self.inputs.permit, &partial)
            }
        }
        .map_err(|error| {
            if self.m8_anchor_evidence_digest.is_some() {
                map_restart_vault_error(error)
            } else {
                RoundError::Vault
            }
        })?;
        self.local_partial = Some(partial);
        self.local_partial_desc = Some(descriptor);
        self.round = ClaimRoundV1::LocalPartialPersisted;
        Ok(partial)
    }

    /// Descriptor of the durably persisted local partial signature.
    ///
    /// A restarted process can pass this public descriptor to
    /// [`BitcoinNonceVault::resend`] and obtain the exact committed bytes;
    /// no nonce or signature is recomputed (M.10.5).
    #[must_use]
    pub fn local_partial_descriptor(&self) -> Option<PersistedArtifactDescriptorV1> {
        self.local_partial_desc
    }

    /// Durable reservation identifier for reconciliation and terminal
    /// accounting. It carries no secret material.
    #[must_use]
    pub fn reservation_id(&self) -> BitcoinNonceReservationIdV1 {
        self.reservation
    }

    /// Verifies the counterparty partial (M.6.7): if it fails, no
    /// pre-signature is ever released.
    pub fn verify_counterparty_partial(
        &mut self,
        remote_partial: &[u8; 32],
    ) -> Result<(), RoundError> {
        if self.round != ClaimRoundV1::LocalPartialPersisted {
            return Err(RoundError::WrongRound);
        }
        let session = self.session.as_ref().ok_or(RoundError::WrongRound)?;
        let remote = self.remote_pubnonce.ok_or(RoundError::WrongRound)?;
        let remote_key =
            self.inputs.roster.participants()[self.inputs.local.remote_idx()].compressed_key;
        self.inputs
            .crypto
            .partial_verify(
                remote_partial,
                &remote,
                &remote_key,
                self.inputs.keyagg,
                session,
            )
            .map_err(|_| RoundError::CounterpartyRejected)?;
        self.round = ClaimRoundV1::PartialsVerified;
        Ok(())
    }

    /// Aggregates the 64-byte pre-signature. Only reachable AFTER both
    /// partials verified (the round guard enforces M.6.7), and the
    /// backend additionally proves the pre-signature is NOT a valid final
    /// signature.
    pub fn aggregate_pre_signature(
        &mut self,
        remote_partial: &[u8; 32],
    ) -> Result<[u8; 64], RoundError> {
        if self.round != ClaimRoundV1::PartialsVerified {
            return Err(RoundError::WrongRound);
        }
        let session = self.session.as_ref().ok_or(RoundError::WrongRound)?;
        let local_partial = self.local_partial.ok_or(RoundError::WrongRound)?;
        let ordered = match self.inputs.local {
            LocalSigner::First => [local_partial, *remote_partial],
            LocalSigner::Second => [*remote_partial, local_partial],
        };
        let pre_sig = self
            .inputs
            .crypto
            .aggregate_pre_signature(
                &ordered,
                self.inputs.output_xonly,
                self.inputs.tap_sighash,
                session,
            )
            .map_err(|_| RoundError::Crypto)?;
        self.round = ClaimRoundV1::PreSignatureReady;
        Ok(pre_sig)
    }

    /// Aborts the round to the refund path.
    ///
    /// For the additive F7 restartable profile, `CrashRefund` is accepted
    /// only after authenticated owner corruption has been reported as
    /// [`RoundError::RestartOwnerCorrupt`]. An ordinary process crash or
    /// storage outage must reopen/retry and may not call this boundary.
    pub fn abort<E: EntropySource>(
        &mut self,
        vault: &mut BitcoinNonceVault<E>,
        reason: PublicAbortReasonV1,
    ) -> Result<(), RoundError> {
        if self.m8_anchor_evidence_digest.is_some()
            && reason == PublicAbortReasonV1::CrashRefund
            && self.secnonce.is_some()
        {
            return Err(RoundError::WrongRound);
        }
        self.secnonce = None;
        vault
            .abort(&self.reservation, reason)
            .map_err(|_| RoundError::Vault)?;
        self.round = ClaimRoundV1::Aborted;
        Ok(())
    }
}

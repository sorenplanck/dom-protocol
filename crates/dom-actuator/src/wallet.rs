//! Encrypted participant-wallet authority and exclusive output reservations.

use std::fs::{self, File, OpenOptions};
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use dom_adaptor::{SessionBlindingShareCapabilityV1, SigningShareV1};
use dom_wallet2::{
    load_wallet_state, save_wallet_state, OutputStatus, StoredOutput, WalletV2State,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, FlockOperation};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;
use zeroize::{Zeroize, Zeroizing};

use crate::model::{
    Digest32, DomActionV1, DomActuatorCapabilityV1, DomActuatorError, DomActuatorResult,
    DomParticipantSigningShareV1, DomSessionBindingV1,
};
use crate::store::{DomActuatorStoreV1, DomLeaseV1, DomOperationDispositionV1};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const RESERVATION_ACTIVE: i64 = 1;
const MAX_WALLET_CIPHERTEXT_BYTES: u64 = 64 * 1024 * 1024;

/// Closed position of one Scriptless Contracts session served by the wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DomWalletSessionLegV1 {
    /// Session between the local route input and the intermediate transfer.
    Upstream = 1,
    /// Session between the intermediate transfer and the local route output.
    Downstream = 2,
}

/// Exact public authority bound to one physical DOM participant wallet.
///
/// A route owns one wallet file and one participant, while its upstream and
/// downstream Scriptless Contracts sessions remain distinct.  This value pins
/// both sessions at open time so a later caller cannot introduce another
/// session, participant, deployment or chain into the wallet authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomWalletAuthorityBindingV1 {
    upstream: DomSessionBindingV1,
    downstream: DomSessionBindingV1,
}

impl DomWalletAuthorityBindingV1 {
    /// Bind one physical wallet to exactly two authenticated route sessions.
    pub fn new(
        upstream: DomSessionBindingV1,
        downstream: DomSessionBindingV1,
    ) -> DomActuatorResult<Self> {
        upstream.validate()?;
        downstream.validate()?;
        if upstream.session_id() == downstream.session_id()
            || !same_wallet_authority(upstream, downstream)
        {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(Self {
            upstream,
            downstream,
        })
    }

    /// Exact session fixed for one route leg.
    pub const fn session(self, leg: DomWalletSessionLegV1) -> DomSessionBindingV1 {
        match leg {
            DomWalletSessionLegV1::Upstream => self.upstream,
            DomWalletSessionLegV1::Downstream => self.downstream,
        }
    }

    /// Route identifier shared by the two sessions.
    pub const fn route_id(self) -> Digest32 {
        self.upstream.route_id()
    }

    /// Sole local participant whose encrypted wallet is controlled.
    pub const fn participant(self) -> crate::DomParticipantV1 {
        self.upstream.participant()
    }

    /// Registry-authenticated deployment shared by the two sessions.
    pub const fn deployment_digest(self) -> Digest32 {
        self.upstream.deployment_digest()
    }

    /// Domain-separated digest of every retained authority and session fact.
    pub fn digest(self) -> Digest32 {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"DOM:participant-wallet-authority:v1");
        hash_session_binding(&mut hasher, DomWalletSessionLegV1::Upstream, self.upstream);
        hash_session_binding(
            &mut hasher,
            DomWalletSessionLegV1::Downstream,
            self.downstream,
        );
        hasher.finalize().into()
    }

    fn validate(self) -> DomActuatorResult<()> {
        Self::new(self.upstream, self.downstream).map(|_| ())
    }
}

/// Request for deterministic selection of confirmed and mature DOM outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletReservationRequestV1 {
    required_value: u64,
}

impl WalletReservationRequestV1 {
    /// Construct a request for the complete value required by the funding template.
    pub fn new(required_value: u64) -> DomActuatorResult<Self> {
        if required_value == 0 {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(Self { required_value })
    }

    /// Required value, including any fee contribution selected by the caller.
    pub const fn required_value(self) -> u64 {
        self.required_value
    }
}

/// Public description of one reserved wallet output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomReservedOutputV1 {
    commitment: [u8; 33],
    value: u64,
}

impl DomReservedOutputV1 {
    /// Pedersen commitment; the blinding remains inside the encrypted wallet.
    pub const fn commitment(self) -> [u8; 33] {
        self.commitment
    }

    /// Public wallet-known value in noms.
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// Durable public reservation receipt. No output blinding is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomOutputReservationV1 {
    reservation_digest: Digest32,
    total_value: u64,
    outputs: Vec<DomReservedOutputV1>,
}

impl DomOutputReservationV1 {
    /// Public commitment written into each wallet output's `reserved_for` field.
    pub const fn reservation_digest(&self) -> Digest32 {
        self.reservation_digest
    }

    /// Sum of all exclusively reserved outputs.
    pub const fn total_value(&self) -> u64 {
        self.total_value
    }

    /// Deterministically ordered public output list.
    pub fn outputs(&self) -> &[DomReservedOutputV1] {
        &self.outputs
    }
}

/// Public context required to compose this participant's funding signing share.
pub struct FundingSigningShareRequestV1<'authority> {
    /// Exact durable output reservation consumed by this funding round.
    pub reservation: &'authority DomOutputReservationV1,
    /// Optional local change commitment included in the funding transaction.
    pub change_commitment: Option<[u8; 33]>,
    /// Participant offset supplied by the authenticated signing transcript.
    pub participant_offset: &'authority [u8; 32],
    /// Opaque shared-output blinding authority for this exact session.
    pub shared: &'authority SessionBlindingShareCapabilityV1,
    /// Wall-clock value used only for the durable capability check.
    pub now_unix_ms: u64,
}

/// Public context required to compose one shared-output spend signing share.
pub struct SharedOutputSpendSigningShareRequestV1<'authority> {
    /// Exact local payout commitment whose blinding remains in the wallet.
    pub payout_commitment: [u8; 33],
    /// Participant offset supplied by the authenticated signing transcript.
    pub participant_offset: &'authority [u8; 32],
    /// Opaque shared-output blinding authority for this exact session.
    pub shared: &'authority SessionBlindingShareCapabilityV1,
    /// Wall-clock value used only for the durable capability check.
    pub now_unix_ms: u64,
}

/// One open encrypted wallet, retained process lock and participant binding.
///
/// The decrypted state and password never leave this value. Debug is redacted,
/// and the password is zeroized on drop.
pub struct DomParticipantWalletV1 {
    path: PathBuf,
    password: Zeroizing<String>,
    state: WalletV2State,
    authority: DomWalletAuthorityBindingV1,
    ciphertext_digest: Digest32,
    wallet_file: File,
    process_lock: File,
}

/// Temporary, move-only view of one exact wallet session.
///
/// The view borrows the sole physical wallet mutably, cannot be cloned or
/// serialized, and carries no secret material of its own.
pub struct DomParticipantWalletSessionV1<'wallet> {
    wallet: &'wallet mut DomParticipantWalletV1,
    leg: DomWalletSessionLegV1,
}

impl core::fmt::Debug for DomParticipantWalletV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DomParticipantWalletV1([redacted])")
    }
}

impl DomParticipantWalletV1 {
    /// Open an existing encrypted wallet under an owner-only retained lock.
    pub fn open_existing(
        path: &Path,
        password: Zeroizing<String>,
        authority: DomWalletAuthorityBindingV1,
    ) -> DomActuatorResult<Self> {
        if !cfg!(target_os = "linux") {
            return Err(DomActuatorError::LinuxRequired);
        }
        authority.validate()?;
        validate_wallet_path(path)?;
        let process_lock = acquire_wallet_lock(path)?;
        reject_ambiguous_temp(path)?;
        let wallet_file = open_wallet_file(path)?;
        validate_open_file_identity(&wallet_file, path)?;
        let state = load_wallet_state(path, password.as_str())
            .map_err(|_| DomActuatorError::WalletUnavailable)?;
        validate_open_file_identity(&wallet_file, path)?;
        let ciphertext_digest = retained_wallet_ciphertext_digest(&wallet_file)?;
        if state.chain_id
            != authority
                .session(DomWalletSessionLegV1::Upstream)
                .chain_id()
        {
            return Err(DomActuatorError::WalletChainMismatch);
        }
        let wallet = Self {
            path: path.to_path_buf(),
            password,
            state,
            authority,
            ciphertext_digest,
            wallet_file,
            process_lock,
        };
        wallet.audit_physical_authority()?;
        Ok(wallet)
    }

    /// Exact immutable two-session authority owned by this physical wallet.
    pub const fn authority_binding(&self) -> DomWalletAuthorityBindingV1 {
        self.authority
    }

    /// Borrow a temporary authority for exactly one pre-bound session.
    pub fn session(
        &mut self,
        leg: DomWalletSessionLegV1,
    ) -> DomActuatorResult<DomParticipantWalletSessionV1<'_>> {
        self.require_session(leg)?;
        self.audit_physical_authority()?;
        Ok(DomParticipantWalletSessionV1 { wallet: self, leg })
    }

    /// Select, durably reserve and encrypt the exact wallet outputs.
    ///
    /// The public SQLite intent and unique commitment rows are committed before
    /// the encrypted wallet is replaced.  Restart replays the same selection;
    /// a wallet-persisted/store-unacknowledged cut is completed idempotently.
    fn reserve_outputs_for_session(
        &mut self,
        leg: DomWalletSessionLegV1,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        request: WalletReservationRequestV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOutputReservationV1> {
        let binding = self.require_session(leg)?;
        self.audit_physical_authority()?;
        self.require_capability(binding, &capability, DomActionV1::ReserveOutputs)?;
        let existing = store.reservation_for_effect(capability.scope().effect_id())?;
        let (reservation_digest, selected, status) = match existing {
            Some(retained) => (
                retained.reservation_digest,
                retained.outputs,
                retained.status,
            ),
            None => {
                let outputs = select_outputs(&self.state, request.required_value)?;
                let digest = reservation_digest(capability.scope(), request, &outputs);
                (digest, outputs, 0)
            }
        };
        let total = selected.iter().try_fold(0_u64, |sum, (_, value)| {
            sum.checked_add(*value)
                .ok_or(DomActuatorError::InvalidBinding)
        })?;
        if total < request.required_value {
            return Err(DomActuatorError::IdempotencyConflict);
        }
        let public_outputs: Vec<(Vec<u8>, u64)> = selected
            .iter()
            .map(|(commitment, value)| (commitment.to_vec(), *value))
            .collect();
        let _ = store.prepare_output_reservation(
            lease,
            &capability,
            reservation_digest,
            &public_outputs,
            now_unix_ms,
        )?;

        let mut changed = false;
        for (commitment, value) in &selected {
            let output = self
                .state
                .outputs
                .get_mut(commitment)
                .ok_or(DomActuatorError::WalletUnavailable)?;
            if output.value != *value || output.status != OutputStatus::Confirmed {
                return Err(DomActuatorError::WalletUnavailable);
            }
            match output.reserved_for {
                None if status != RESERVATION_ACTIVE => {
                    output.reserve(reservation_digest, now_unix_ms / 1000);
                    changed = true;
                }
                Some(value) if value == reservation_digest => {}
                _ => return Err(DomActuatorError::OutputReservationConflict),
            }
        }
        if status == RESERVATION_ACTIVE && changed {
            return Err(DomActuatorError::WalletUnavailable);
        }
        if changed {
            self.persist_securely()?;
        }
        self.audit_physical_authority()?;
        let wallet_receipt = self.ciphertext_digest;
        let _ = store.activate_output_reservation(
            lease,
            capability,
            reservation_digest,
            wallet_receipt,
            now_unix_ms,
        )?;
        self.audit_physical_authority()?;
        Ok(DomOutputReservationV1 {
            reservation_digest,
            total_value: total,
            outputs: selected
                .into_iter()
                .map(|(commitment, value)| DomReservedOutputV1 { commitment, value })
                .collect(),
        })
    }

    /// Release an exact reservation only under a terminal release capability.
    fn release_outputs_for_session(
        &mut self,
        leg: DomWalletSessionLegV1,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        reservation_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        let binding = self.require_session(leg)?;
        self.audit_physical_authority()?;
        self.require_capability(binding, &capability, DomActionV1::ReleaseOutputs)?;
        let retained = store
            .reservation_by_digest(reservation_digest)?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if retained.route_id != binding.route_id() || retained.session_id != binding.session_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let mut changed = false;
        for (commitment, value) in retained.outputs {
            let output = self
                .state
                .outputs
                .get_mut(&commitment)
                .ok_or(DomActuatorError::WalletUnavailable)?;
            if output.value != value {
                return Err(DomActuatorError::WalletUnavailable);
            }
            match output.reserved_for {
                Some(value) if value == reservation_digest => {
                    output.release_reservation(now_unix_ms / 1000);
                    changed = true;
                }
                None => {}
                Some(_) => return Err(DomActuatorError::OutputReservationConflict),
            }
        }
        if changed {
            self.persist_securely()?;
        }
        self.audit_physical_authority()?;
        let receipt = self.ciphertext_digest;
        store.release_output_reservation(
            lease,
            capability,
            reservation_digest,
            receipt,
            now_unix_ms,
        )?;
        self.audit_physical_authority()?;
        Ok(if changed {
            DomOperationDispositionV1::Prepared
        } else {
            DomOperationDispositionV1::Idempotent
        })
    }

    /// Compose this participant's funding kernel share without exporting any blinding.
    ///
    /// The scalar arithmetic is delegated to `dom-slate` and `dom-adaptor`.
    /// Only the local participant's reserved inputs and optional local change
    /// output are read; the aggregate shared-output blinding is never built.
    fn compose_funding_signing_share_for_session(
        &self,
        leg: DomWalletSessionLegV1,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        request: FundingSigningShareRequestV1<'_>,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        let FundingSigningShareRequestV1 {
            reservation,
            change_commitment,
            participant_offset,
            shared,
            now_unix_ms,
        } = request;
        let binding = self.require_session(leg)?;
        self.audit_physical_authority()?;
        self.require_signing_capability(binding, capability)?;
        store.validate_live_capability(lease, capability, now_unix_ms)?;
        self.require_shared_binding(binding, shared)?;
        self.require_live_reservation(store, binding, reservation)?;
        let inputs: Vec<&[u8; 32]> = reservation
            .outputs
            .iter()
            .map(|reserved| {
                self.state
                    .outputs
                    .get(&reserved.commitment)
                    .map(|output| &*output.blinding)
                    .ok_or(DomActuatorError::WalletUnavailable)
            })
            .collect::<DomActuatorResult<_>>()?;
        let change = change_commitment
            .map(|commitment| {
                self.state
                    .outputs
                    .get(&commitment)
                    .map(|output| &*output.blinding)
                    .ok_or(DomActuatorError::WalletUnavailable)
            })
            .transpose()?;
        let mut wallet_excess = Zeroizing::new(
            dom_slate::sender_excess_blinding(inputs, change, participant_offset)
                .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?,
        );
        let wallet_share = SigningShareV1::from_be_bytes(*wallet_excess)
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        wallet_excess.zeroize();
        let share = shared
            .compose_funding_signing_share_v1(&wallet_share)
            .map(|share| DomParticipantSigningShareV1::new(binding, share))
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        self.audit_physical_authority()?;
        Ok(share)
    }

    /// Compose this participant's exact shared-output spend share without exporting it.
    fn compose_shared_output_spend_signing_share_for_session(
        &self,
        leg: DomWalletSessionLegV1,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        request: SharedOutputSpendSigningShareRequestV1<'_>,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        let SharedOutputSpendSigningShareRequestV1 {
            payout_commitment,
            participant_offset,
            shared,
            now_unix_ms,
        } = request;
        let binding = self.require_session(leg)?;
        self.audit_physical_authority()?;
        self.require_signing_capability(binding, capability)?;
        store.validate_live_capability(lease, capability, now_unix_ms)?;
        self.require_shared_binding(binding, shared)?;
        let output = self
            .state
            .outputs
            .get(&payout_commitment)
            .ok_or(DomActuatorError::WalletUnavailable)?;
        let mut payout_excess = Zeroizing::new(
            dom_slate::sender_excess_blinding(
                core::iter::empty::<&[u8; 32]>(),
                Some(&*output.blinding),
                participant_offset,
            )
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?,
        );
        let wallet_share = SigningShareV1::from_be_bytes(*payout_excess)
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        payout_excess.zeroize();
        let share = shared
            .compose_shared_output_spend_signing_share_v1(&wallet_share)
            .map(|share| DomParticipantSigningShareV1::new(binding, share))
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        self.audit_physical_authority()?;
        Ok(share)
    }

    fn require_capability(
        &self,
        binding: DomSessionBindingV1,
        capability: &DomActuatorCapabilityV1,
        action: DomActionV1,
    ) -> DomActuatorResult<()> {
        if capability.scope().binding() != binding || capability.scope().action() != action {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }

    fn require_signing_capability(
        &self,
        binding: DomSessionBindingV1,
        capability: &DomActuatorCapabilityV1,
    ) -> DomActuatorResult<()> {
        if capability.scope().binding() != binding
            || !matches!(
                capability.scope().action(),
                DomActionV1::PresignRefund
                    | DomActionV1::PresignClaimAdaptor
                    | DomActionV1::BroadcastFunding
            )
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }

    fn require_shared_binding(
        &self,
        expected: DomSessionBindingV1,
        shared: &SessionBlindingShareCapabilityV1,
    ) -> DomActuatorResult<()> {
        let binding = shared.binding();
        if binding.chain_id() != &expected.chain_id()
            || binding.session_id() != &expected.session_id()
            || binding.participant_id() != &expected.participant().participant_id()
            || binding.participant_index() != u16::from(expected.participant().protocol_index())
            || binding.terms_hash() != &expected.terms_digest()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }

    fn require_live_reservation(
        &self,
        store: &DomActuatorStoreV1,
        binding: DomSessionBindingV1,
        reservation: &DomOutputReservationV1,
    ) -> DomActuatorResult<()> {
        let retained = store
            .reservation_by_digest(reservation.reservation_digest)?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        let public_outputs: Vec<([u8; 33], u64)> = reservation
            .outputs
            .iter()
            .map(|output| (output.commitment, output.value))
            .collect();
        if retained.reservation_digest != reservation.reservation_digest
            || retained.route_id != binding.route_id()
            || retained.session_id != binding.session_id()
            || retained.status != RESERVATION_ACTIVE
            || retained.outputs != public_outputs
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        for reserved in &reservation.outputs {
            let output = self
                .state
                .outputs
                .get(&reserved.commitment)
                .ok_or(DomActuatorError::WalletUnavailable)?;
            if output.value != reserved.value
                || output.reserved_for != Some(reservation.reservation_digest)
            {
                return Err(DomActuatorError::OutputReservationConflict);
            }
        }
        Ok(())
    }

    fn require_session(
        &self,
        leg: DomWalletSessionLegV1,
    ) -> DomActuatorResult<DomSessionBindingV1> {
        self.authority.validate()?;
        let binding = self.authority.session(leg);
        binding.validate()?;
        if self.state.chain_id != binding.chain_id() {
            return Err(DomActuatorError::WalletChainMismatch);
        }
        Ok(binding)
    }

    fn audit_physical_authority(&self) -> DomActuatorResult<()> {
        self.authority.validate()?;
        validate_wallet_path(&self.path)?;
        reject_ambiguous_temp(&self.path)?;
        validate_open_file_identity(&self.wallet_file, &self.path)?;
        let lock_path = wallet_lock_path(&self.path);
        validate_open_file_identity(&self.process_lock, &lock_path)?;
        if self
            .process_lock
            .metadata()
            .map_err(|_| DomActuatorError::WalletUnavailable)?
            .len()
            != 0
            || retained_wallet_ciphertext_digest(&self.wallet_file)? != self.ciphertext_digest
        {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
        Ok(())
    }

    fn persist_securely(&mut self) -> DomActuatorResult<()> {
        self.audit_physical_authority()?;
        if save_wallet_state(&self.state, &self.path, self.password.as_str()).is_err() {
            return Err(DomActuatorError::WalletUnavailable);
        }
        validate_wallet_path(&self.path)?;
        let wallet_file = open_wallet_file(&self.path)?;
        let ciphertext_digest = retained_wallet_ciphertext_digest(&wallet_file)?;
        self.wallet_file = wallet_file;
        self.ciphertext_digest = ciphertext_digest;
        self.audit_physical_authority()
    }
}

impl DomParticipantWalletSessionV1<'_> {
    /// Exact immutable session served by this temporary wallet view.
    pub fn binding(&self) -> DomSessionBindingV1 {
        self.wallet.authority.session(self.leg)
    }

    /// Position of this exact session in the route.
    pub const fn leg(&self) -> DomWalletSessionLegV1 {
        self.leg
    }

    /// Select, durably reserve and encrypt the exact wallet outputs.
    pub fn reserve_outputs(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        request: WalletReservationRequestV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOutputReservationV1> {
        self.wallet.reserve_outputs_for_session(
            self.leg,
            store,
            lease,
            capability,
            request,
            now_unix_ms,
        )
    }

    /// Release an exact reservation under the same session that created it.
    pub fn release_outputs(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: DomActuatorCapabilityV1,
        reservation_digest: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomOperationDispositionV1> {
        self.wallet.release_outputs_for_session(
            self.leg,
            store,
            lease,
            capability,
            reservation_digest,
            now_unix_ms,
        )
    }

    /// Compose this participant's funding share without exposing a scalar.
    pub fn compose_funding_signing_share(
        &self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        request: FundingSigningShareRequestV1<'_>,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        self.wallet
            .compose_funding_signing_share_for_session(self.leg, store, lease, capability, request)
    }

    /// Compose this participant's shared-output spend share without exporting it.
    pub fn compose_shared_output_spend_signing_share(
        &self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        capability: &DomActuatorCapabilityV1,
        request: SharedOutputSpendSigningShareRequestV1<'_>,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        self.wallet
            .compose_shared_output_spend_signing_share_for_session(
                self.leg, store, lease, capability, request,
            )
    }
}

fn select_outputs(state: &WalletV2State, required: u64) -> DomActuatorResult<Vec<([u8; 33], u64)>> {
    let tip = state.meta.last_reconciled_tip;
    let maturity = state.network.coinbase_maturity();
    let mut candidates: Vec<&StoredOutput> = state
        .outputs
        .iter()
        .filter(|output| {
            output.status == OutputStatus::Confirmed
                && output.reserved_for.is_none()
                && (!output.is_coinbase
                    || output
                        .origin_block
                        .is_some_and(|block| tip.saturating_sub(block.height) >= maturity))
        })
        .collect();
    candidates.sort_by(|left, right| {
        right
            .value
            .cmp(&left.value)
            .then_with(|| left.commitment.cmp(&right.commitment))
    });
    let mut total = 0_u64;
    let mut selected = Vec::new();
    for output in candidates {
        if total >= required {
            break;
        }
        total = total
            .checked_add(output.value)
            .ok_or(DomActuatorError::InvalidBinding)?;
        selected.push((output.commitment, output.value));
    }
    if total < required {
        return Err(DomActuatorError::InsufficientFunds);
    }
    selected.sort_by_key(|(commitment, _)| *commitment);
    Ok(selected)
}

fn same_wallet_authority(left: DomSessionBindingV1, right: DomSessionBindingV1) -> bool {
    left.route_id() == right.route_id()
        && left.participant().participant_id() == right.participant().participant_id()
        && left.chain_id() == right.chain_id()
        && left.genesis_hash() == right.genesis_hash()
        && left.runtime_identity() == right.runtime_identity()
        && left.profile_digest() == right.profile_digest()
        && left.deployment_digest() == right.deployment_digest()
        && left.asset_binding_digest() == right.asset_binding_digest()
        && left.registry_epoch() == right.registry_epoch()
        && left.min_confirmations() == right.min_confirmations()
        && left.max_reorg_depth() == right.max_reorg_depth()
}

fn hash_session_binding(
    hasher: &mut Blake2b<U32>,
    leg: DomWalletSessionLegV1,
    binding: DomSessionBindingV1,
) {
    let runtime = binding.runtime_identity();
    for part in [
        [leg as u8].as_slice(),
        binding.route_id().as_slice(),
        binding.session_id().as_slice(),
        binding.participant().participant_id().as_slice(),
        [binding.participant().protocol_index()].as_slice(),
        binding.chain_id().as_slice(),
        binding.genesis_hash().as_slice(),
        runtime.network.label().as_bytes(),
        runtime.network_magic.to_be_bytes().as_slice(),
        runtime.protocol_version.to_be_bytes().as_slice(),
        [runtime.range_proof_serialization_version].as_slice(),
        binding.terms_digest().as_slice(),
        binding.profile_digest().as_slice(),
        binding.deployment_digest().as_slice(),
        binding.asset_binding_digest().as_slice(),
        binding.registry_epoch().to_be_bytes().as_slice(),
        binding.min_confirmations().to_be_bytes().as_slice(),
        binding.max_reorg_depth().to_be_bytes().as_slice(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
}

fn reservation_digest(
    scope: crate::ScopedDomActionV1,
    request: WalletReservationRequestV1,
    outputs: &[([u8; 33], u64)],
) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    for part in [
        b"DOM:wallet-output-reservation:v1".as_slice(),
        scope.binding().route_id().as_slice(),
        scope.binding().session_id().as_slice(),
        scope.effect_id().as_slice(),
        scope.binding().participant().participant_id().as_slice(),
        request.required_value.to_be_bytes().as_slice(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    for (commitment, value) in outputs {
        hasher.update(commitment);
        hasher.update(value.to_be_bytes());
    }
    hasher.finalize().into()
}

#[cfg(target_os = "linux")]
fn retained_wallet_ciphertext_digest(file: &File) -> DomActuatorResult<Digest32> {
    const READ_BUFFER_BYTES: usize = 16 * 1024;
    let length = file
        .metadata()
        .map_err(|_| DomActuatorError::WalletUnavailable)?
        .len();
    if length == 0 || length > MAX_WALLET_CIPHERTEXT_BYTES {
        return Err(DomActuatorError::WalletUnavailable);
    }
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"DOM:wallet-ciphertext-receipt:v1");
    hasher.update(length.to_be_bytes());
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    let mut offset = 0_u64;
    while offset < length {
        let remaining = usize::try_from((length - offset).min(READ_BUFFER_BYTES as u64))
            .map_err(|_| DomActuatorError::WalletUnavailable)?;
        let read = file
            .read_at(&mut buffer[..remaining], offset)
            .map_err(|_| DomActuatorError::WalletUnavailable)?;
        if read == 0 {
            return Err(DomActuatorError::WalletUnavailable);
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| DomActuatorError::WalletUnavailable)?)
            .ok_or(DomActuatorError::WalletUnavailable)?;
    }
    if file
        .metadata()
        .map_err(|_| DomActuatorError::WalletUnavailable)?
        .len()
        != length
    {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    Ok(hasher.finalize().into())
}

#[cfg(not(target_os = "linux"))]
fn retained_wallet_ciphertext_digest(_file: &File) -> DomActuatorResult<Digest32> {
    Err(DomActuatorError::LinuxRequired)
}

fn wallet_lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".interop.lock");
    PathBuf::from(value)
}

fn open_wallet_file(path: &Path) -> DomActuatorResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| DomActuatorError::WalletUnavailable)?;
    validate_open_file_identity(&file, path)?;
    let length = file
        .metadata()
        .map_err(|_| DomActuatorError::WalletUnavailable)?
        .len();
    if length == 0 || length > MAX_WALLET_CIPHERTEXT_BYTES {
        return Err(DomActuatorError::WalletUnavailable);
    }
    Ok(file)
}

fn acquire_wallet_lock(path: &Path) -> DomActuatorResult<File> {
    let lock_path = wallet_lock_path(path);
    let file = match fs::symlink_metadata(&lock_path) {
        Ok(_) => {
            validate_owner_file(&lock_path)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(|_| DomActuatorError::WalletUnavailable)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(target_os = "linux")]
            options.mode(FILE_MODE);
            options
                .open(&lock_path)
                .map_err(|_| DomActuatorError::WalletUnavailable)?
        }
        Err(_) => return Err(DomActuatorError::WalletUnavailable),
    };
    #[cfg(target_os = "linux")]
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| DomActuatorError::ProcessLocked)?;
    validate_open_file_identity(&file, &lock_path)?;
    if file
        .metadata()
        .map_err(|_| DomActuatorError::WalletUnavailable)?
        .len()
        != 0
    {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    Ok(file)
}

fn reject_ambiguous_temp(path: &Path) -> DomActuatorResult<()> {
    let temp = path.with_extension("tmp");
    if fs::symlink_metadata(temp).is_ok() {
        Err(DomActuatorError::WalletUnavailable)
    } else {
        Ok(())
    }
}

fn validate_wallet_path(path: &Path) -> DomActuatorResult<()> {
    let parent = path
        .parent()
        .ok_or(DomActuatorError::InvalidStorageAuthority)?;
    let canonical =
        fs::canonicalize(path).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
    if canonical != path {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    validate_owner_directory(parent)?;
    validate_owner_file(path)
}

fn validate_owner_directory(path: &Path) -> DomActuatorResult<()> {
    #[cfg(target_os = "linux")]
    {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != DIRECTORY_MODE
            || metadata.nlink() == 0
        {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
    }
    Ok(())
}

fn validate_owner_file(path: &Path) -> DomActuatorResult<()> {
    #[cfg(target_os = "linux")]
    {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
        if !owner_file_metadata_is_exact(&metadata) {
            return Err(DomActuatorError::InvalidStorageAuthority);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn owner_file_metadata_is_exact(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == geteuid().as_raw()
        && metadata.mode() & 0o7777 == FILE_MODE
        && metadata.nlink() == 1
}

#[cfg(target_os = "linux")]
fn validate_open_file_identity(file: &File, path: &Path) -> DomActuatorResult<()> {
    let retained = file
        .metadata()
        .map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
    let named =
        fs::symlink_metadata(path).map_err(|_| DomActuatorError::InvalidStorageAuthority)?;
    if !owner_file_metadata_is_exact(&retained)
        || !owner_file_metadata_is_exact(&named)
        || retained.dev() != named.dev()
        || retained.ino() != named.ino()
    {
        return Err(DomActuatorError::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_open_file_identity(_file: &File, _path: &Path) -> DomActuatorResult<()> {
    Err(DomActuatorError::LinuxRequired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;

    use deployment_registry::{DomNetworkV1, DomRuntimeIdentityV1};
    use dom_wallet2::{BlockRef, Network, OutputOrigin, StoredOutput};

    use crate::model::{CapabilityIssuanceV1, StoredDomSessionBindingPartsV1};
    use crate::store::tests::{TestContext, TestResult};
    use crate::{DomParticipantV1, ScopedDomActionV1};

    fn digest(tag: u8) -> Digest32 {
        [tag; 32]
    }

    struct TestBindingPartsV1 {
        route_id: Digest32,
        session_id: Digest32,
        participant_id: Digest32,
        protocol_index: u8,
        terms_digest: Digest32,
        deployment_digest: Digest32,
    }

    fn binding_from(parts: TestBindingPartsV1) -> TestResult<DomSessionBindingV1> {
        DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
            route_id: parts.route_id,
            session_id: parts.session_id,
            participant: DomParticipantV1::new(parts.participant_id, parts.protocol_index)
                .test_context("participant")?,
            chain_id: digest(4),
            genesis_hash: digest(5),
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            terms_digest: parts.terms_digest,
            profile_digest: digest(7),
            deployment_digest: parts.deployment_digest,
            asset_binding_digest: digest(9),
            registry_epoch: 1,
            min_confirmations: 2,
            max_reorg_depth: 10,
        })
        .test_context("binding")
    }

    fn bindings() -> TestResult<(
        DomSessionBindingV1,
        DomSessionBindingV1,
        DomWalletAuthorityBindingV1,
    )> {
        let upstream = binding_from(TestBindingPartsV1 {
            route_id: digest(1),
            session_id: digest(2),
            participant_id: digest(3),
            protocol_index: 0,
            terms_digest: digest(6),
            deployment_digest: digest(8),
        })?;
        let downstream = binding_from(TestBindingPartsV1 {
            route_id: digest(1),
            session_id: digest(12),
            participant_id: digest(3),
            protocol_index: 1,
            terms_digest: digest(16),
            deployment_digest: digest(8),
        })?;
        let authority = DomWalletAuthorityBindingV1::new(upstream, downstream)
            .test_context("wallet authority")?;
        Ok((upstream, downstream, authority))
    }

    fn create_wallet(path: &Path, binding: DomSessionBindingV1) -> TestResult {
        const BLINDING: [u8; 32] = [0x9a; 32];
        let mut state = WalletV2State::new(Network::Regtest, binding.chain_id());
        state.meta.last_reconciled_tip = 10;
        let mut output = StoredOutput::new_unconfirmed(
            [0x41; 33],
            50,
            BLINDING,
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1,
        );
        output
            .confirm(
                BlockRef {
                    height: 2,
                    hash: digest(10),
                },
                2,
            )
            .test_context("confirm")?;
        state.outputs.insert(output).test_context("insert")?;
        save_wallet_state(&state, path, "test-password").test_context("save wallet")?;
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
            .test_context("wallet mode")?;
        Ok(())
    }

    #[test]
    fn reservation_survives_restart_and_no_secret_enters_public_store() -> TestResult {
        const BLINDING: [u8; 32] = [0x9a; 32];
        let directory = tempfile::tempdir().test_context("tempdir")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .test_context("directory mode")?;
        let wallet_path = directory.path().join("wallet.v2");
        let store_path = directory.path().join("actuator.sqlite");
        let (upstream, _, authority) = bindings()?;
        create_wallet(&wallet_path, upstream)?;

        let mut store = DomActuatorStoreV1::create(&store_path).test_context("store")?;
        let lease = store
            .acquire_lease(digest(3), digest(20), 1_000, 10_000)
            .test_context("lease")?;
        store
            .bind_session(lease, upstream, 1_000)
            .test_context("bind")?;
        let scoped = ScopedDomActionV1::new(upstream, digest(21), DomActionV1::ReserveOutputs)
            .test_context("scope")?;
        let (capability, _) = store
            .authorize_action(lease, scoped, digest(22), None, 1_001)
            .test_context("authorize")?;
        let mut wallet = DomParticipantWalletV1::open_existing(
            &wallet_path,
            Zeroizing::new("test-password".to_owned()),
            authority,
        )
        .test_context("open wallet")?;
        let reservation = wallet
            .session(DomWalletSessionLegV1::Upstream)
            .test_context("upstream wallet session")?
            .reserve_outputs(
                &mut store,
                lease,
                capability,
                WalletReservationRequestV1::new(40).test_context("request")?,
                1_002,
            )
            .test_context("reserve")?;
        assert_eq!(reservation.outputs().len(), 1);
        assert_eq!(reservation.total_value(), 50);
        assert!(!format!("{wallet:?}").contains("9a, 9a"));
        drop(wallet);
        drop(store);

        for path in [
            store_path.clone(),
            PathBuf::from(format!("{}-wal", store_path.display())),
        ] {
            if let Ok(bytes) = fs::read(path) {
                assert!(
                    !bytes
                        .windows(BLINDING.len())
                        .any(|window| window == BLINDING),
                    "wallet blinding leaked into public actuator storage"
                );
            }
        }

        let mut reopened =
            DomActuatorStoreV1::open_existing(&store_path).test_context("reopen store")?;
        let resumed = reopened
            .acquire_lease(digest(3), digest(20), 1_003, 10_000)
            .test_context("resume lease")?;
        let (capability, disposition) = reopened
            .authorize_action(resumed, scoped, digest(22), None, 1_004)
            .test_context("resume operation")?;
        assert_eq!(disposition, DomOperationDispositionV1::AlreadyCompleted);
        let mut reopened_wallet = DomParticipantWalletV1::open_existing(
            &wallet_path,
            Zeroizing::new("test-password".to_owned()),
            authority,
        )
        .test_context("reopen wallet")?;
        let repeated = reopened_wallet
            .session(DomWalletSessionLegV1::Upstream)
            .test_context("reopened upstream wallet session")?
            .reserve_outputs(
                &mut reopened,
                resumed,
                capability,
                WalletReservationRequestV1::new(40).test_context("request")?,
                1_005,
            )
            .test_context("idempotent restart")?;
        assert_eq!(repeated, reservation);
        Ok(())
    }

    #[test]
    fn one_physical_wallet_serves_two_exact_sessions_and_refuses_transplant() -> TestResult {
        let directory = tempfile::tempdir().test_context("tempdir")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .test_context("directory mode")?;
        let wallet_path = directory.path().join("wallet.v2");
        let store_path = directory.path().join("actuator.sqlite");
        let (upstream, downstream, authority) = bindings()?;
        create_wallet(&wallet_path, upstream)?;

        let mut store = DomActuatorStoreV1::create(&store_path).test_context("store")?;
        let lease = store
            .acquire_lease(digest(3), digest(20), 1_000, 10_000)
            .test_context("lease")?;
        store
            .bind_session(lease, upstream, 1_000)
            .test_context("bind upstream")?;
        store
            .bind_session(lease, downstream, 1_000)
            .test_context("bind downstream")?;
        let upstream_scope =
            ScopedDomActionV1::new(upstream, digest(21), DomActionV1::ReserveOutputs)
                .test_context("upstream scope")?;
        let (upstream_capability, _) = store
            .authorize_action(lease, upstream_scope, digest(22), None, 1_001)
            .test_context("authorize upstream")?;

        let mut wallet = DomParticipantWalletV1::open_existing(
            &wallet_path,
            Zeroizing::new("test-password".to_owned()),
            authority,
        )
        .test_context("open wallet")?;
        assert_eq!(wallet.authority_binding(), authority);
        assert_ne!(authority.digest(), [0; 32]);
        {
            let upstream_view = wallet
                .session(DomWalletSessionLegV1::Upstream)
                .test_context("upstream view")?;
            assert_eq!(upstream_view.binding(), upstream);
        }
        {
            let downstream_view = wallet
                .session(DomWalletSessionLegV1::Downstream)
                .test_context("downstream view")?;
            assert_eq!(downstream_view.binding(), downstream);
        }

        let reservation = wallet
            .session(DomWalletSessionLegV1::Upstream)
            .test_context("upstream reservation view")?
            .reserve_outputs(
                &mut store,
                lease,
                upstream_capability,
                WalletReservationRequestV1::new(40).test_context("request")?,
                1_002,
            )
            .test_context("upstream reservation")?;
        assert_eq!(
            wallet.require_live_reservation(&store, downstream, &reservation),
            Err(DomActuatorError::CapabilityMismatch)
        );

        let transplanted_scope =
            ScopedDomActionV1::new(upstream, digest(23), DomActionV1::ReserveOutputs)
                .test_context("transplanted scope")?;
        let transplanted_capability = DomActuatorCapabilityV1::issue(
            transplanted_scope,
            lease.fencing_epoch(),
            digest(24),
            CapabilityIssuanceV1::Fresh,
        );

        assert!(matches!(
            DomParticipantWalletV1::open_existing(
                &wallet_path,
                Zeroizing::new("test-password".to_owned()),
                authority,
            ),
            Err(DomActuatorError::ProcessLocked)
        ));

        let error = wallet
            .session(DomWalletSessionLegV1::Downstream)
            .test_context("downstream view")?
            .reserve_outputs(
                &mut store,
                lease,
                transplanted_capability,
                WalletReservationRequestV1::new(40).test_context("request")?,
                1_004,
            )
            .err()
            .test_context("transplanted upstream capability unexpectedly succeeded")?;
        assert_eq!(error, DomActuatorError::CapabilityMismatch);
        Ok(())
    }

    #[test]
    fn wallet_authority_rejects_route_participant_and_deployment_divergence() -> TestResult {
        let (upstream, _, _) = bindings()?;
        for divergent in [
            binding_from(TestBindingPartsV1 {
                route_id: digest(31),
                session_id: digest(12),
                participant_id: digest(3),
                protocol_index: 1,
                terms_digest: digest(16),
                deployment_digest: digest(8),
            })?,
            binding_from(TestBindingPartsV1 {
                route_id: digest(1),
                session_id: digest(12),
                participant_id: digest(32),
                protocol_index: 1,
                terms_digest: digest(16),
                deployment_digest: digest(8),
            })?,
            binding_from(TestBindingPartsV1 {
                route_id: digest(1),
                session_id: digest(12),
                participant_id: digest(3),
                protocol_index: 1,
                terms_digest: digest(16),
                deployment_digest: digest(33),
            })?,
        ] {
            assert_eq!(
                DomWalletAuthorityBindingV1::new(upstream, divergent),
                Err(DomActuatorError::InvalidBinding)
            );
        }
        assert_eq!(
            DomWalletAuthorityBindingV1::new(upstream, upstream),
            Err(DomActuatorError::InvalidBinding)
        );
        Ok(())
    }

    #[test]
    fn retained_wallet_identity_rejects_mode_link_and_named_path_swap() -> TestResult {
        let directory = tempfile::tempdir().test_context("tempdir")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .test_context("directory mode")?;
        let wallet_path = directory.path().join("wallet.v2");
        let displaced_path = directory.path().join("wallet.displaced");
        let hard_link_path = directory.path().join("wallet.alias");
        let (upstream, _, authority) = bindings()?;
        create_wallet(&wallet_path, upstream)?;
        let mut wallet = DomParticipantWalletV1::open_existing(
            &wallet_path,
            Zeroizing::new("test-password".to_owned()),
            authority,
        )
        .test_context("open wallet")?;

        fs::set_permissions(&wallet_path, fs::Permissions::from_mode(0o640))
            .test_context("weaken wallet mode")?;
        assert!(matches!(
            wallet.session(DomWalletSessionLegV1::Upstream),
            Err(DomActuatorError::InvalidStorageAuthority)
        ));
        fs::set_permissions(&wallet_path, fs::Permissions::from_mode(FILE_MODE))
            .test_context("restore wallet mode")?;

        fs::hard_link(&wallet_path, &hard_link_path).test_context("create wallet hard link")?;
        assert!(matches!(
            wallet.session(DomWalletSessionLegV1::Upstream),
            Err(DomActuatorError::InvalidStorageAuthority)
        ));
        fs::remove_file(&hard_link_path).test_context("remove wallet hard link")?;

        fs::rename(&wallet_path, &displaced_path).test_context("displace retained wallet")?;
        fs::copy(&displaced_path, &wallet_path)
            .test_context("install byte-identical substitute")?;
        fs::set_permissions(&wallet_path, fs::Permissions::from_mode(FILE_MODE))
            .test_context("substitute wallet mode")?;
        assert!(matches!(
            wallet.session(DomWalletSessionLegV1::Upstream),
            Err(DomActuatorError::InvalidStorageAuthority)
        ));
        Ok(())
    }

    #[test]
    fn wallet_restart_authenticates_ciphertext_and_live_tamper_fails_closed() -> TestResult {
        let directory = tempfile::tempdir().test_context("tempdir")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .test_context("directory mode")?;
        let wallet_path = directory.path().join("wallet.v2");
        let (upstream, _, authority) = bindings()?;
        create_wallet(&wallet_path, upstream)?;

        let mut wallet = DomParticipantWalletV1::open_existing(
            &wallet_path,
            Zeroizing::new("test-password".to_owned()),
            authority,
        )
        .test_context("open wallet")?;
        let _upstream_view = wallet
            .session(DomWalletSessionLegV1::Upstream)
            .test_context("upstream view")?;

        let mut tamper = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wallet_path)
            .test_context("open tamper handle")?;
        tamper
            .seek(SeekFrom::Start(64))
            .test_context("seek tamper byte")?;
        let mut byte = [0_u8; 1];
        tamper
            .read_exact(&mut byte)
            .test_context("read tamper byte")?;
        byte[0] ^= 0xff;
        tamper
            .seek(SeekFrom::Start(64))
            .test_context("rewind tamper byte")?;
        tamper.write_all(&byte).test_context("write tamper byte")?;
        tamper.sync_all().test_context("sync tamper")?;

        assert!(matches!(
            wallet.session(DomWalletSessionLegV1::Upstream),
            Err(DomActuatorError::InvalidStorageAuthority)
        ));
        drop(wallet);
        assert!(matches!(
            DomParticipantWalletV1::open_existing(
                &wallet_path,
                Zeroizing::new("test-password".to_owned()),
                authority,
            ),
            Err(DomActuatorError::WalletUnavailable)
        ));
        Ok(())
    }
}
